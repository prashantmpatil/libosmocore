/*! \file gprs_ns2_fr.c
 * NS-over-FR-over-GRE implementation.
 * GPRS Networks Service (NS) messages on the Gb interface.
 * 3GPP TS 08.16 version 8.0.1 Release 1999 / ETSI TS 101 299 V8.0.1 (2002-05)
 * as well as its successor 3GPP TS 48.016 */

/* (C) 2009-2010,2014,2017 by Harald Welte <laforge@gnumonks.org>
 * (C) 2020 sysmocom - s.f.m.c. GmbH
 * Author: Alexander Couzens <lynxis@fe80.eu>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <linux/hdlc.h>
#include <linux/if.h>

#include <osmocom/gprs/frame_relay.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gprs/gprs_ns2.h>

#include "common_vty.h"
#include "gprs_ns2_internal.h"

#define GRE_PTYPE_FR	0x6559
#define GRE_PTYPE_IPv4	0x0800
#define GRE_PTYPE_IPv6	0x86dd
#define GRE_PTYPE_KAR	0x0000	/* keepalive response */

#ifndef IPPROTO_GRE
# define IPPROTO_GRE 47
#endif

struct gre_hdr {
	uint16_t flags;
	uint16_t ptype;
} __attribute__ ((packed));

#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__CYGWIN__)
/**
 * On BSD the IPv4 struct is called struct ip and instead of iXX
 * the members are called ip_XX. One could change this code to use
 * struct ip but that would require to define _BSD_SOURCE and that
 * might have other complications. Instead make sure struct iphdr
 * is present on FreeBSD. The below is taken from GLIBC.
 *
 * The GNU C Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */
struct iphdr
  {
#if BYTE_ORDER == LITTLE_ENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#elif BYTE_ORDER == BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
  };
#endif


static void free_bind(struct gprs_ns2_vc_bind *bind);
static int fr_dlci_rx_cb(void *cb_data, struct msgb *msg);

struct gprs_ns2_vc_driver vc_driver_fr = {
	.name = "GB frame relay",
	.free_bind = free_bind,
};

struct priv_bind {
	struct osmo_fd fd;
	char netif[IF_NAMESIZE + 1];
	struct osmo_fr_link *link;
};

struct priv_vc {
	struct osmo_sockaddr remote;
	uint16_t dlci;
	struct osmo_fr_dlc *dlc;
};

static void free_vc(struct gprs_ns2_vc *nsvc)
{
	OSMO_ASSERT(nsvc);

	if (!nsvc->priv)
		return;

	talloc_free(nsvc->priv);
	nsvc->priv = NULL;
}

static void dump_vty(const struct gprs_ns2_vc_bind *bind, struct vty *vty, bool _stats)
{
	struct priv_bind *priv;
	struct gprs_ns2_vc *nsvc;

	if (!bind)
		return;

	priv = bind->priv;

	vty_out(vty, "FR bind: %s%s", priv->netif, VTY_NEWLINE);

	llist_for_each_entry(nsvc, &bind->nsvc, blist) {
		vty_out(vty, "    %s%s", gprs_ns2_ll_str(nsvc), VTY_NEWLINE);
	}

	priv = bind->priv;
}

/*! clean up all private driver state. Should be only called by gprs_ns2_free_bind() */
static void free_bind(struct gprs_ns2_vc_bind *bind)
{
	struct priv_bind *priv;

	if (!bind)
		return;

	priv = bind->priv;

	OSMO_ASSERT(llist_empty(&bind->nsvc));

	osmo_fr_link_free(priv->link);
	osmo_fd_close(&priv->fd);
	talloc_free(priv);
}

static struct priv_vc *fr_alloc_vc(struct gprs_ns2_vc_bind *bind,
				   struct gprs_ns2_vc *nsvc,
				   uint16_t dlci)
{
	struct priv_bind *privb = bind->priv;
	struct priv_vc *priv = talloc_zero(bind, struct priv_vc);
	if (!priv)
		return NULL;

	nsvc->priv = priv;
	priv->dlci = dlci;
	priv->dlc = osmo_fr_dlc_alloc(privb->link, dlci);
	if (!priv->dlc) {
		nsvc->priv = NULL;
		talloc_free(priv);
		return NULL;
	}

	priv->dlc->rx_cb_data = nsvc;
	priv->dlc->rx_cb = fr_dlci_rx_cb;

	return priv;
}

int gprs_ns2_find_vc_by_dlci(struct gprs_ns2_vc_bind *bind,
			     uint16_t dlci,
			     struct gprs_ns2_vc **result)
{
	struct gprs_ns2_vc *nsvc;
	struct priv_vc *vcpriv;

	if (!result)
		return -EINVAL;

	llist_for_each_entry(nsvc, &bind->nsvc, blist) {
		vcpriv = nsvc->priv;
		if (vcpriv->dlci != dlci) {
			*result = nsvc;
			return 0;
		}
	}

	return 1;
}

/* PDU from the network interface towards the fr layer (upwards) */
static int handle_netif_read(struct osmo_fd *bfd)
{
	struct gprs_ns2_vc_bind *bind = bfd->data;
	struct priv_bind *priv = bind->priv;
	struct msgb *msg = msgb_alloc(NS_ALLOC_SIZE, "Gb/NS/FR/GRE Rx");
	int rc = 0;

	if (!msg)
		return -ENOMEM;

	rc = read(bfd->fd, msg->data, NS_ALLOC_SIZE);
	if (rc < 0) {
		LOGP(DLNS, LOGL_ERROR, "recv error %s during NS-FR-GRE recv\n",
		     strerror(errno));
		goto out_err;
	} else if (rc == 0) {
		goto out_err;
	}

	msgb_put(msg, rc);
	msg->dst = priv->link;
	return osmo_fr_rx(msg);

out_err:
	msgb_free(msg);
	return rc;
}

/* PDU from the frame relay towards the NS-VC (upwards) */
static int fr_dlci_rx_cb(void *cb_data, struct msgb *msg)
{
	int rc;
	struct gprs_ns2_vc *nsvc = cb_data;

	rc = ns2_recv_vc(nsvc, msg);

	return rc;
}

static int handle_netif_write(struct osmo_fd *bfd)
{
	/* FIXME */
	return -EIO;
}

static int fr_fd_cb(struct osmo_fd *bfd, unsigned int what)
{
	int rc = 0;

	if (what & OSMO_FD_READ)
		rc = handle_netif_read(bfd);
	if (what & OSMO_FD_WRITE)
		rc = handle_netif_write(bfd);

	return rc;
}

/*! determine if given bind is for FR-GRE encapsulation. */
int gprs_ns2_is_fr_bind(struct gprs_ns2_vc_bind *bind)
{
	return (bind->driver == &vc_driver_fr);
}

/* PDU from the NS-VC towards the frame relay layer (downwards) */
static int fr_vc_sendmsg(struct gprs_ns2_vc *nsvc, struct msgb *msg)
{
	struct priv_vc *vcpriv = nsvc->priv;

	msg->dst = vcpriv->dlc;
	return osmo_fr_tx_dlc(msg);
}

/* PDU from the frame relay layer towards the network interface (downwards) */
int fr_tx_cb(void *data, struct msgb *msg)
{
	struct gprs_ns2_vc_bind *bind = data;
	struct priv_bind *priv = bind->priv;
	int rc;

	/* FIXME half writes */
	rc = write(priv->fd.fd, msg->data, msg->len);
	msgb_free(msg);

	return rc;
}

static int devname2ifindex(const char *ifname)
{
	struct ifreq ifr;
	int sk, rc;

	sk = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sk < 0)
		return sk;


	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_name[sizeof(ifr.ifr_name)-1] = 0;

	rc = ioctl(sk, SIOCGIFINDEX, &ifr);
	close(sk);
	if (rc < 0)
		return rc;

	return ifr.ifr_ifindex;
}

static int open_socket(const char *ifname)
{
	struct sockaddr_ll addr;
	int ifindex;
	int fd, rc, on = 1;

	ifindex = devname2ifindex(ifname);
	if (ifindex < 0) {
		LOGP(DLNS, LOGL_ERROR, "Can not get interface index for interface %s\n", ifname);
		return ifindex;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = ifindex;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		LOGP(DLNS, LOGL_ERROR, "Can not get socket for interface %s. Are you root or have CAP_RAW_SOCKET?\n", ifname);
		return fd;
	}

	if (ioctl(fd, FIONBIO, (unsigned char *)&on) < 0) {
		LOGP(DLGLOBAL, LOGL_ERROR,
			"cannot set this socket unblocking: %s\n",
			strerror(errno));
		close(fd);
		fd = -EINVAL;
	}

	rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0) {
		LOGP(DLNS, LOGL_ERROR, "Can not bind for interface %s\n", ifname);
		close(fd);
		return rc;
	}

	return fd;
}

/*! Create a new bind for NS over FR.
 *  \param[in] nsi NS instance in which to create the bind
 *  \param[in] netif Network interface to bind to
 *  \param[in] fr_network
 *  \param[in] fr_role
 *  \param[out] result pointer to created bind
 *  \return 0 on success; negative on error */
int gprs_ns2_fr_bind(struct gprs_ns2_inst *nsi,
		     const char *netif,
		     struct osmo_fr_network *fr_network,
		     enum osmo_fr_role fr_role,
		     struct gprs_ns2_vc_bind **result)
{
	struct gprs_ns2_vc_bind *bind = talloc_zero(nsi, struct gprs_ns2_vc_bind);
	struct priv_bind *priv;
	struct osmo_fr_link *fr_link;
	int rc = 0;

	if (!bind)
		return -ENOSPC;

	bind->driver = &vc_driver_fr;
	bind->send_vc = fr_vc_sendmsg;
	bind->free_vc = free_vc;
	bind->dump_vty = dump_vty;
	bind->nsi = nsi;
	priv = bind->priv = talloc_zero(bind, struct priv_bind);
	if (!priv) {
		rc = -ENOSPC;
		goto err_bind;
	}

	priv->fd.cb = fr_fd_cb;
	priv->fd.data = bind;
	if (strlen(netif) > IF_NAMESIZE) {
		rc = -EINVAL;
		goto err_priv;
	}
	strncpy(priv->netif, netif, sizeof(priv->netif));

	ns2_vty_bind_apply(bind);
	if (result)
		*result = bind;

	/* FIXME: move fd handling into socket.c */
	fr_link = osmo_fr_link_alloc(fr_network, fr_role);
	if (!fr_link) {
		rc = -EINVAL;
		goto err_priv;
	}

	fr_link->tx_cb = fr_tx_cb;
	fr_link->tx_cb_data = bind;
	priv->link = fr_link;
	priv->fd.fd = rc = open_socket(netif);
	if (rc < 0)
		goto err_fr;

	priv->fd.when = OSMO_FD_READ;
	rc = osmo_fd_register(&priv->fd);
	if (rc < 0)
		goto err_fd;

	INIT_LLIST_HEAD(&bind->nsvc);
	llist_add(&bind->list, &nsi->binding);

	return rc;

err_fd:
	close(priv->fd.fd);
err_fr:
	osmo_fr_link_free(fr_link);
err_priv:
	talloc_free(priv);
err_bind:
	talloc_free(bind);

	return rc;
}

/*! Return the network interface of the bind
 * \param[in] bind The bind
 * \return the network interface
 */
const char *gprs_ns2_fr_bind_netif(struct gprs_ns2_vc_bind *bind)
{
	struct priv_bind *priv;

	priv = bind->priv;
	return priv->netif;
}

/*! Find NS bind for a given network interface
 * \param[in] nsi NS instance
 * \param[in] netif the network interface to search for
 * \return the bind or NULL if not found
 */
struct gprs_ns2_vc_bind *gprs_ns2_fr_bind_by_netif(
		struct gprs_ns2_inst *nsi,
		const char *netif)
{
	struct gprs_ns2_vc_bind *bind;
	const char *_netif;

	OSMO_ASSERT(nsi);
	OSMO_ASSERT(netif);

	llist_for_each_entry(bind, &nsi->binding, list) {
		if (!gprs_ns2_is_fr_bind(bind))
			continue;

		_netif = gprs_ns2_fr_bind_netif(bind);
		if (!strncmp(_netif, netif, IF_NAMESIZE))
			return bind;
	}

	return NULL;
}

/*! Create, connect and activate a new FR-based NS-VC
 *  \param[in] bind bind in which the new NS-VC is to be created
 *  \param[in] nsei NSEI of the NS Entity in which the NS-VC is to be created
 *  \param[in] dlci Data Link connection identifier
 *  \return pointer to newly-allocated, connected and activated NS-VC; NULL on error */
struct gprs_ns2_vc *gprs_ns2_fr_connect(struct gprs_ns2_vc_bind *bind,
					uint16_t nsei,
					uint16_t nsvci,
					uint16_t dlci)
{
	bool created_nse = false;
	struct gprs_ns2_vc *nsvc = NULL;
	struct priv_vc *priv = NULL;
	struct gprs_ns2_nse *nse = gprs_ns2_nse_by_nsei(bind->nsi, nsei);
	if (!nse) {
		nse = gprs_ns2_create_nse(bind->nsi, nsei);
		if (!nse)
			return NULL;
		created_nse = true;
	}

	nsvc = gprs_ns2_fr_nsvc_by_dlci(bind, dlci);
	if (nsvc) {
		goto err_nse;
	}

	nsvc = ns2_vc_alloc(bind, nse, true);
	if (!nsvc)
		goto err_nse;

	nsvc->priv = priv = fr_alloc_vc(bind, nsvc, dlci);
	if (!priv)
		goto err;

	nsvc->nsvci = nsvci;
	nsvc->nsvci_is_valid = true;

	gprs_ns2_vc_fsm_start(nsvc);

	return nsvc;

err:
	gprs_ns2_free_nsvc(nsvc);
err_nse:
	if (created_nse)
		gprs_ns2_free_nse(nse);

	return NULL;
}

/*! gprs_ns2_fr_nsvc_by_dlci
 * \param[in] bind
 * \param[in] dlci Data Link connection identifier
 * \return the nsvc or NULL if not found
 */
struct gprs_ns2_vc *gprs_ns2_fr_nsvc_by_dlci(struct gprs_ns2_vc_bind *bind,
					     uint16_t dlci)
{
	struct gprs_ns2_vc *nsvc;
	struct priv_vc *vcpriv;

	llist_for_each_entry(nsvc, &bind->nsvc, blist) {
		vcpriv = nsvc->priv;

		if (dlci == vcpriv->dlci)
			return nsvc;
	}

	return NULL;
}
