/*! \file gprs_ns2_udp.c
 * NS-over-UDP implementation.
 * GPRS Networks Service (NS) messages on the Gb interface.
 * 3GPP TS 08.16 version 8.0.1 Release 1999 / ETSI TS 101 299 V8.0.1 (2002-05)
 * as well as its successor 3GPP TS 48.016 */

/* (C) 2020 sysmocom - s.f.m.c. GmbH
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

#include <osmocom/core/select.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/core/socket.h>
#include <osmocom/gprs/gprs_ns2.h>

#include "common_vty.h"
#include "gprs_ns2_internal.h"


static void free_bind(struct gprs_ns2_vc_bind *bind);


struct gprs_ns2_vc_driver vc_driver_ip = {
	.name = "GB UDP IPv4/IPv6",
	.free_bind = free_bind,
};

struct priv_bind {
	struct osmo_fd fd;
	struct osmo_sockaddr addr;
	int dscp;
};

struct priv_vc {
	struct osmo_sockaddr remote;
};

/*! clean up all private driver state. Should be only called by gprs_ns2_free_bind() */
static void free_bind(struct gprs_ns2_vc_bind *bind)
{
	struct priv_bind *priv;

	if (!bind)
		return;

	priv = bind->priv;

	osmo_fd_close(&priv->fd);
	talloc_free(priv);
}

static void free_vc(struct gprs_ns2_vc *nsvc)
{
	if (!nsvc->priv)
		return;

	talloc_free(nsvc->priv);
	nsvc->priv = NULL;
}

static void dump_vty(const struct gprs_ns2_vc_bind *bind,
		     struct vty *vty, bool _stats)
{
	struct priv_bind *priv;
	struct gprs_ns2_vc *nsvc;
	struct osmo_sockaddr_str sockstr = {};
	unsigned long nsvcs = 0;

	if (!bind)
		return;

	priv = bind->priv;
	if (osmo_sockaddr_str_from_sockaddr(&sockstr, &priv->addr.u.sas))
		strcpy(sockstr.ip, "invalid");

	llist_for_each_entry(nsvc, &bind->nsvc, blist) {
		nsvcs++;
	}

	vty_out(vty, "UDP bind: %s:%d dcsp: %d%s", sockstr.ip, sockstr.port, priv->dscp, VTY_NEWLINE);
	vty_out(vty, "  %lu NS-VC: %s", nsvcs, VTY_NEWLINE);

	llist_for_each_entry(nsvc, &bind->nsvc, blist) {
		vty_out(vty, "    %s%s", gprs_ns2_ll_str(nsvc), VTY_NEWLINE);
	}
}


/*! Find a NS-VC by its remote socket address.
 *  \param[in] bind in which to search
 *  \param[in] saddr remote peer socket adddress to search
 *  \returns NS-VC matching sockaddr; NULL if none found */
struct gprs_ns2_vc *gprs_ns2_nsvc_by_sockaddr_bind(struct gprs_ns2_vc_bind *bind,
						   const struct osmo_sockaddr *saddr)
{
	struct gprs_ns2_vc *nsvc;
	struct priv_vc *vcpriv;

	llist_for_each_entry(nsvc, &bind->nsvc, blist) {
		vcpriv = nsvc->priv;
		if (vcpriv->remote.u.sa.sa_family != saddr->u.sa.sa_family)
			continue;
		if (osmo_sockaddr_cmp(&vcpriv->remote, saddr))
			continue;

		return nsvc;
	}

	return NULL;
}

static inline int nsip_sendmsg(struct gprs_ns2_vc_bind *bind,
			       struct msgb *msg,
			       struct osmo_sockaddr *dest)
{
	int rc;
	struct priv_bind *priv = bind->priv;

	rc = sendto(priv->fd.fd, msg->data, msg->len, 0,
		    &dest->u.sa, sizeof(*dest));

	msgb_free(msg);

	return rc;
}

/*! send the msg and free it afterwards.
 * \param nsvc NS-VC on which the message shall be sent
 * \param msg message to be sent
 * \return number of bytes transmitted; negative on error */
static int nsip_vc_sendmsg(struct gprs_ns2_vc *nsvc, struct msgb *msg)
{
	int rc;
	struct gprs_ns2_vc_bind *bind = nsvc->bind;
	struct priv_vc *priv = nsvc->priv;

	rc = nsip_sendmsg(bind, msg, &priv->remote);

	return rc;
}

/* Read a single NS-over-IP message */
static struct msgb *read_nsip_msg(struct osmo_fd *bfd, int *error,
				  struct osmo_sockaddr *saddr)
{
	struct msgb *msg = gprs_ns2_msgb_alloc();
	int ret = 0;
	socklen_t saddr_len = sizeof(*saddr);

	if (!msg) {
		*error = -ENOMEM;
		return NULL;
	}

	ret = recvfrom(bfd->fd, msg->data, NS_ALLOC_SIZE - NS_ALLOC_HEADROOM, 0,
			&saddr->u.sa, &saddr_len);
	if (ret < 0) {
		LOGP(DLNS, LOGL_ERROR, "recv error %s during NSIP recvfrom %s\n",
		     strerror(errno), osmo_sock_get_name2(bfd->fd));
		msgb_free(msg);
		*error = ret;
		return NULL;
	} else if (ret == 0) {
		msgb_free(msg);
		*error = ret;
		return NULL;
	}

	msg->l2h = msg->data;
	msgb_put(msg, ret);

	return msg;
}

static struct priv_vc *ns2_driver_alloc_vc(struct gprs_ns2_vc_bind *bind, struct gprs_ns2_vc *nsvc, struct osmo_sockaddr *remote)
{
	struct priv_vc *priv = talloc_zero(bind, struct priv_vc);
	if (!priv)
		return NULL;

	nsvc->priv = priv;
	priv->remote = *remote;

	return priv;
}

static int handle_nsip_read(struct osmo_fd *bfd)
{
	int rc = 0;
	int error = 0;
	struct gprs_ns2_vc_bind *bind = bfd->data;
	struct osmo_sockaddr saddr;
	struct gprs_ns2_vc *nsvc;
	struct msgb *msg = read_nsip_msg(bfd, &error, &saddr);
	struct msgb *reject;

	if (!msg)
		return -EINVAL;

	/* check if a vc is available */
	nsvc = gprs_ns2_nsvc_by_sockaddr_bind(bind, &saddr);
	if (!nsvc) {
		/* VC not found */
		rc = ns2_create_vc(bind, msg, "newconnection", &reject, &nsvc);
		switch (rc) {
		case GPRS_NS2_CS_FOUND:
			break;
		case GPRS_NS2_CS_ERROR:
		case GPRS_NS2_CS_SKIPPED:
			rc = 0;
			goto out;
		case GPRS_NS2_CS_REJECTED:
			/* nsip_sendmsg will free reject */
			rc = nsip_sendmsg(bind, reject, &saddr);
			goto out;
		case GPRS_NS2_CS_CREATED:
			ns2_driver_alloc_vc(bind, nsvc, &saddr);
			gprs_ns2_vc_fsm_start(nsvc);
			break;
		}
	}

	return ns2_recv_vc(nsvc, msg);

out:
	msgb_free(msg);
	return rc;
}

static int handle_nsip_write(struct osmo_fd *bfd)
{
	/* FIXME: actually send the data here instead of nsip_sendmsg() */
	return -EIO;
}

static int nsip_fd_cb(struct osmo_fd *bfd, unsigned int what)
{
	int rc = 0;

	if (what & OSMO_FD_READ)
		rc = handle_nsip_read(bfd);
	if (what & OSMO_FD_WRITE)
		rc = handle_nsip_write(bfd);

	return rc;
}

/*! Find NS bind for a given socket address
 *  \param[in] nsi NS instance
 *  \param[in] sockaddr socket address to search for
 *  \return
 */
struct gprs_ns2_vc_bind *gprs_ns2_ip_bind_by_sockaddr(struct gprs_ns2_inst *nsi,
						      const struct osmo_sockaddr *sockaddr)
{
	struct gprs_ns2_vc_bind *bind;
	const struct osmo_sockaddr *local;

	OSMO_ASSERT(nsi);
	OSMO_ASSERT(sockaddr);

	llist_for_each_entry(bind, &nsi->binding, list) {
		if (!gprs_ns2_is_ip_bind(bind))
			continue;

		local = gprs_ns2_ip_bind_sockaddr(bind);
		if (!osmo_sockaddr_cmp(sockaddr, local))
			return bind;
	}

	return NULL;
}

/*! Bind to an IPv4/IPv6 address
 *  \param[in] nsi NS Instance in which to create the NSVC
 *  \param[in] local the local address to bind to
 *  \param[in] dscp the DSCP/TOS bits used for transmitted data
 *  \param[out] result if set, returns the bind object
 *  \return 0 on success; negative in case of error */
int gprs_ns2_ip_bind(struct gprs_ns2_inst *nsi,
		     const struct osmo_sockaddr *local,
		     int dscp,
		     struct gprs_ns2_vc_bind **result)
{
	struct gprs_ns2_vc_bind *bind;
	struct priv_bind *priv;
	int rc;

	bind = gprs_ns2_ip_bind_by_sockaddr(nsi, local);
	if (bind) {
		*result = bind;
		return -EBUSY;
	}

	bind = talloc_zero(nsi, struct gprs_ns2_vc_bind);
	if (!bind)
		return -ENOSPC;

	if (local->u.sa.sa_family != AF_INET && local->u.sa.sa_family != AF_INET6) {
		talloc_free(bind);
		return -EINVAL;
	}

	bind->driver = &vc_driver_ip;
	bind->send_vc = nsip_vc_sendmsg;
	bind->free_vc = free_vc;
	bind->dump_vty = dump_vty;
	bind->nsi = nsi;

	priv = bind->priv = talloc_zero(bind, struct priv_bind);
	if (!priv) {
		talloc_free(bind);
		return -ENOSPC;
	}
	priv->fd.cb = nsip_fd_cb;
	priv->fd.data = bind;
	priv->addr = *local;
	INIT_LLIST_HEAD(&bind->nsvc);

	rc = osmo_sock_init_osa_ofd(&priv->fd, SOCK_DGRAM, IPPROTO_UDP,
				 local, NULL,
				 OSMO_SOCK_F_BIND);
	if (rc < 0) {
		talloc_free(priv);
		talloc_free(bind);
		return rc;
	}

	if (dscp > 0) {
		priv->dscp = dscp;

		rc = setsockopt(priv->fd.fd, IPPROTO_IP, IP_TOS,
				&dscp, sizeof(dscp));
		if (rc < 0)
			LOGP(DLNS, LOGL_ERROR,
				"Failed to set the DSCP to %d with ret(%d) errno(%d)\n",
				dscp, rc, errno);
	}

	llist_add(&bind->list, &nsi->binding);
	ns2_vty_bind_apply(bind);

	if (result)
		*result = bind;

	return 0;
}

/*! Create new NS-VC to a given remote address
 *  \param[in] bind the bind we want to connect
 *  \param[in] nse NS entity to be used for the new NS-VC
 *  \param[in] remote remote address to connect to
 *  \return pointer to newly-allocated and connected NS-VC; NULL on error */
struct gprs_ns2_vc *gprs_ns2_ip_bind_connect(struct gprs_ns2_vc_bind *bind,
					     struct gprs_ns2_nse *nse,
					     const struct osmo_sockaddr *remote)
{
	struct gprs_ns2_vc *nsvc;
	struct priv_vc *priv;

	nsvc = ns2_vc_alloc(bind, nse, true);
	if (!nsvc)
		return NULL;

	nsvc->priv = talloc_zero(bind, struct priv_vc);
	if (!nsvc->priv) {
		gprs_ns2_free_nsvc(nsvc);
		return NULL;
	}

	priv = nsvc->priv;
	priv->remote = *remote;

	nsvc->ll = GPRS_NS_LL_UDP;

	return nsvc;
}

/*! Return the socket address of the local peer of a NS-VC.
 *  \param[in] nsvc NS-VC whose local peer we want to know
 *  \return address of the local peer; NULL in case of error */
const struct osmo_sockaddr *gprs_ns2_ip_vc_local(const struct gprs_ns2_vc *nsvc)
{
	struct priv_bind *priv;

	if (nsvc->ll != GPRS_NS_LL_UDP)
		return NULL;

	if (nsvc->bind->driver != &vc_driver_ip)
		return NULL;

	priv = nsvc->bind->priv;
	return &priv->addr;
}

/*! Return the socket address of the remote peer of a NS-VC.
 *  \param[in] nsvc NS-VC whose remote peer we want to know
 *  \return address of the remote peer; NULL in case of error */
const struct osmo_sockaddr *gprs_ns2_ip_vc_remote(const struct gprs_ns2_vc *nsvc)
{
	struct priv_vc *priv;

	if (nsvc->ll != GPRS_NS_LL_UDP)
		return NULL;

	priv = nsvc->priv;
	return &priv->remote;
}

/*! Compare the NS-VC with the given parameter
 *  \param[in] nsvc NS-VC to compare with
 *  \param[in] local The local address
 *  \param[in] remote The remote address
 *  \param[in] nsvci NS-VCI will only be used if the NS-VC in BLOCKRESET mode otherwise NS-VCI isn't applicable.
 *  \return true if the NS-VC has the same properties as given
 */
bool gprs_ns2_ip_vc_equal(const struct gprs_ns2_vc *nsvc,
			  const struct osmo_sockaddr *local,
			  const struct osmo_sockaddr *remote,
			  uint16_t nsvci)
{
	struct priv_vc *vpriv;
	struct priv_bind *bpriv;

	if (nsvc->ll != GPRS_NS_LL_UDP)
		return false;

	vpriv = nsvc->priv;
	bpriv = nsvc->bind->priv;

	if (osmo_sockaddr_cmp(local, &bpriv->addr))
		return false;

	if (osmo_sockaddr_cmp(remote, &vpriv->remote))
		return false;

	if (nsvc->mode == NS2_VC_MODE_BLOCKRESET)
		if (nsvc->nsvci != nsvci)
			return false;

	return true;
}

/*! Return the locally bound socket address of the bind.
 *  \param[in] bind The bind whose local address we want to know
 *  \return address of the local bind */
const struct osmo_sockaddr *gprs_ns2_ip_bind_sockaddr(struct gprs_ns2_vc_bind *bind)
{
	struct priv_bind *priv;

	priv = bind->priv;
	return &priv->addr;
}

/*! Is the given bind an IP bind? */
int gprs_ns2_is_ip_bind(struct gprs_ns2_vc_bind *bind)
{
	return (bind->driver == &vc_driver_ip);
}

/*! Set the DSCP (TOS) bit value of the given bind. */
int gprs_ns2_ip_bind_set_dscp(struct gprs_ns2_vc_bind *bind, int dscp)
{
	struct priv_bind *priv;
	int rc = 0;

	priv = bind->priv;

	if (dscp != priv->dscp) {
		priv->dscp = dscp;

		rc = setsockopt(priv->fd.fd, IPPROTO_IP, IP_TOS,
				&dscp, sizeof(dscp));
		if (rc < 0)
			LOGP(DLNS, LOGL_ERROR,
			     "Failed to set the DSCP to %d with ret(%d) errno(%d)\n",
			     dscp, rc, errno);
	}

	return rc;
}
