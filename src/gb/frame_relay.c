#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

#include <osmocom/gprs/frame_relay.h>
#include <osmocom/core/endian.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gsm/tlv.h>


#define DFR DLNS

/* Table 4-2/Q.931 */
enum q931_msgtype {
	/* Call establishment message */
	Q931_MSGT_ALERTING		= 0x01,
	Q931_MSGT_CALL_PROCEEDING	= 0x02,
	Q931_MSGT_CONNECT		= 0x07,
	Q931_MSGT_CONNECT_ACK		= 0x0f,
	Q931_MSGT_PROGRESS		= 0x03,
	Q931_MSGT_SETUP			= 0x05,
	Q931_MSGT_SETUP_ACK		= 0x0d,
	/* Call information phase message */
	Q931_MSGT_RESUME		= 0x26,
	Q931_MSGT_RESUME_ACK		= 0x2e,
	Q931_MSGT_RESUME_REJ		= 0x22,
	Q931_MSGT_SUSPEND		= 0x25,
	Q931_MSGT_SUSPEND_ACK		= 0x2d,
	Q931_MSGT_USER_INFO		= 0x20,
	/* Call clearing message */
	Q931_MSGT_DISCONNECT		= 0x45,
	Q931_MSGT_RELEASE		= 0x4d,
	Q931_MSGT_RELEASE_COMPLETE	= 0x5a,
	Q931_MSGT_RESTART		= 0x46,
	Q931_MSGT_RESTART_ACK		= 0x4e,
	/* Miscellaneous messages */
	Q931_MSGT_SEGMENT		= 0x60,
	Q931_MSGT_CONGESTION_CONTROL	= 0x79,
	Q931_MSGT_IFORMATION		= 0x7b,
	Q931_MSGT_NOTIFY		= 0x6e,
	Q931_MSGT_STATUS		= 0x7d,
	Q931_MSGT_STATUS_ENQUIRY	= 0x75,
};


/* Figure A.1/Q.933 Report type information element */
enum q933_type_of_report {
	Q933_REPT_FULL_STATUS		= 0x00,
	Q933_REPT_LINK_INTEGRITY_VERIF	= 0x01,
	Q933_REPT_SINGLE_PVC_ASYNC_STS	= 0x02,
};

/* Q.933 Section A.3 */
enum q933_iei {
	Q933_IEI_REPORT_TYPE		= 0x51,
	Q933_IEI_LINK_INT_VERIF		= 0x53,
	Q933_IEI_PVC_STATUS		= 0x57,
};

#define LAPF_UI			0x03	/* UI control word */
#define Q931_PDISC_CC		0x08	/* protocol discriminator */
#define LMI_Q933A_CALLREF	0x00	/* NULL call-ref */

/* LMI DLCI values */
#define LMI_Q933A_DLCI		0	/* Q.933A DLCI */
#define LMI_CISCO_DLCI		1023	/* Cisco DLCI */

/* maximum of supported */
#define MAX_SUPPORTED_PVC	10

/* TODO: add counters since good connection */

/* Message header of the L3 payload of a Q.933 Annex A message */
struct q933_a_hdr {
	uint8_t prot_disc;
	uint8_t call_ref;
	uint8_t msg_type;
} __attribute__((packed));

/* Value part of the Q.933 Annex A.3.3 IE */
struct q933_a_pvc_sts {
	uint8_t dlci_msb:6,
		spare:1,
		ext0:1;
	uint8_t space1:3,
		dlci_lsb:4,
		ext1:1;
	uint8_t reserved:1,
		active:1,
		delete:1,
		new:1,
		spare2:3,
		ext2:1;

} __attribute__((packed));

/* RX Message: 14 [ 00 01 03 08 00 75  95 01 01 00 03 02 01 00 ] */
/* RX Message: 13 [ 00 01 03 08 00 75  51 01 00  53 02 01 00 ] */

/* Table A.4/Q.933 */
struct osmo_tdef fr_tdefs[] = {
	{
		.T=391,
//		.default_val = 10,
	.default_val = 5,

		.min_val = 5,
		.max_val = 30,
		.desc = "Link integrity verification polling timer",
			.unit =  OSMO_TDEF_S,
	}, {
		.T=392,
		.default_val = 15,
		.min_val = 5,
		.max_val = 30,
		.desc = "Polling verification timer",
				.unit =  OSMO_TDEF_S,
	},
	{}
};

static const struct tlv_definition q933_att_tlvdef = {
	.def = {
		[Q933_IEI_REPORT_TYPE] = { TLV_TYPE_TLV },
		[Q933_IEI_LINK_INT_VERIF] = { TLV_TYPE_TLV },
		[Q933_IEI_PVC_STATUS] = { TLV_TYPE_TLV },
	},
};

static void check_link_state(struct osmo_fr_link *link, bool valid);

static inline uint16_t q922_to_dlci(const uint8_t *hdr)
{
	return ((hdr[0] & 0xFC) << 2) | ((hdr[1] & 0xF0) >> 4);
}


static inline void dlci_to_q922(uint8_t *hdr, uint16_t dlci)
{
	hdr[0] = (dlci >> 2) & 0xFC;
	hdr[1] = ((dlci << 4) & 0xF0) | 0x01;
}

/* allocate a message buffer and put Q.933 Annex A headers (L2 + L3) */
static struct msgb *q933_msgb_alloc(uint16_t dlci, uint8_t prot_disc, uint8_t msg_type)
{
	struct msgb *msg = msgb_alloc_headroom(1600+64, 64, "FR Q.933 Tx");
	struct q933_a_hdr *qh;

	if (!msg)
		return NULL;

	msg->l1h = msgb_put(msg, 2);
	dlci_to_q922(msg->l1h, dlci);

	/* LAPF UI control */
	msg->l2h = msgb_put(msg, 1);
	*msg->l2h = LAPF_UI;

	msg->l3h = msgb_put(msg, sizeof(*qh));
	qh = (struct q933_a_hdr *) msg->l3h;
	qh->prot_disc = prot_disc;
	qh->call_ref = LMI_Q933A_CALLREF;
	qh->msg_type = msg_type;

	return msg;
}

/* obtain the [next] transmit sequence number */
static uint8_t link_get_tx_seq(struct osmo_fr_link *link)
{
	/* The {user equipment, network} increments the send sequence
	 * counter using modulo 256. The value zero is skipped. */
	link->last_tx_seq++;
	if (link->last_tx_seq == 0)
		link->last_tx_seq++;

	return link->last_tx_seq;
}

/* Append PVC Status IE according to Q.933 A.3.2 */
static void msgb_put_link_int_verif(struct msgb *msg, struct osmo_fr_link *link)
{
	uint8_t link_int_tx[2];
	link_int_tx[0] = link_get_tx_seq(link);
	link_int_tx[1] = link->last_rx_seq;
	msgb_tlv_put(msg, Q933_IEI_LINK_INT_VERIF, 2, link_int_tx);
}

static void dlc_destroy(struct osmo_fr_dlc *dlc)
{
	llist_del(&dlc->list);
	talloc_free(dlc);
}

/* Append PVC Status IE according to Q.933 A.3.3 */
static void msgb_put_pvc_status(struct msgb *msg, struct osmo_fr_dlc *dlc)
{
	uint8_t ie[3];

	ie[0] = (dlc->dlci >> 4) & 0x3f;
	ie[1] = 0x80 | ((dlc->dlci & 0xf) << 3);
	ie[2] = 0x80;

	/* FIXME: validate: this status should be added as long it's not yet acked by the remote */
	if (dlc->active)
		ie[2] |= 0x02;

	if (dlc->add) {
		ie[2] |= 0x08;
		/* we've reported it as new once, reset the status */
	}

	if (dlc->del) {
		ie[2] |= 0x04;
		/* we've reported it as deleted once, destroy it */
		dlc_destroy(dlc);
	}

	msgb_tlv_put(msg, Q933_IEI_PVC_STATUS, 3, ie);
}

/* Send a Q.933 STATUS ENQUIRY given type over given link */
static int tx_lmi_q933_status_enq(struct osmo_fr_link *link, uint8_t rep_type)
{
	struct msgb *resp;

	resp = q933_msgb_alloc(0, Q931_PDISC_CC, Q931_MSGT_STATUS_ENQUIRY);
	if (!resp)
		return -1;
	resp->dst = link;
	link->expected_rep = rep_type;

	/* Table A.2/Q.933 */
	msgb_tlv_put(resp, Q933_IEI_REPORT_TYPE, 1, &rep_type);
	msgb_put_link_int_verif(resp, link);

	return link->tx_cb(link->tx_cb_data, resp);
}

/* Send a Q.933 STATUS of given type over given link */
static int tx_lmi_q933_status(struct osmo_fr_link *link, uint8_t rep_type)
{
	struct osmo_fr_dlc *dlc;
	struct msgb *resp;

	resp = q933_msgb_alloc(0, Q931_PDISC_CC, Q931_MSGT_STATUS);
	if (!resp)
		return -1;

	resp->dst = link;

	/* Table A.1/Q.933 */
	msgb_tlv_put(resp, Q933_IEI_REPORT_TYPE, 1, &rep_type);
	switch (rep_type) {
	case Q933_REPT_FULL_STATUS:
		msgb_put_link_int_verif(resp, link);
		llist_for_each_entry(dlc, &link->dlc_list, list) {
			if (dlc->add || dlc->del)
				dlc->state_send = true;

			msgb_put_pvc_status(resp, dlc);
		}
		break;
	case Q933_REPT_LINK_INTEGRITY_VERIF:
		msgb_put_link_int_verif(resp, link);
		llist_for_each_entry(dlc, &link->dlc_list, list) {
			if (dlc->add || dlc->del) {
				msgb_put_pvc_status(resp, dlc);
				dlc->state_send = true;
			}
		}
		break;
	case Q933_REPT_SINGLE_PVC_ASYNC_STS:
		llist_for_each_entry(dlc, &link->dlc_list, list)
			msgb_put_pvc_status(resp, dlc);
		break;
	}

	return link->tx_cb(link->tx_cb_data, resp);
}


/* Q.933 */
static int rx_lmi_q933_status_enq(struct msgb *msg, struct tlv_parsed *tp)
{
	struct osmo_fr_link *link = msg->dst;
	struct osmo_fr_dlc *dlc;
	const uint8_t *link_int_rx;
	uint8_t rep_type;

	if (link->role == FR_ROLE_USER_EQUIPMENT) {
		LOGP(DFR, LOGL_DEBUG, "Status enq aren't support for role user ");
		return -1;
	}

	/* check for mandatory IEs */
	if (!TLVP_PRES_LEN(tp, Q933_IEI_REPORT_TYPE, 1) ||
	    !TLVP_PRES_LEN(tp, Q933_IEI_LINK_INT_VERIF, 2))
		return -1;

	rep_type = *TLVP_VAL(tp, Q933_IEI_REPORT_TYPE);

	link_int_rx = TLVP_VAL(tp, Q933_IEI_LINK_INT_VERIF);
	link->last_rx_seq = link_int_rx[0];

	/* the network checks the receive sequence number received from
	 * the user equipment against its send sequence counter */
	if (link_int_rx[1] != link->last_tx_seq) {
		check_link_state(link, false);
		link->err_count++;
	} else {
		check_link_state(link, true);
		/* confirm DLC state changes */
		llist_for_each_entry(dlc, &link->dlc_list, list) {
			if (!dlc->state_send)
				continue;

			if (dlc->add) {
				dlc->active = link->state;
				dlc->add = false;
			}

			if (dlc->del) {
				dlc->del = false;
				/* TODO: implement FRNET free */
			}

			dlc->state_send = false;
		}
	}


	/* The network responds to each STATUS ENQUIRY message with a
	 * STATUS message and resets the T392 timer */
	osmo_timer_schedule(&link->t392, osmo_tdef_get(link->net->T_defs, 392, OSMO_TDEF_S, 15), 0);

	return tx_lmi_q933_status(link, rep_type);
}

/* check if the link become active or not.
 * param[in] valid contains the status of the last packet */
static void check_link_state(struct osmo_fr_link *link, bool valid)
{
	unsigned int last, i;
	unsigned int carry = 0;
	struct osmo_fr_dlc *dlc;

	link->succeed = link->succeed << 1;
	if (valid)
		link->succeed |= 1;

	/* count the bits */
	last = link->succeed & ((1 << link->net->n393) - 1);
	for (i = 0; i < link->net->n393; i++)
		if (last & 1 << i)
			carry++;

	if (link->net->n393 - carry >= link->net->n392) {
		/* failing link */
		if (!link->state)
			return;

		LOGP(DFR, LOGL_INFO, "Link failed");
		link->state = false;
		if (link->role == FR_ROLE_USER_EQUIPMENT)
			return;

		llist_for_each_entry(dlc, &link->dlc_list, list) {
			dlc->active = false;
		}
	} else {
		/* good link */
		if (link->state)
			return;

		LOGP(DFR, LOGL_INFO, "Link recovered");
		link->state = true;
		if (link->role == FR_ROLE_USER_EQUIPMENT)
			return;

		llist_for_each_entry(dlc, &link->dlc_list, list) {
			if (!dlc->add && !dlc->del)
				dlc->active = true;
		}
	}
}

static int validate_pvc_status(struct tlv_parsed *tp, size_t tp_len)
{
	size_t i;
	uint16_t len = 0;

	for (i = 0; i < tp_len; i++) {
		if (!TLVP_PRESENT(&tp[i], Q933_IEI_PVC_STATUS))
			continue;

		/* PVC status can be 2 or 3 bytes. If the PVC is bigger
		 * ignore this to be compatible to future extensions. */
		len = TLVP_LEN(&tp[i], Q933_IEI_PVC_STATUS);
		if (len <= 1) {
			return -EINVAL;
		}
		/* FIXME: validate correct flags: are some flags invalid at the same time? */
	}

	return 0;
}

static int parse_full_pvc_status(struct osmo_fr_link *link, struct tlv_parsed *tp, size_t tp_len)
{
	size_t i;
	int err = 0;
	struct osmo_fr_dlc *dlc, *tmp;
	struct q933_a_pvc_sts *pvc;
	uint16_t dlci = 0;
	uint16_t *dlcis = talloc_zero_array(link, uint16_t, tp_len);
	if (!dlcis)
		return -ENOMEM;

	/* first run validate all PVCs */
	err = validate_pvc_status(tp, tp_len);
	if (err < 0)
		goto out;

	for (i = 0; i < tp_len; i++) {
		if (!TLVP_PRESENT(&tp[i], Q933_IEI_PVC_STATUS))
			continue;

		/* parse only 3 byte PVCs */
		pvc = (struct q933_a_pvc_sts *) TLVP_VAL_MINLEN(
					&tp[i],
					Q933_IEI_PVC_STATUS,
					sizeof(struct q933_a_pvc_sts));
		if (!pvc)
			continue;

		dlci = ((pvc->dlci_msb & 0x3f) << 4) | (pvc->dlci_lsb & 0xf);
		dlcis[i] = dlci;
		dlc = osmo_fr_dlc_by_dlci(link, dlci);
		if (!dlc) {
			dlc = osmo_fr_dlc_alloc(link, dlci);
			if (!dlc) {
				LOGP(DFR, LOGL_ERROR, "Could not create DLC %d", dlci);
			}
		}

		/* Figure A.3/Q.933: The delete bit is only applicable for timely notification
		 *                   using the optional single PVC asynchronous status report.
		 * Ignoring the delete. */
		dlc->add = pvc->new;
		dlc->active = pvc->active;
		dlc->del = 0;
	}

	/* check if all dlc are present in PVC Status */
	llist_for_each_entry_safe(dlc, tmp, &link->dlc_list, list) {
		bool found = false;
		for (i = 0; i < tp_len; i++) {
			if (dlcis[i] == dlc->dlci) {
				found = true;
				break;
			}
		}

		if (!found) {
			dlc->active = false;
			dlc->del = true;
		}
	}

	return 0;
out:
	talloc_free(dlcis);
	return err;
}

static int parse_link_pvc_status(struct osmo_fr_link *link, struct tlv_parsed *tp, size_t tp_len)
{
	int err;
	size_t i;
	struct q933_a_pvc_sts *pvc;
	struct osmo_fr_dlc *dlc;
	uint16_t dlci = 0;

	err = validate_pvc_status(tp, tp_len);
	if (err < 0)
		return err;

	for (i = 0; i < tp_len; i++) {
		if (!TLVP_PRESENT(&tp[i], Q933_IEI_PVC_STATUS))
			continue;

		/* parse only 3 byte PVCs */
		pvc = (struct q933_a_pvc_sts *) TLVP_VAL_MINLEN(
					&tp[i],
					Q933_IEI_PVC_STATUS,
					sizeof(struct q933_a_pvc_sts));
		if (!pvc)
			continue;

		dlci = ((pvc->dlci_msb & 0x3f) << 4) | (pvc->dlci_lsb & 0xf);
		dlc = osmo_fr_dlc_by_dlci(link, dlci);
		if (!dlc) {
			/* don't create dlc's for the ones which are about to be deleted. */
			if (dlc->del)
				continue;

			dlc = osmo_fr_dlc_alloc(link, dlci);
			if (!dlc) {
				LOGP(DFR, LOGL_ERROR, "Could not create DLC %d", dlci);
			}
		}

		if (pvc->delete) {
			dlc->del = 1;
		} else {
			dlc->add = pvc->new;
			dlc->active = pvc->active;
			dlc->del = 0;
		}
	}

	return 0;
}

static size_t count_pvc_status(struct tlv_parsed *tp, size_t tp_len)
{
	size_t i, count = 0;
	for (i = 0; i < tp_len; i++) {
		if (!TLVP_PRESENT(&tp[i], Q933_IEI_PVC_STATUS))
			continue;
		count++;
	}

	return count;
}

static int rx_lmi_q933_status(struct msgb *msg, struct tlv_parsed *tp)
{
	struct osmo_fr_link *link = msg->dst;
	const uint8_t *link_int_rx;
	uint8_t rep_type;

	if (link->role == FR_ROLE_NETWORK_EQUIPMENT) {
		LOGP(DFR, LOGL_DEBUG, "Status aren't support for role network\n");
		return -1;
	}

	/* check for mandatory IEs */
	if (!TLVP_PRES_LEN(tp, Q933_IEI_REPORT_TYPE, 1)) {
		LOGP(DFR, LOGL_DEBUG, "Missing TLV Q933 Report Type\n");
		return -1;
	}

	rep_type = *TLVP_VAL(tp, Q933_IEI_REPORT_TYPE);

	switch (rep_type) {
	case Q933_REPT_FULL_STATUS:
	case Q933_REPT_LINK_INTEGRITY_VERIF:
		if (rep_type != link->expected_rep) {
			LOGP(DFR, LOGL_DEBUG, "Unexpected Q933 report type (got 0x%x != exp 0x%x)\n",
			     rep_type, link->expected_rep);
			return -1;
		}

		if (!TLVP_PRES_LEN(tp, Q933_IEI_LINK_INT_VERIF, 2)) {
			LOGP(DFR, LOGL_DEBUG, "Missing TLV Q933 Link Integrety Verification\n");
			return -1;
		}
		link_int_rx = TLVP_VAL(tp, Q933_IEI_LINK_INT_VERIF);
		link->last_rx_seq = link_int_rx[0];
		/* The received receive sequence number is not valid if
		 * it is not equal to the last transmitted send sequence
		 * number. Ignore messages containing this error. As a
		 * result, timer T391 expires and the user then
		 * increments the error count. */
		if (link_int_rx[1] != link->last_tx_seq)
			return 0;
		break;
	case Q933_REPT_SINGLE_PVC_ASYNC_STS:
	default:
		return -1;
	}

	check_link_state(link, true);
	if (count_pvc_status(tp, MAX_SUPPORTED_PVC + 1) > MAX_SUPPORTED_PVC) {
		LOGP(DFR, LOGL_ERROR, "Too many PVC! Only %d are supported!\n",
		     MAX_SUPPORTED_PVC);
	}

	switch (rep_type) {
	case Q933_REPT_FULL_STATUS:
		parse_full_pvc_status(link, tp, MAX_SUPPORTED_PVC);
		break;
	case Q933_REPT_LINK_INTEGRITY_VERIF:
		parse_link_pvc_status(link, tp, MAX_SUPPORTED_PVC);
		break;
	default:
		break;
	}

	/* The network responds to each STATUS ENQUIRY message with a
	 * STATUS message and resets the T392 timer */
	osmo_timer_schedule(&link->t392, osmo_tdef_get(link->net->T_defs, 392, OSMO_TDEF_S, 15), 0);

	return 0;
}

static int rx_lmi_q922(struct msgb *msg)
{
	struct q933_a_hdr *qh;
	/* the + 1 is used to detect more than MAX_SUPPORTED_PVC */
	struct tlv_parsed tp[MAX_SUPPORTED_PVC + 1];
	uint8_t *lapf;
	int rc;

	if (msgb_l2len(msg) < 1)
		return -1;
	lapf = msgb_l2(msg);

	/* we only support LAPF UI frames */
	if (lapf[0] != LAPF_UI)
		return -1;

	msg->l3h = msg->l2h + 1;
	if (msgb_l3len(msg) < 3)
		return -1;

	qh = (struct q933_a_hdr *) msgb_l3(msg);
	if (qh->prot_disc != Q931_PDISC_CC) {
		LOGP(DFR, LOGL_NOTICE, "Rx unsupported LMI protocol discriminator %u\n", qh->prot_disc);
		return -1;
	}

	tlv_parse2(tp, MAX_SUPPORTED_PVC + 1, &q933_att_tlvdef, msgb_l3(msg) + sizeof(*qh), msgb_l3len(msg) - sizeof(*qh), 0, 0);

	switch (qh->msg_type) {
	case Q931_MSGT_STATUS_ENQUIRY:
		rc = rx_lmi_q933_status_enq(msg, tp);
		break;
	case Q931_MSGT_STATUS:
		rc = rx_lmi_q933_status(msg, tp);
		break;
	default:
		LOGP(DFR, LOGL_NOTICE, "Rx unsupported LMI message type %u\n", qh->msg_type);
		rc = -1;
		break;
	}
	msgb_free(msg);

	return rc;
}

int osmo_fr_rx(struct msgb *msg)
{
	int rc = 0;
	uint8_t *frh;
	uint16_t dlci;
	struct osmo_fr_dlc *dlc;
	struct osmo_fr_link *link = msg->dst;

	if (msgb_length(msg) < 2) {
		LOGP(DFR, LOGL_ERROR, "Short FR header: %u bytes\n", msgb_length(msg));
		rc = -1;
		goto out;
	}

	frh = msg->l1h = msgb_data(msg);
	if (frh[0] & 0x01) {
		LOGP(DFR, LOGL_NOTICE, "Unsupported single-byte FR address\n");
		rc = -1;
		goto out;
	}
	if ((frh[1] & 0x0f) != 0x01) {
		LOGP(DFR, LOGL_NOTICE, "Unknown second FR octet 0x%02x\n", frh[1]);
		rc = -1;
		goto out;
	}
	dlci = q922_to_dlci(frh);
	msg->l2h = frh + 2;

	switch (dlci) {
	case LMI_Q933A_DLCI:
		return rx_lmi_q922(msg);
	case LMI_CISCO_DLCI:
		LOGP(DFR, LOGL_NOTICE, "Unsupported FR DLCI %u\n", dlci);
		goto out;
	}

	if (!link->state) {
		LOGP(DFR, LOGL_NOTICE, "Link is not reliable. Discarding Rx PDU on DLCI %d\n", dlci);
		goto out;
	}

	llist_for_each_entry(dlc, &link->dlc_list, list) {
		if (dlc->dlci == dlci) {
			/* dispatch to handler of respective DLC */
			msg->dst = dlc;
			return dlc->rx_cb(dlc->rx_cb_data, msg);
		}
	}

	if (link->unknown_dlc_rx_cb)
		return link->unknown_dlc_rx_cb(link->unknown_dlc_rx_cb_data, msg);
	else
		LOGP(DFR, LOGL_NOTICE, "DLCI %u doesn't exist, discarding\n", dlci);

out:
	msgb_free(msg);

	return rc;
}

int osmo_fr_tx_dlc(struct msgb *msg)
{
	uint8_t *frh;
	struct osmo_fr_dlc *dlc = msg->dst;
	struct osmo_fr_link *link = dlc->link;

	if (!link->state || !dlc->active) {
		LOGP(DFR, LOGL_NOTICE, "DLCI %u is not active (yet), discarding\n", dlc->dlci);
		msgb_free(msg);
		return -1;
	}
	LOGP(DFR, LOGL_NOTICE, "DLCI %u is active, sending message\n", dlc->dlci);

	if (msgb_headroom(msg) < 2) {
		msgb_free(msg);
		return -ENOSPC;
	}

	frh = msgb_push(msg, 2);
	dlci_to_q922(frh, dlc->dlci);

	msg->dst = link;
	return link->tx_cb(link->tx_cb_data, msg);
}

/* Every T391 seconds, the user equipment sends a STATUS ENQUIRY
 * message to the network and resets its polling timer (T391). */
static void fr_t391_cb(void *data)
{
	struct osmo_fr_link *link = data;

	if (link->polling_count % link->net->n391 == 0)
		tx_lmi_q933_status_enq(link, Q933_REPT_FULL_STATUS);
	else
		tx_lmi_q933_status_enq(link, Q933_REPT_LINK_INTEGRITY_VERIF);
	link->polling_count++;
	osmo_timer_schedule(&link->t391, osmo_tdef_get(link->net->T_defs, 391, OSMO_TDEF_S, 10), 0);
}

static void fr_t392_cb(void *data)
{
	struct osmo_fr_link *link = data;
	/* A.5 The network increments the error count .. Non-receipt of
	 * a STATUS ENQUIRY within T392, which results in restarting
	 * T392 */
	link->err_count++;
	check_link_state(link, false);
	osmo_timer_schedule(&link->t392, osmo_tdef_get(link->net->T_defs, 392, OSMO_TDEF_S, 15), 0);
}

/* allocate a frame relay network */
struct osmo_fr_network *osmo_fr_network_alloc(void *ctx)
{
	struct osmo_fr_network *net = talloc_zero(ctx, struct osmo_fr_network);

	INIT_LLIST_HEAD(&net->links);
	net->T_defs = fr_tdefs;
	osmo_tdefs_reset(net->T_defs);
	net->n391 = 6;
	net->n392 = 3;
	net->n393 = 4;

	return net;
}

void osmo_fr_network_free(struct osmo_fr_network *net)
{
	struct osmo_fr_link *link, *tmp;

	if (!net)
		return;

	llist_for_each_entry_safe(link, tmp, &net->links, list) {
		osmo_fr_link_free(link);
	}
}

/* allocate a frame relay link in a given network */
struct osmo_fr_link *osmo_fr_link_alloc(struct osmo_fr_network *net, enum osmo_fr_role role)
{
	struct osmo_fr_link *link = talloc_zero(net, struct osmo_fr_link);
	if (!link)
		return NULL;

	LOGP(DFR, LOGL_INFO, "Creating frame relay link with role %d\n", role);

	link->role = role;
	link->net = net;
	INIT_LLIST_HEAD(&link->dlc_list);
	llist_add_tail(&link->list, &net->links);

	osmo_timer_setup(&link->t391, fr_t391_cb, link);
	osmo_timer_setup(&link->t392, fr_t392_cb, link);

	switch (role) {
	case FR_ROLE_USER_EQUIPMENT:
		osmo_timer_schedule(&link->t391, osmo_tdef_get(link->net->T_defs, 391, OSMO_TDEF_S, 15), 0);
		break;
	case FR_ROLE_NETWORK_EQUIPMENT:
		osmo_timer_schedule(&link->t392, osmo_tdef_get(link->net->T_defs, 392, OSMO_TDEF_S, 15), 0);
		break;
	}

	return link;
}

void osmo_fr_link_free(struct osmo_fr_link *link)
{
	if (!link)
		return;

	osmo_timer_del(&link->t391);
	osmo_timer_del(&link->t392);

	llist_del(&link->list);
	talloc_free(link);
}

/* allocate a data link connectoin on a given framerelay link */
struct osmo_fr_dlc *osmo_fr_dlc_alloc(struct osmo_fr_link *link, uint16_t dlci)
{
	struct osmo_fr_dlc *dlc = talloc_zero(link, struct osmo_fr_dlc);
	if (!dlc)
		return NULL;

	dlc->link = link;
	dlc->dlci = dlci;
	dlc->active = false;

	llist_add_tail(&dlc->list, &link->dlc_list);

	dlc->add = true;
	tx_lmi_q933_status(link, Q933_IEI_PVC_STATUS);

	return dlc;
}

/* TODO: osmo_fr_dlc_alloc with deregistering it from the link in fr-net */

struct osmo_fr_dlc *osmo_fr_dlc_by_dlci(struct osmo_fr_link *link, uint16_t dlci)
{
	struct osmo_fr_dlc *dlc;

	llist_for_each_entry(dlc, &link->dlc_list, list) {
		if (dlc->dlci == dlci)
			return dlc;
	}
	return NULL;
}
