/*! \file frame_relay.h */

#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>

#include <stdint.h>

struct osmo_tdef;
struct msgb;

enum osmo_fr_role {
	FR_ROLE_USER_EQUIPMENT,
	FR_ROLE_NETWORK_EQUIPMENT,
};

struct osmo_fr_network {
	struct llist_head links;

	unsigned int n391; 		/* full status polling counter */
	unsigned int n392;		/* error threshold */
	unsigned int n393;		/* monitored events count */

	struct osmo_tdef *T_defs;	/* T391, T392 */
};

struct osmo_fr_dlc;

/* Frame Relay Link */
struct osmo_fr_link {
	/* list in osmo_fr_network.links */
	struct llist_head list;
	struct osmo_fr_network *net;
	enum osmo_fr_role role;

	/* value of the last received send sequence number field in the
	 * link integrity verification information element */
	uint8_t last_rx_seq;

	/* value of the send sequence number field of the last link
	 * integrity verification information element sent */
	uint8_t last_tx_seq;

	struct osmo_timer_list t391;
	struct osmo_timer_list t392;

	unsigned int polling_count;
	unsigned int err_count;
	unsigned int succeed;
	/* the type of the last status enquiry */
	uint8_t expected_rep;
	bool state;

	/* list of data link connections at this link */
	struct llist_head dlc_list;

	int (*unknown_dlc_rx_cb)(void *cb_data, struct msgb *msg);
	void *unknown_dlc_rx_cb_data;

	int (*tx_cb)(void *data, struct msgb *msg);
	void *tx_cb_data;
};

/* Frame Relay Data Link Connection */
struct osmo_fr_dlc {
	/* entry in fr_link.dlc_list */
	struct llist_head list;
	struct osmo_fr_link *link;

	uint16_t dlci;

	/* is this DLC marked active for traffic? */
	bool active;
	/* was this DLC newly added? */
	bool add;
	/* is this DLC about to be destroyed */
	bool del;

	/* the local state needs to be transfered to the
	 * UE. The NET must wait until the UE confirms it implicited by a seq number check */
	bool state_send;

	int (*rx_cb)(void *cb_data, struct msgb *msg);
	void *rx_cb_data;
};

/* allocate a frame relay network */
struct osmo_fr_network *osmo_fr_network_alloc(void *ctx);

/* allocate a frame relay link in a given network */
struct osmo_fr_link *osmo_fr_link_alloc(struct osmo_fr_network *net, enum osmo_fr_role role);

/* free a frame link in a given network */
void osmo_fr_link_free(struct osmo_fr_link *link);

/* allocate a data link connectoin on a given framerelay link */
struct osmo_fr_dlc *osmo_fr_dlc_alloc(struct osmo_fr_link *link, uint16_t dlci);

struct osmo_fr_dlc *osmo_fr_dlc_by_dlci(struct osmo_fr_link *link, uint16_t dlci);

int osmo_fr_rx(struct msgb *msg);
int osmo_fr_tx_dlc(struct msgb *msg);
