/*! \file mdns_msg.h */

#pragma once

#include <stdint.h>
#include "mdns_rfc.h"

struct osmo_mdns_msg_request {
	uint16_t id;
	char *domain;
	enum osmo_mdns_rfc_record_type type;
};

struct osmo_mdns_msg_answer {
	uint16_t id;
	char *domain;
	struct llist_head records;
};

int osmo_mdns_msg_request_encode(void *ctx, struct msgb *msg, const struct osmo_mdns_msg_request *req);
struct osmo_mdns_msg_request *osmo_mdns_msg_request_decode(void *ctx, const uint8_t *data, size_t data_len);

void osmo_mdns_msg_answer_init(struct osmo_mdns_msg_answer *answer);
int osmo_mdns_msg_answer_encode(void *ctx, struct msgb *msg, const struct osmo_mdns_msg_answer *ans);
struct osmo_mdns_msg_answer *osmo_mdns_msg_answer_decode(void *ctx, const uint8_t *data, size_t data_len);
