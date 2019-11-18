/*! \file mdns_record.h */

#pragma once

#include "mdns_rfc.h"
#include <osmocom/core/linuxlist.h>
#include <stdint.h>

struct osmo_mdns_record {
	struct llist_head list;
	enum osmo_mdns_rfc_record_type type;
	uint16_t length;
	uint8_t *data;
};

struct osmo_mdns_record *osmo_mdns_record_txt_encode(void *ctx, const char *key, const char *value_fmt, ...);
int osmo_mdns_record_txt_decode(void *ctx, const struct osmo_mdns_record *rec, char **key, char **value);
