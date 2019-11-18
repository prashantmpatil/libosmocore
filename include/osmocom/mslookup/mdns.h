/*! \file mdns.h */

#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/mslookup/mslookup.h>

int osmo_mdns_query_encode(void *ctx, struct msgb *msg, struct osmo_mslookup_query *query);

int osmo_mdns_result_encode(void *ctx, struct msgb *msg, struct osmo_mslookup_result *result);

int osmo_mdns_decode(const uint8_t *data, size_t data_len, struct osmo_mslookup_query *query,
		     struct osmo_mslookup_result *result);
