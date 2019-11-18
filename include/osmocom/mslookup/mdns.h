/*! \file mdns.h */

#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/mslookup/mslookup.h>

int osmo_mdns_query_encode(void *ctx, struct msgb *msg, uint16_t packet_id, const struct osmo_mslookup_query *query);

struct osmo_mslookup_query *osmo_mdns_query_decode(void *ctx, const uint8_t *data, size_t data_len,
						   uint16_t *packet_id);

int osmo_mdns_result_encode(void *ctx, struct msgb *msg, uint16_t packet_id, const struct osmo_mslookup_query *query,
			    const struct osmo_mslookup_result *result);

int osmo_mdns_result_decode(void *ctx, const uint8_t *data, size_t data_len, uint16_t *packet_id,
			    struct osmo_mslookup_query *query, struct osmo_mslookup_result *result);
