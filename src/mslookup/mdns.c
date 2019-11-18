#include <osmocom/core/msgb.h>
#include <osmocom/mslookup/mslookup.h>

int osmo_mdns_query_encode(void *ctx, struct msgb *msg, struct osmo_mslookup_query *query)
{
	return -1; /* FIXME */
}

int osmo_mdns_result_encode(void *ctx, struct msgb *msg, struct osmo_mslookup_result *result)
{
	return -1; /* FIXME */
}

int osmo_mdns_decode(const uint8_t *data, size_t data_len, struct osmo_mslookup_query *query,
		     struct osmo_mslookup_result *result)
{
	return -1; /* FIXME */
}
