#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/mslookup/mslookup.h>
#include <errno.h>
#include <inttypes.h>
#include "mdns_msg.h"
#include "mdns_record.h"

static char *domain_from_query(void *ctx, const struct osmo_mslookup_query *query)
{
	const char *id;

	/* Get id from query */
	switch (query->id.type) {
		case OSMO_MSLOOKUP_ID_IMSI:
			id = query->id.imsi;
			break;
		case OSMO_MSLOOKUP_ID_MSISDN:
			id = query->id.msisdn;
			break;
		default:
			LOGP(DLMSLOOKUP, LOGL_ERROR, "can't encode mslookup query id type %i", query->id.type);
			return NULL;
	}

	return talloc_asprintf(ctx, "%s.%s.%s", query->service, id, osmo_mslookup_id_type_name(query->id.type));
}

int osmo_mdns_query_encode(void *ctx, struct msgb *msg, uint16_t packet_id, const struct osmo_mslookup_query *query)
{
	struct osmo_mdns_msg_request req = {0};
	int ret;

	req.id = packet_id;
	req.type = OSMO_MDNS_RFC_RECORD_TYPE_ALL;
	req.domain = domain_from_query(ctx, query);
	if (!req.domain)
		return -EINVAL;

	ret = osmo_mdns_msg_request_encode(ctx, msg, &req);
	talloc_free(req.domain);
	return ret;
}

struct osmo_mslookup_query *osmo_mdns_query_decode(void *ctx, const uint8_t *data, size_t data_len,
						   uint16_t *packet_id)
{
	struct osmo_mdns_msg_request *req = NULL;
	struct osmo_mslookup_query *query = NULL;

	req = osmo_mdns_msg_request_decode(ctx, data, data_len);
	if (!req)
		return NULL;

	query = talloc_zero(ctx, struct osmo_mslookup_query);
	if (osmo_mslookup_query_from_domain_str(query, req->domain) < 0)
		goto error;

	*packet_id = req->id;
	talloc_free(req);
	return query;
error:
	if (req)
		talloc_free(req);
	if (query)
		talloc_free(query);
	return NULL;
}

static int sockaddr_str_from_mdns_record(struct osmo_sockaddr_str *sockaddr_str, struct osmo_mdns_record *rec)
{
	switch (rec->type) {
		case OSMO_MDNS_RFC_RECORD_TYPE_A:
			if (rec->length != 4) {
				LOGP(DLMSLOOKUP, LOGL_ERROR, "unexpected length of A record\n");
				return -EINVAL;
			}
			osmo_sockaddr_str_from_32(sockaddr_str, *(uint32_t *)rec->data, 0);
			break;
		case OSMO_MDNS_RFC_RECORD_TYPE_AAAA:
			if (rec->length != 16) {
				LOGP(DLMSLOOKUP, LOGL_ERROR, "unexpected length of AAAA record\n");
				return -EINVAL;
			}
			osmo_sockaddr_str_from_in6_addr(sockaddr_str, (struct in6_addr*)rec->data, 0);
			break;
		default:
			LOGP(DLMSLOOKUP, LOGL_ERROR, "unexpected record type\n");
			return -EINVAL;
	}
	return 0;
}

int osmo_mdns_result_encode(void *ctx, struct msgb *msg, uint16_t packet_id, const struct osmo_mslookup_query *query,
			    const struct osmo_mslookup_result *result)
{
	int ret = 0;
	struct osmo_mdns_msg_answer ans = {0};
	struct osmo_mdns_record *rec_age = NULL;
	struct osmo_mdns_record rec_ip_v4 = {0};
	struct osmo_mdns_record rec_ip_v6 = {0};
	struct osmo_mdns_record *rec_ip_v4_port = NULL;
	struct osmo_mdns_record *rec_ip_v6_port = NULL;
	struct in_addr rec_ip_v4_in;
	struct in6_addr rec_ip_v6_in;

	ctx = talloc_named(ctx, 0, "osmo_mdns_result_encode");

	/* Check result code */
	if (result->rc != OSMO_MSLOOKUP_RC_OK) {
		LOGP(DLMSLOOKUP, LOGL_ERROR, "can't encode mslookup result code %i\n", result->rc);
		goto error;
	}

	/* Prepare answer (ans) */
	ans.domain = domain_from_query(ctx, query);
	if (!ans.domain)
		goto error;
	ans.id = packet_id;
	INIT_LLIST_HEAD(&ans.records);

	/* Record for age */
	rec_age = osmo_mdns_record_txt_keyval_encode(ctx, "age", "%"PRIu32, result->age);
	OSMO_ASSERT(rec_age);
	llist_add_tail(&rec_age->list, &ans.records);

	/* Records for IPv4 */
	if (osmo_sockaddr_str_is_set(&result->host_v4)) {
		if (osmo_sockaddr_str_to_in_addr(&result->host_v4, &rec_ip_v4_in) < 0) {
			LOGP(DLMSLOOKUP, LOGL_ERROR, "failed to encode ipv4\n");
			goto error;
		}
		rec_ip_v4.type = OSMO_MDNS_RFC_RECORD_TYPE_A;
		rec_ip_v4.data = (uint8_t *)&rec_ip_v4_in;
		rec_ip_v4.length = sizeof(rec_ip_v4_in);
		llist_add_tail(&rec_ip_v4.list, &ans.records);

		rec_ip_v4_port = osmo_mdns_record_txt_keyval_encode(ctx, "port", "%"PRIu16, result->host_v4.port);
		OSMO_ASSERT(rec_ip_v4_port);
		llist_add_tail(&rec_ip_v4_port->list, &ans.records);
	}

	/* Records for IPv6 */
	if (osmo_sockaddr_str_is_set(&result->host_v6)) {
		if (osmo_sockaddr_str_to_in6_addr(&result->host_v6, &rec_ip_v6_in) < 0) {
			LOGP(DLMSLOOKUP, LOGL_ERROR, "failed to encode ipv6\n");
			goto error;
		}
		rec_ip_v6.type = OSMO_MDNS_RFC_RECORD_TYPE_AAAA;
		rec_ip_v6.data = (uint8_t *)&rec_ip_v6_in;
		rec_ip_v6.length = sizeof(rec_ip_v6_in);
		llist_add_tail(&rec_ip_v6.list, &ans.records);

		rec_ip_v6_port = osmo_mdns_record_txt_keyval_encode(ctx, "port", "%"PRIu16, result->host_v6.port);
		OSMO_ASSERT(rec_ip_v6_port);
		llist_add_tail(&rec_ip_v6_port->list, &ans.records);
	}

	ret = osmo_mdns_msg_answer_encode(ctx, msg, &ans);
	talloc_free(ctx);
	return ret;
error:
	talloc_free(ctx);
	return -EINVAL;
}

static int decode_uint32_t(const char *str, uint32_t *val)
{
	long long int lld;
	char *endptr = NULL;
	*val = 0;
	errno = 0;
	lld = strtoll(str, &endptr, 10);
	if (errno || !endptr || *endptr)
		return -EINVAL;
	if (lld < 0 || lld > UINT32_MAX)
		return -EINVAL;
	*val = lld;
	return 0;
}

static int decode_port(const char *str, uint16_t *port)
{
	uint32_t val;
	if (decode_uint32_t(str, &val))
		return -EINVAL;
	if (val > 65535)
		return -EINVAL;
	*port = val;
	return 0;
}

/*! Read expected mDNS records into mslookup result. The records must arrive in a specific format.
 *  Either "age", ip_v4/v6, "port" (only IPv4 or IPv6 present)
 *  or "age", ip_v4, "port", ip_v6, "port" (both IPv4 and v6 present).
 * "age" and "port" are TXT records, ip_v4 is an A record, ip_v6 is an AAAA record. */
int osmo_mdns_result_from_answer(struct osmo_mslookup_result *result, const struct osmo_mdns_msg_answer *ans)
{
	struct osmo_mdns_record *rec;
	char txt_key[64];
	char txt_value[64];
	bool found_age = false;
	bool found_ip_v4 = false;
	bool found_ip_v6 = false;
	struct osmo_sockaddr_str *expect_port_for = NULL;

	result->rc = OSMO_MSLOOKUP_RC_DECODE_ERROR;

	llist_for_each_entry(rec, &ans->records, list) {
		switch (rec->type) {
			case OSMO_MDNS_RFC_RECORD_TYPE_A:
				if (expect_port_for) {
					LOGP(DLMSLOOKUP, LOGL_ERROR,
					     "'A' record found, but still expecting a 'port' value first\n");
					return -EINVAL;
				}
				if (found_ip_v4) {
					LOGP(DLMSLOOKUP, LOGL_ERROR, "'A' record found twice in mDNS answer\n");
					return -EINVAL;
				}
				found_ip_v4 = true;
				expect_port_for = &result->host_v4;
				if (sockaddr_str_from_mdns_record(expect_port_for, rec)) {
					LOGP(DLMSLOOKUP, LOGL_ERROR, "'A' record with invalid address data\n");
					return -EINVAL;
				}
				break;
			case OSMO_MDNS_RFC_RECORD_TYPE_AAAA:
				if (expect_port_for) {
					LOGP(DLMSLOOKUP, LOGL_ERROR,
					     "'AAAA' record found, but still expecting a 'port' value first\n");
					return -EINVAL;
				}
				if (found_ip_v6) {
					LOGP(DLMSLOOKUP, LOGL_ERROR, "'AAAA' record found twice in mDNS answer\n");
					return -EINVAL;
				}
				found_ip_v6 = true;
				expect_port_for = &result->host_v6;
				if (sockaddr_str_from_mdns_record(expect_port_for, rec) != 0) {
					LOGP(DLMSLOOKUP, LOGL_ERROR, "'AAAA' record with invalid address data\n");
					return -EINVAL;
				}
				break;
			case OSMO_MDNS_RFC_RECORD_TYPE_TXT:
				if (osmo_mdns_record_txt_keyval_decode(rec, txt_key, sizeof(txt_key),
								       txt_value, sizeof(txt_value)) != 0) {
					LOGP(DLMSLOOKUP, LOGL_ERROR, "failed to decode txt record\n");
					return -EINVAL;
				}
				if (strcmp(txt_key, "age") == 0) {
					if (found_age) {
						LOGP(DLMSLOOKUP, LOGL_ERROR, "duplicate 'TXT' record for 'age'\n");
						return -EINVAL;
					}
					found_age = true;
					if (decode_uint32_t(txt_value, &result->age)) {
						LOGP(DLMSLOOKUP, LOGL_ERROR,
						     "'TXT' record: invalid 'age' value ('age=%s')\n", txt_value);
						return -EINVAL;
					}
				} else if (strcmp(txt_key, "port") == 0) {
					if (!expect_port_for) {
						LOGP(DLMSLOOKUP, LOGL_ERROR,
						     "'TXT' record for 'port' without previous 'A' or 'AAAA' record\n");
						return -EINVAL;
					}
					if (decode_port(txt_value, &expect_port_for->port)) {
						LOGP(DLMSLOOKUP, LOGL_ERROR,
						     "'TXT' record: invalid 'port' value ('port=%s')\n", txt_value);
						return -EINVAL;
					}
					expect_port_for = NULL;
				} else {
					LOGP(DLMSLOOKUP, LOGL_ERROR, "unexpected key '%s' in TXT record\n", txt_key);
					return -EINVAL;
				}
				break;
			default:
				LOGP(DLMSLOOKUP, LOGL_ERROR, "unexpected record type\n");
				return -EINVAL;
		}
	}

	/* Check if everything was found */
	if (!found_age || !(found_ip_v4 || found_ip_v6) || expect_port_for) {
		LOGP(DLMSLOOKUP, LOGL_ERROR, "missing resource records in mDNS answer\n");
		return -EINVAL;
	}

	result->rc = OSMO_MSLOOKUP_RC_OK;
	return 0;
}


int osmo_mdns_result_decode(void *ctx, const uint8_t *data, size_t data_len, uint16_t *packet_id,
			    struct osmo_mslookup_query *query, struct osmo_mslookup_result *result)
{
	int rc = -EINVAL;
	struct osmo_mdns_msg_answer *ans;
	ans = osmo_mdns_msg_answer_decode(ctx, data, data_len);
	if (!ans)
		goto exit_free;

	if (osmo_mslookup_query_from_domain_str(query, ans->domain) < 0)
		goto exit_free;

	if (osmo_mdns_result_from_answer(result, ans) < 0)
		goto exit_free;

	*packet_id = ans->id;
	rc = 0;
exit_free:
	if (ans)
		talloc_free(ans);
	return rc;
}
