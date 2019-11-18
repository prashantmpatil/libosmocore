#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <osmocom/mslookup/mslookup_client.h>
#include <osmocom/mslookup/mslookup_client_mdns.h>
#include <osmocom/core/select.h>
#include <osmocom/core/logging.h>
#include <osmocom/mslookup/mdns.h>
#include <osmocom/mslookup/mdns_sock.h>

/* FIXME: to be replaced with new mdns.h api calls */
#include "mdns_msg.h"
#include "mdns_record.h"

struct osmo_mdns_method_state {
	/* Parameters passed by _add_method_dns() */
	struct osmo_sockaddr_str bind_addr;

	struct osmo_mdns_sock *mc;

	struct osmo_mslookup_client *client;
	struct llist_head requests;
	uint16_t next_packet_id;
};

struct osmo_mdns_method_request {
	struct llist_head entry;
	uint32_t request_handle;
	struct osmo_mslookup_query query;
	struct osmo_mdns_msg_request dns_req;
};

static int sock_addrstr_from_mdns_record(struct osmo_sockaddr_str *sockaddr_str, struct osmo_mdns_record *rec)
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

/*! Read expected mDNS records into mslookup result. The records must arrive in a specific format.
 *  Either "age", ip_v4/v6, "port" (only IPv4 or IPv6 present)
 *  or "age", ip_v4, "port", ip_v6, "port" (both IPv4 and v6 present).
 * "age" and "port" are TXT records, ip_v4 is an A record, ip_v6 is an AAAA record. */
struct osmo_mslookup_result *result_from_mdns_answer(void *ctx, struct osmo_mdns_msg_answer *ans)
{
	struct osmo_mdns_record *rec, *rec_prev;
	char *txt_key;
	char *txt_value;
	struct osmo_mslookup_result *ret = talloc_zero(ctx, struct osmo_mslookup_result);
	bool found_age = false;
	bool found_ip_v4 = false;
	bool found_ip_v6 = false;
	int found_ports = 0;

	llist_for_each_entry(rec, &ans->records, list) {
		switch (rec->type) {
			case OSMO_MDNS_RFC_RECORD_TYPE_A:
				if (found_ip_v4) {
					LOGP(DLMSLOOKUP, LOGL_ERROR, "'A' record found twice in mDNS answer\n");
					goto error;
				}
				found_ip_v4 = true;
				if (sock_addrstr_from_mdns_record(&ret->host_v4, rec) != 0)
					goto error;
				break;
			case OSMO_MDNS_RFC_RECORD_TYPE_AAAA:
				if (found_ip_v6) {
					LOGP(DLMSLOOKUP, LOGL_ERROR, "'AAAA' record found twice in mDNS answer\n");
					goto error;
				}
				found_ip_v6 = true;
				if (sock_addrstr_from_mdns_record(&ret->host_v6, rec) != 0)
					goto error;
				break;
			case OSMO_MDNS_RFC_RECORD_TYPE_TXT:
				if (osmo_mdns_record_txt_decode(ret, rec, &txt_key, &txt_value) != 0) {
					LOGP(DLMSLOOKUP, LOGL_ERROR, "failed to decode txt record\n");
					goto error;
				}
				if (strcmp(txt_key, "age") == 0) {
					if (found_age) {
						LOGP(DLMSLOOKUP, LOGL_ERROR, "'TXT' record for 'age' found twice in"
									     " mDNS answer\n");
						goto error;
					}
					found_age = true;
					ret->age = atoi(txt_value);
				} else if (strcmp(txt_key, "port") == 0) {
					if (rec->list.prev == &ans->records) {
						LOGP(DLMSLOOKUP, LOGL_ERROR, "'TXT' record for 'port' without previous"
									     " record\n");
						goto error;
					}

					rec_prev = (struct osmo_mdns_record *) rec->list.prev;
					if (rec_prev->type != OSMO_MDNS_RFC_RECORD_TYPE_A &&
					    rec_prev->type != OSMO_MDNS_RFC_RECORD_TYPE_AAAA) {
						LOGP(DLMSLOOKUP, LOGL_ERROR, "'TXT' record for 'port' without previous"
									     " 'A' or 'AAAA' record\n");
						goto error;
					}
					if (rec_prev->type == OSMO_MDNS_RFC_RECORD_TYPE_A)
						ret->host_v4.port = atoi(txt_value);
					else
						ret->host_v6.port = atoi(txt_value);
					found_ports++;
				} else {
					LOGP(DLMSLOOKUP, LOGL_ERROR, "unexpected key '%s' in TXT record\n", txt_key);
					goto error;
				}
				talloc_free(txt_key);
				talloc_free(txt_value);
				break;
			default:
				LOGP(DLMSLOOKUP, LOGL_ERROR, "unexpected record type\n");
				goto error;
		}
	}

	/* Check if everything was found */
	if (!found_age || (!found_ip_v4 && !found_ip_v6) || found_ports != found_ip_v4 + found_ip_v6) {
		LOGP(DLMSLOOKUP, LOGL_ERROR, "missing resource records in mDNS answer\n");
		goto error;
	}

	ret->rc = OSMO_MSLOOKUP_RC_OK;
	return ret;
error:
	talloc_free(ret); /* also frees txt_key, txt_value */
	return NULL;
}

static int request_handle_by_answer(uint32_t *request_handle, struct osmo_mdns_method_state *state,
			     struct osmo_mdns_msg_answer *ans)
{
	struct osmo_mdns_method_request *request;

	llist_for_each_entry(request, &state->requests, entry) {
		if (request->dns_req.id != ans->id)
			continue;
		if (strcmp(request->dns_req.domain, ans->domain) != 0) {
			LOGP(DLMSLOOKUP, LOGL_ERROR, "received mDNS answer with known id=%i, but different domain"
				" ('%s' instead of '%s'), ignoring\n", ans->id, request->dns_req.domain, ans->domain);
			continue;
		}

		/* Match! */
		LOGP(DLMSLOOKUP, LOGL_DEBUG, "received mDNS answer for id=%i, domain=%s\n", ans->id, ans->domain);
		*request_handle = request->request_handle;
		return 0;
	}
	return -1;
}

static int mdns_method_recv(struct osmo_fd *osmo_fd, unsigned int what)
{
	struct osmo_mdns_msg_answer *ans = NULL;
	struct osmo_mdns_method_state *state = osmo_fd->data;
	struct osmo_mslookup_result *result = NULL;
	int n;
	uint8_t buffer[1024];
	uint32_t request_handle = 0;
	void *ctx = NULL; /* FIXME */

	n = read(osmo_fd->fd, buffer, sizeof(buffer));
	if (n < 0) {
		LOGP(DLMSLOOKUP, LOGL_ERROR, "failed to read from socket\n");
		return n;
	}

	ans = osmo_mdns_msg_answer_decode(ctx, buffer, n);
	if (!ans) {
		LOGP(DLMSLOOKUP, LOGL_ERROR, "received something that is not a valid mDNS answer, ignoring\n");
		return -EINVAL;
	}

	if (request_handle_by_answer(&request_handle, state, ans) != 0)
		goto error;

	result = result_from_mdns_answer(ctx, ans);
	if (!result)
		goto error;

	osmo_mslookup_result_name_buf((char *)&buffer, sizeof(buffer), NULL, result);
	LOGP(DLMSLOOKUP, LOGL_DEBUG, "possible mDNS result for domain=%s%s\n", ans->domain, buffer);

	osmo_mslookup_client_rx_result(state->client, request_handle, result);
	talloc_free(ans);
	talloc_free(result);
	return n;

error:
	if (ans)
		talloc_free(ans);
	if (result)
		talloc_free(result);
	return -EINVAL;
}

static void mdns_method_request(struct osmo_mslookup_client_method *method, const struct osmo_mslookup_query *query,
				uint32_t request_handle)
{
	struct osmo_mdns_method_state *state = method->priv;
	struct msgb *msg = msgb_alloc(1024, __func__);
	struct osmo_mdns_method_request *r = talloc_zero(method->client, struct osmo_mdns_method_request);
	void *ctx = NULL; /* FIXME */

	*r = (struct osmo_mdns_method_request){
		.request_handle = request_handle,
		.query = *query,
	};
	llist_add(&r->entry, &state->requests);


	r->dns_req.id = state->next_packet_id;
	state->next_packet_id++;

	r->dns_req.domain = talloc_asprintf(method->client, "%s.%s.%s", query->service, query->id.imsi,
					    osmo_mslookup_id_type_name(query->id.type));
	/* Always request all records, mslookup server will reply at most with both IPv4 and IPv6. */
	r->dns_req.type = OSMO_MDNS_RFC_RECORD_TYPE_ALL;
	osmo_mdns_msg_request_encode(ctx, msg, &r->dns_req);

	/* Send over the wire */
	LOGP(DLMSLOOKUP, LOGL_DEBUG, "sending mDNS query: how to reach %s?\n", r->dns_req.domain);
	if (osmo_mdns_sock_send(state->mc, msg) == -1) {
		LOGP(DLMSLOOKUP, LOGL_ERROR, "sending mDNS query failed!\n");
		/* TODO: do we need to call the callback now? */
	}
}

static void mdns_method_request_cleanup(struct osmo_mslookup_client_method *method, uint32_t request_handle)
{
	struct osmo_mdns_method_state *state = method->priv;

	/* Tear down any state associated with this handle. */
	struct osmo_mdns_method_request *r;
	llist_for_each_entry(r, &state->requests, entry) {
		if (r->request_handle != request_handle)
			continue;
		llist_del(&r->entry);
		talloc_free(r);
		return;
	}
}

static void mdns_method_destruct(struct osmo_mslookup_client_method *method)
{
	struct osmo_mdns_method_state *state = method->priv;
	struct osmo_mdns_method_request *e, *n;
	if (!state)
		return;

	/* Drop all DNS lookup request state. Triggering a timeout event and cleanup for mslookup client users will
	 * happen in the mslookup_client.c, we will simply stop responding from this lookup method. */
	llist_for_each_entry_safe(e, n, &state->requests, entry) {
		llist_del(&e->entry);
	}

	osmo_mdns_sock_cleanup(state->mc);
}

struct osmo_mslookup_client_method *osmo_mslookup_client_add_mdns(struct osmo_mslookup_client *client, const char *ip,
								  uint16_t port, bool reuse_addr)
{
	struct osmo_mdns_method_state *state;
	struct osmo_mslookup_client_method *m;

	m = talloc_zero(client, struct osmo_mslookup_client_method);
	OSMO_ASSERT(m);

	state = talloc_zero(m, struct osmo_mdns_method_state);
	OSMO_ASSERT(state);
	INIT_LLIST_HEAD(&state->requests);
	if (osmo_sockaddr_str_from_str(&state->bind_addr, ip, port)) {
		LOGP(DLMSLOOKUP, LOGL_ERROR, "mslookup mDNS: invalid address/port: %s %u\n",
		     ip, port);
		goto error_cleanup;
	}

	state->client = client;

	state->mc = osmo_mdns_sock_init(state, ip, port, reuse_addr, mdns_method_recv, state, 0);
	if (!state->mc)
		goto error_cleanup;

	*m = (struct osmo_mslookup_client_method){
		.name = "mDNS",
		.priv = state,
		.request = mdns_method_request,
		.request_cleanup = mdns_method_request_cleanup,
		.destruct = mdns_method_destruct,
	};

	osmo_mslookup_client_method_add(client, m);
	return m;

error_cleanup:
	talloc_free(m);
	return NULL;
}

const struct osmo_sockaddr_str *osmo_mslookup_client_method_mdns_get_bind_addr(struct osmo_mslookup_client_method
									       *dns_method)
{
	struct osmo_mdns_method_state *state;
	if (!dns_method || !dns_method->priv)
		return NULL;
	state = dns_method->priv;
	return &state->bind_addr;
}
