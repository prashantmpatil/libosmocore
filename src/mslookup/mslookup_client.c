#include <osmocom/core/logging.h>
#include <osmocom/mslookup/mslookup_client.h>

/*! Lookup client's internal data for a query. */
struct osmo_mslookup_client {
	struct llist_head lookup_methods;
	struct llist_head requests;
	uint32_t next_request_handle;
};

/*! Lookup client's internal data for a query.
 * The request methods only get to see the query part, and result handling is done commonly for all request methods. */
struct osmo_mslookup_client_request {
	struct llist_head entry;
	struct osmo_mslookup_client *client;
	uint32_t request_handle;

	struct osmo_mslookup_query query;
	struct osmo_mslookup_query_handling handling;
	struct osmo_timer_list timeout;

	struct osmo_mslookup_result result;
};

static struct osmo_mslookup_client_request *get_request(struct osmo_mslookup_client *client, uint32_t request_handle)
{
	struct osmo_mslookup_client_request *r;
	if (!request_handle)
		return NULL;
	llist_for_each_entry(r, &client->requests, entry) {
		if (r->request_handle == request_handle)
			return r;
	}
	return NULL;
}

struct osmo_mslookup_client *osmo_mslookup_client_new(void *ctx)
{
	struct osmo_mslookup_client *client = talloc_zero(ctx, struct osmo_mslookup_client);
	OSMO_ASSERT(client);
	INIT_LLIST_HEAD(&client->lookup_methods);
	INIT_LLIST_HEAD(&client->requests);
	return client;
}

/*! Return whether any lookup methods are available.
 * \param[in] client  Client to query.
 * \return true when a client is present that has at least one osmo_mslookup_client_method registered.
 */
bool osmo_mslookup_client_active(struct osmo_mslookup_client *client)
{
	if (!client)
		return false;
	if (llist_empty(&client->lookup_methods))
		return false;
	return true;
}

static void _osmo_mslookup_client_method_del(struct osmo_mslookup_client_method *method)
{
	if (method->destruct)
		method->destruct(method);
	llist_del(&method->entry);
	talloc_free(method);
}

/*! Stop and free mslookup client and all registered lookup methods.
 */
void osmo_mslookup_client_free(struct osmo_mslookup_client *client)
{
	struct osmo_mslookup_client_method *m, *n;
	if (!client)
		return;
	llist_for_each_entry_safe(m, n, &client->lookup_methods, entry) {
		_osmo_mslookup_client_method_del(m);
	}
}

/*! Add an osmo_mslookup_client_method to service MS Lookup requests.
 * Note, osmo_mslookup_client_method_del() will talloc_free() the method pointer, so it needs to be dynamically
 * allocated.
 * \param client  The osmo_mslookup_client instance to add to.
 * \param method  A fully initialized method struct, allocated by talloc.
 */
void osmo_mslookup_client_method_add(struct osmo_mslookup_client *client,
				     struct osmo_mslookup_client_method *method)
{
	method->client = client;
	llist_add_tail(&method->entry, &client->lookup_methods);
}

/*! \return false if the method was not listed, true if the method was listed, removed and talloc_free()d.
 */
bool osmo_mslookup_client_method_del(struct osmo_mslookup_client *client,
				     struct osmo_mslookup_client_method *method)
{
	struct osmo_mslookup_client_method *m;
	llist_for_each_entry(m, &client->lookup_methods, entry) {
		if (m == method) {
			_osmo_mslookup_client_method_del(method);
			return true;
		}
	}
	return false;
}

static void osmo_mslookup_request_finish(struct osmo_mslookup_client_request *r)
{
	struct osmo_mslookup_client *client = r->client;
	uint32_t request_handle = r->request_handle;

	if (r->result.rc == OSMO_MSLOOKUP_RC_TIMEOUT) {
		/* Timeout cb has been fired before, don't call again. */
		return;
	}
	if (r->result.rc == OSMO_MSLOOKUP_RC_NONE) {
		/* No response has come in, and we hit a timeout. Send a timeout rc. */
		r->result = (struct osmo_mslookup_result){ .rc = OSMO_MSLOOKUP_RC_TIMEOUT };
	}
	r->handling.result_cb(r->client, r->request_handle, &r->query, &r->result);

	/* Make sure the request struct is discarded.
	 * The result_cb() may already have triggered a cleanup, so query by request_handle. */
	osmo_mslookup_client_request_cleanup(client, request_handle);
}

void osmo_mslookup_client_rx_result(struct osmo_mslookup_client *client, uint32_t request_handle,
				    const struct osmo_mslookup_result *result)
{
	struct osmo_mslookup_client_request *req = get_request(client, request_handle);

	if (!req) {
		LOGP(DLMSLOOKUP, LOGL_ERROR,
		     "Internal error: Got mslookup result for a request that does not exist (handle %u)\n",
		     req->request_handle);
		return;
	}

	if (result->rc == OSMO_MSLOOKUP_RC_NONE)
		return;

	/* Store best result */
	switch (req->result.rc) {
	case OSMO_MSLOOKUP_RC_TIMEOUT:
		/* The timer has already timed out, this reply is too late. Ignore. */
		return;

	case OSMO_MSLOOKUP_RC_NONE:
		/* There is no result yet, store whatever came in. */
		req->result = *result;
		break;

	case OSMO_MSLOOKUP_RC_OK:
		/* A previous successful result is already stored. Overwrite only when the incoming result is successful
		 * and younger. */
		if (result->rc == OSMO_MSLOOKUP_RC_OK
		    && req->result.age > result->age)
			req->result = *result;
		break;
	default:
		/* store the youngest error */
		if (req->result.age > result->age)
			req->result = *result;
		break;
	}

	/* If age == 0, it doesn't get any better, so return the result immediately. */
	if (req->result.rc == OSMO_MSLOOKUP_RC_OK
	    && req->result.age == 0) {
		osmo_mslookup_request_finish(req);
	}
}

static void timeout_cb(void *data)
{
	struct osmo_mslookup_client_request *r = data;
	osmo_mslookup_request_finish(r);
}

/*! Launch a subscriber lookup with the provided query.
 * A request is cleared implicitly when the handling->result_cb is invoked; if the quer->priv pointer becomes invalid
 * before that, a request should be canceled by calling osmo_mslookup_client_request_cleanup() with the returned
 * request_handle. A request handle of zero indicates error.
 * \return a nonzero request_handle that allows ending the request, or 0 on invalid query data. */
uint32_t osmo_mslookup_client_request(struct osmo_mslookup_client *client,
				      const struct osmo_mslookup_query *query,
				      const struct osmo_mslookup_query_handling *handling)
{
	struct osmo_mslookup_client_request *r;
	struct osmo_mslookup_client_request *other;
	struct osmo_mslookup_client_method *m;

	if (!osmo_mslookup_service_valid(query->service)
	    || !osmo_mslookup_id_valid(&query->id)) {
		char buf[128];
		LOGP(DLMSLOOKUP, LOGL_ERROR, "Invalid query: %s\n",
		     osmo_mslookup_result_name_b(buf, sizeof(buf), query, NULL));
		return 0;
	}
	
	r = talloc_zero(client, struct osmo_mslookup_client_request);
	OSMO_ASSERT(r);

	/* A request_handle of zero means error, so make sure we don't use a zero handle. */
	if (!client->next_request_handle)
		client->next_request_handle++;
	*r = (struct osmo_mslookup_client_request){
		.client = client,
		.query = *query,
		.handling = *handling,
		.request_handle = client->next_request_handle++,
	};

	/* Paranoia: make sure a request_handle exists only once, by expiring an already existing one. This is unlikely
	 * to happen in practice: before we get near wrapping a uint32_t range, previous requests should long have
	 * timed out or ended. */
	llist_for_each_entry(other, &client->requests, entry) {
		if (other->request_handle != r->request_handle)
			continue;
		osmo_mslookup_request_finish(other);
		/* we're sure it exists only once. */
		break;
	}

	/* Now sure that the new request_handle does not exist a second time. */
	llist_add_tail(&r->entry, &client->requests);

	osmo_timer_setup(&r->timeout, timeout_cb, r);
	osmo_timer_schedule(&r->timeout,
			    handling->result_timeout_milliseconds / 1000,
			    (handling->result_timeout_milliseconds % 1000) * 1000);

	/* Let the lookup implementations know */
	llist_for_each_entry(m, &client->lookup_methods, entry) {
		m->request(m, query, r->request_handle);
	}
	return r->request_handle;
}

static void _osmo_mslookup_client_request_cleanup(struct osmo_mslookup_client_request *r)
{
	struct osmo_mslookup_client_method *m;
	osmo_timer_del(&r->timeout);
	llist_for_each_entry(m, &r->client->lookup_methods, entry) {
		if (!m->request_cleanup)
			continue;
		m->request_cleanup(m, r->request_handle);
	}
	llist_del(&r->entry);
	talloc_free(r);
}

/*! End or cancel a subscriber lookup. This *must* be invoked exactly once per osmo_mslookup_client_request() invocation,
 * either after a lookup has concluded or to abort an ongoing lookup.
 * \param[in] request_handle  The request_handle returned by an osmo_mslookup_client_request() invocation.
 */
void osmo_mslookup_client_request_cleanup(struct osmo_mslookup_client *client, uint32_t request_handle)
{
	struct osmo_mslookup_client_request *r = get_request(client, request_handle);
	if (!r)
		return;
	_osmo_mslookup_client_request_cleanup(r);
}
