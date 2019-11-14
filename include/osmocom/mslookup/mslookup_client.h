#pragma once

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/mslookup/mslookup.h>

struct osmo_mslookup_client;
struct osmo_mslookup_result;

typedef void (*osmo_mslookup_cb_t)(struct osmo_mslookup_client *client,
				   uint32_t request_handle,
				   const struct osmo_mslookup_query *query,
				   const struct osmo_mslookup_result *result);

/*! This part of a lookup request is not seen by the individual query method implementations. */
struct osmo_mslookup_query_handling {
	/*! Time in seconds to wait for lookup responses. If 0, an internal default timeout is used. */
	unsigned int result_timeout_milliseconds;

	/*! Invoked to return lookup results when the timeout has expired. */
	osmo_mslookup_cb_t result_cb;
};

uint32_t osmo_mslookup_client_request(struct osmo_mslookup_client *client,
				      const struct osmo_mslookup_query *query,
				      const struct osmo_mslookup_query_handling *handling);

void osmo_mslookup_client_request_cleanup(struct osmo_mslookup_client *client, uint32_t request_handle);

struct osmo_mslookup_client *osmo_mslookup_client_new(void *ctx);
bool osmo_mslookup_client_active(struct osmo_mslookup_client *client);
void osmo_mslookup_client_free(struct osmo_mslookup_client *client);

struct osmo_mslookup_client_method {
	struct llist_head entry;

	/*! Human readable name of this lookup method. */
	const char *name;

	/*! Private data for the lookup method implementation. */
	void *priv;

	/*! Backpointer to the client this method is added to. */
	struct osmo_mslookup_client *client;

	/*! Launch a lookup query. Called from osmo_mslookup_client_request().
	 * The implementation returns results by calling osmo_mslookup_client_rx_result(). */
	void (*request)(struct osmo_mslookup_client_method *method,
			const struct osmo_mslookup_query *query,
			uint32_t request_handle);
	/*! End a lookup query. Called from osmo_mslookup_client_request_cleanup(). It is guaranteed to be called
	 * exactly once per above request() invocation. (The API user is required to invoke
	 * osmo_mslookup_client_request_cleanup() exactly once per osmo_mslookup_client_request().) */
	void (*request_cleanup)(struct osmo_mslookup_client_method *method,
				uint32_t request_handle);

	/*! The mslookup_client is removing this method, clean up all open requests, lists and allocations. */
	void (*destruct)(struct osmo_mslookup_client_method *method);
};

void osmo_mslookup_client_method_add(struct osmo_mslookup_client *client,
				     struct osmo_mslookup_client_method *method);
bool osmo_mslookup_client_method_del(struct osmo_mslookup_client *client,
				     struct osmo_mslookup_client_method *method);
void osmo_mslookup_client_rx_result(struct osmo_mslookup_client *client, uint32_t request_handle,
				    const struct osmo_mslookup_result *result);
