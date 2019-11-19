#pragma once

#include <osmocom/core/utils.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>

#define OSMO_MSLOOKUP_SERVICE_MAXLEN 64

/*! Request HLR for the home HLR's GSUP connection. */
#define OSMO_MSLOOKUP_SERVICE_HLR_GSUP "gsup.hlr"

/*! Request SIP for a voice call (osmo-sip-connector or PBX). */
#define OSMO_MSLOOKUP_SERVICE_SIP "sip.voice"

/*! Request SMPP to deliver an SMS (osmo-msc or SMPP handler). */
#define OSMO_MSLOOKUP_SERVICE_SMPP "smpp.sms"

/*! Request GSUP to deliver an SMS (osmo-hlr or ESME). */
#define OSMO_MSLOOKUP_SERVICE_SMS_GSUP "gsup.sms"

bool osmo_mslookup_service_valid(const char *service);

enum osmo_mslookup_id_type {
	OSMO_MSLOOKUP_ID_NONE = 0,
	OSMO_MSLOOKUP_ID_IMSI,
	OSMO_MSLOOKUP_ID_MSISDN,
};

extern const struct value_string osmo_mslookup_id_type_names[];
static inline const char *osmo_mslookup_id_type_name(enum osmo_mslookup_id_type val)
{ return get_value_string(osmo_mslookup_id_type_names, val); }

struct osmo_mslookup_id {
	enum osmo_mslookup_id_type type;
	union {
		char imsi[GSM23003_IMSI_MAX_DIGITS+1];
		char msisdn[GSM23003_MSISDN_MAX_DIGITS+1];
	};
};

int osmo_mslookup_id_cmp(const struct osmo_mslookup_id *a, const struct osmo_mslookup_id *b);
bool osmo_mslookup_id_valid(const struct osmo_mslookup_id *id);

enum osmo_mslookup_result_code {
	OSMO_MSLOOKUP_RC_NONE = 0,
	OSMO_MSLOOKUP_RC_OK,
	OSMO_MSLOOKUP_RC_TIMEOUT,
	OSMO_MSLOOKUP_RC_CANCELED,
	OSMO_MSLOOKUP_RC_NOT_FOUND,
	OSMO_MSLOOKUP_RC_DECODE_ERROR,
};

/*! Information to request from a lookup. */
struct osmo_mslookup_query {
	/*! Which service to request: HLR, SMS or voice. Typically an OSMO_MSLOOKUP_SERVICE_* constant, but could be an
	 * arbitrary string that service providers understand. */
	char service[OSMO_MSLOOKUP_SERVICE_MAXLEN + 1];
	/*! IMSI or MSISDN to look up. */
	struct osmo_mslookup_id id;

	/*! Caller provided private data, if desired. */
	void *priv;
};

/*! Result data as passed back to a lookup client that invoked an osmo_mslookup_client_request. */
struct osmo_mslookup_result {
	/*! Outcome of the request. */
	enum osmo_mslookup_result_code rc;

	/*! IP address and port to reach the given service via IPv4, if any. */
	struct osmo_sockaddr_str host_v4;

	/*! IP address and port to reach the given service via IPv6, if any. */
	struct osmo_sockaddr_str host_v6;

	/*! How long ago the service last verified presence of the subscriber, in seconds, or zero if the presence is
	 * invariable (like the home HLR record for an IMSI).
	 * If a subscriber has recently moved to a different location, we get multiple replies and want to choose the
	 * most recent one. If this were a timestamp, firstly the time zones would need to be taken care of.
	 * Even if we choose UTC, a service provider with an inaccurate date/time would end up affecting the result.
	 * The least susceptible to configuration errors or difference in local and remote clock is a value that
	 * indicates the actual age of the record in seconds. The time that the lookup query took to be answered should
	 * be neglectable here, since we would typically wait one second (or very few seconds) for lookup replies,
	 * while typical Location Updating periods are in the range of 15 minutes. */
	uint32_t age;
};

int osmo_mslookup_query_from_domain_str(struct osmo_mslookup_query *q, const char *domain);

size_t osmo_mslookup_id_name_buf(char *buf, size_t buflen, const struct osmo_mslookup_id *id);
char *osmo_mslookup_id_name_c(void *ctx, const struct osmo_mslookup_id *id);
char *osmo_mslookup_id_name_b(char *buf, size_t buflen, const struct osmo_mslookup_id *id);

size_t osmo_mslookup_result_name_buf(char *buf, size_t buflen,
				     const struct osmo_mslookup_query *query,
				     const struct osmo_mslookup_result *result);
char *osmo_mslookup_result_name_c(void *ctx,
				  const struct osmo_mslookup_query *query,
				  const struct osmo_mslookup_result *result);
char *osmo_mslookup_result_name_b(char *buf, size_t buflen,
				  const struct osmo_mslookup_query *query,
				  const struct osmo_mslookup_result *result);
