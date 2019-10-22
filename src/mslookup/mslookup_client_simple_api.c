/* Calling the standard osmo_mslookup_client API from Python is hard, because each struct datatype needs to be
 * re-written in python (when using ctypes). One alternative is using SWIG to generate Python API.
 * Another alternative is this API that wraps all arguments and return values in primitive data types. */

#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/mslookup/mslookup_client.h>
#include <osmocom/mslookup/mslookup_client_fake.h>
#include <osmocom/mslookup/mslookup_client_mdns.h>

static void *ctx = NULL;
static struct osmo_mslookup_client *g_client = NULL;

bool osmo_mslookup_s_init()
{
	if (ctx && g_client)
		return true;
	if (ctx || g_client)
		return false;

	ctx = talloc_named_const(NULL, 0, "osmo_mslookup_s");
	g_client = osmo_mslookup_client_new(ctx);
	return true;
}

bool osmo_mslookup_s_init_logging()
{
	if (!osmo_mslookup_s_init())
		return false;
	osmo_init_logging2(g_client, NULL);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_extended_timestamp(osmo_stderr_target, 1);
	log_set_use_color(osmo_stderr_target, 0);
	return true;
}

void osmo_mslookup_s_set_logging(bool enabled, unsigned int level)
{
	log_set_category_filter(osmo_stderr_target, DLMSLOOKUP, enabled, level);
}

bool osmo_mslookup_s_init_dns()
{
	/* FIXME: pass as arguments? also we need to change it to ip_listen, ip_server, see comment in
	 * mslookup_client_dns.c */
	const char *ip = "127.0.0.1";
	uint16_t port = 12345;

	if (!osmo_mslookup_s_init())
		return false;
	osmo_mslookup_client_add_mdns(g_client, ip, port, false);
	return true;
}

bool osmo_mslookup_s_init_fake()
{
	static struct osmo_mslookup_fake_response fake_lookup_responses[] = {
		{
			.time_to_reply = { .tv_sec = 1, },
			.for_id = {
				.type = OSMO_MSLOOKUP_ID_IMSI,
				.imsi = "1234567",
			},
			.for_service = OSMO_MSLOOKUP_SERVICE_HLR_GSUP,
			.result = {
				.rc = OSMO_MSLOOKUP_RC_OK,
				.host_v4 = {
					.af = AF_INET,
					.ip = "12.34.56.7",
					.port = 42,
				},
				.host_v6 = {
					.af = AF_INET6,
					.ip = "be:ef:ed:ca:fe:fa:ce::1",
					.port = 42,
				},
				.age = 0,
			},
		},
		{
			.time_to_reply = { .tv_usec = 600 * 1000, },
			.for_id = {
				.type = OSMO_MSLOOKUP_ID_MSISDN,
				.msisdn = "112",
			},
			.for_service = OSMO_MSLOOKUP_SERVICE_SIP,
			.result = {
				.rc = OSMO_MSLOOKUP_RC_OK,
				.host_v4 = {
					.af = AF_INET,
					.ip = "66.66.66.66",
					.port = 666,
				},
				.host_v6 = {
					.af = AF_INET,
					.ip = "6666:6666:6666::6",
					.port = 666,
				},
				.age = 423,
			},
		},
		{
			.time_to_reply = { .tv_usec = 800 * 1000, },
			.for_id = {
				.type = OSMO_MSLOOKUP_ID_MSISDN,
				.msisdn = "112",
			},
			.for_service = OSMO_MSLOOKUP_SERVICE_SIP,
			.result = {
				.rc = OSMO_MSLOOKUP_RC_OK,
				.host_v4 = {
					.af = AF_INET,
					.ip = "112.112.112.112",
					.port = 23,
				},
				.age = 235,
			},
		},
		{
			.time_to_reply = { .tv_sec = 1, .tv_usec = 200 * 1000, },
			.for_id = {
				.type = OSMO_MSLOOKUP_ID_MSISDN,
				.msisdn = "112",
			},
			.for_service = OSMO_MSLOOKUP_SERVICE_SIP,
			.result = {
				.rc = OSMO_MSLOOKUP_RC_OK,
				.host_v4 = {
					.af = AF_INET,
					.ip = "99.99.99.99",
					.port = 999,
				},
				.host_v6 = {
					.af = AF_INET,
					.ip = "9999:9999:9999::9",
					.port = 999,
				},
				.age = 335,
			},
		},
		{
			.time_to_reply = { .tv_sec = 1, .tv_usec = 500 * 1000, },
			.for_id = {
				.type = OSMO_MSLOOKUP_ID_MSISDN,
				.msisdn = "112",
			},
			.for_service = OSMO_MSLOOKUP_SERVICE_SIP,
			.result = {
				.rc = OSMO_MSLOOKUP_RC_OK,
				.host_v4 = {
					.af = AF_INET,
					.ip = "99.99.99.99",
					.port = 999,
				},
				.age = 999,
			},
		},
	};

	if (!osmo_mslookup_s_init())
		return false;
	osmo_mslookup_client_add_fake(g_client, fake_lookup_responses, ARRAY_SIZE(fake_lookup_responses));
	return true;
}

typedef void (*osmo_mslookup_s_callback_t)(uint32_t handle,
					   const char *v4_ip, uint16_t v4_port,
					   const char *v6_ip, uint16_t v6_port,
					   unsigned int age);

void osmo_mslookup_s_result(struct osmo_mslookup_client *client,
			    uint32_t request_handle,
			    const struct osmo_mslookup_query *query,
			    const struct osmo_mslookup_result *result)
{
	char buf[128];
	LOGP(DLMSLOOKUP, LOGL_DEBUG, "Result: %s\n", osmo_mslookup_result_name_b(buf, sizeof(buf), query, result));
	osmo_mslookup_s_callback_t result_cb = query->priv;
	if (result_cb)
		result_cb(request_handle,
			  result->host_v4.ip, result->host_v4.port,
			  result->host_v6.ip, result->host_v6.port,
			  result->age);
	osmo_mslookup_client_request_cleanup(client, request_handle);
}

uint32_t osmo_mslookup_s_request(const char *id_type, const char *id, const char *service,
				 int timeout_milliseconds, osmo_mslookup_s_callback_t result_cb)
{
	char buf[128];
	uint32_t handle;
	struct osmo_mslookup_query q = {
		.id = {
			.type = get_string_value(osmo_mslookup_id_type_names, id_type),
		},
		.priv = result_cb,
	};
	OSMO_STRLCPY_ARRAY(q.service, service);
	switch (q.id.type) {
	case OSMO_MSLOOKUP_ID_IMSI:
		OSMO_STRLCPY_ARRAY(q.id.imsi, id);
		break;
	case OSMO_MSLOOKUP_ID_MSISDN:
		OSMO_STRLCPY_ARRAY(q.id.msisdn, id);
		break;
	default:
		LOGP(DLMSLOOKUP, LOGL_ERROR, "Invalid ID type: %s\n", id_type);
		return 0;
	}
	struct osmo_mslookup_query_handling h = {
		.result_timeout_milliseconds = timeout_milliseconds,
		.result_cb = osmo_mslookup_s_result,
	};

	handle = osmo_mslookup_client_request(g_client, &q, &h);
	if (handle)
		LOGP(DLMSLOOKUP, LOGL_DEBUG, "Request handle=%u: %s\n", handle,
		     osmo_mslookup_result_name_b(buf, sizeof(buf), &q, NULL));
	else
		LOGP(DLMSLOOKUP, LOGL_ERROR, "Request failed: %s\n",
		     osmo_mslookup_result_name_b(buf, sizeof(buf), &q, NULL));
	return handle;
}

void osmo_mslookup_s_request_cleanup(uint32_t request_handle)
{
	osmo_mslookup_client_request_cleanup(g_client, request_handle);
}
