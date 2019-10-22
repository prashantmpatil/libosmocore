#include <string.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/select.h>
#include <osmocom/core/application.h>
#include <osmocom/mslookup/mslookup_client.h>
#include <osmocom/mslookup/mslookup_client_fake.h>

void *ctx = NULL;

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

const struct timeval fake_time_start_time = { 0, 0 };

#define fake_time_passes(secs, usecs) do \
{ \
	struct timeval diff; \
	osmo_gettimeofday_override_add(secs, usecs); \
	osmo_clock_override_add(CLOCK_MONOTONIC, secs, usecs * 1000); \
	timersub(&osmo_gettimeofday_override_time, &fake_time_start_time, &diff); \
	LOGP(DLMSLOOKUP, LOGL_DEBUG, "Total time passed: %d.%06d s\n", \
	       (int)diff.tv_sec, (int)diff.tv_usec); \
	osmo_timers_prepare(); \
	osmo_timers_update(); \
} while (0)

static void fake_time_start()
{
	struct timespec *clock_override;

	osmo_gettimeofday_override_time = fake_time_start_time;
	osmo_gettimeofday_override = true;
	clock_override = osmo_clock_override_gettimespec(CLOCK_MONOTONIC);
	OSMO_ASSERT(clock_override);
	clock_override->tv_sec = fake_time_start_time.tv_sec;
	clock_override->tv_nsec = fake_time_start_time.tv_usec * 1000;
	osmo_clock_override_enable(CLOCK_MONOTONIC, true);
	fake_time_passes(0, 0);
}

static void result_cb_once(struct osmo_mslookup_client *client,
			   uint32_t request_handle,
			   const struct osmo_mslookup_query *query,
			   const struct osmo_mslookup_result *result)
{
	LOGP(DLMSLOOKUP, LOGL_DEBUG, "result_cb(): %s\n", osmo_mslookup_result_name_c(ctx, query, result));

	osmo_mslookup_client_request_cleanup(client, request_handle);
}

int main()
{
	ctx = talloc_named_const(NULL, 0, "main");
	osmo_init_logging2(ctx, NULL);

	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_level(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 0);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_category_filter(osmo_stderr_target, DLMSLOOKUP, true, LOGL_DEBUG);

	fake_time_start();

	struct osmo_mslookup_client *client = osmo_mslookup_client_new(ctx);
	osmo_mslookup_client_add_fake(client, fake_lookup_responses, ARRAY_SIZE(fake_lookup_responses));

	/* Place some requests to be replied upon asynchronously */

	struct osmo_mslookup_query_handling handling = {
		.result_timeout_milliseconds = 2000,
		.result_cb = result_cb_once,
	};

	struct osmo_mslookup_query q1 = {
		.service = OSMO_MSLOOKUP_SERVICE_HLR_GSUP,
		.id = {
			.type = OSMO_MSLOOKUP_ID_IMSI,
			.imsi = "1234567",
		},
	};
	OSMO_ASSERT(osmo_mslookup_client_request(client, &q1, &handling));

	struct osmo_mslookup_query q2 = {
		.service = OSMO_MSLOOKUP_SERVICE_SIP,
		.id = {
			.type = OSMO_MSLOOKUP_ID_MSISDN,
			.msisdn = "112",
		},
	};
	handling.result_timeout_milliseconds = 3000;
	OSMO_ASSERT(osmo_mslookup_client_request(client, &q2, &handling));

	struct osmo_mslookup_query q3 = {
		.service = OSMO_MSLOOKUP_SERVICE_SMPP,
		.id = {
			.type = OSMO_MSLOOKUP_ID_MSISDN,
			.msisdn = "00000",
		},
	};
	handling.result_timeout_milliseconds = 5000;
	OSMO_ASSERT(osmo_mslookup_client_request(client, &q3, &handling));

	struct osmo_mslookup_query q4 = {
		.service = OSMO_MSLOOKUP_SERVICE_HLR_GSUP,
		.id = {
			.type = OSMO_MSLOOKUP_ID_MSISDN,
			.msisdn = "666",
		},
	};
	handling.result_timeout_milliseconds = 10000;
	uint32_t q4_handle;
	OSMO_ASSERT((q4_handle = osmo_mslookup_client_request(client, &q4, &handling)));

	while (osmo_gettimeofday_override_time.tv_sec < 6) {
		log_reset_context();
		fake_time_passes(0, 1e6 / 5);
	}

	osmo_mslookup_client_request_cleanup(client, q4_handle);

	return 0;
}
