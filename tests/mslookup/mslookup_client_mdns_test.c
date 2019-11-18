#include "../../src/mslookup/mdns_msg.h"
#include "../../src/mslookup/mdns_record.h" /* FIXME: use new mdns.h api instead */
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/select.h>
#include <osmocom/core/application.h>
#include <osmocom/mslookup/mslookup.h>
#include <osmocom/mslookup/mslookup_client.h>
#include <osmocom/mslookup/mslookup_client_mdns.h>
#include <osmocom/mslookup/mdns.h>
#include <osmocom/mslookup/mdns_sock.h>

void *ctx = NULL;

#define TEST_IP OSMO_MSLOOKUP_MDNS_IP4
#define TEST_PORT OSMO_MSLOOKUP_MDNS_PORT

int result_from_answer(struct osmo_mslookup_result *result, struct osmo_mdns_msg_answer *ans);

static uint8_t ip_v4_n[] = {0x2a, 0x2a, 0x2a, 0x2a};
static uint8_t ip_v6_n[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
			    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};

/*
 * Test server (emulates the mDNS server in OsmoHLR) and client
 */
struct osmo_mdns_sock *server_mc;


/* FIXME: use osmo_mdns_result_encode() */
static void server_reply(struct osmo_mdns_msg_request *req)
{
	int rc;
	struct msgb *msg;
	struct osmo_mdns_msg_answer ans = {0};
	struct osmo_mdns_record *rec_age;
	struct osmo_mdns_record rec_ip_v4 = {0};
	struct osmo_mdns_record *rec_ip_v4_port;
	struct osmo_mdns_record rec_ip_v6 = {0};
	struct osmo_mdns_record *rec_ip_v6_port;

	ans.id = req->id;
	ans.domain = req->domain;
	INIT_LLIST_HEAD(&ans.records);

	rec_age = osmo_mdns_record_txt_encode(ctx, "age", "3");
	OSMO_ASSERT(rec_age);
	llist_add_tail(&rec_age->list, &ans.records);

	rec_ip_v4.type = OSMO_MDNS_RFC_RECORD_TYPE_A;
	rec_ip_v4.data = ip_v4_n;
	rec_ip_v4.length = sizeof(ip_v4_n);
	llist_add_tail(&rec_ip_v4.list, &ans.records);

	rec_ip_v4_port = osmo_mdns_record_txt_encode(ctx, "port", "444");
	OSMO_ASSERT(rec_ip_v4_port);
	llist_add_tail(&rec_ip_v4_port->list, &ans.records);

	rec_ip_v6.type = OSMO_MDNS_RFC_RECORD_TYPE_AAAA;
	rec_ip_v6.data = ip_v6_n;
	rec_ip_v6.length = sizeof(ip_v6_n);
	llist_add_tail(&rec_ip_v6.list, &ans.records);

	rec_ip_v6_port = osmo_mdns_record_txt_encode(ctx, "port", "666");
	OSMO_ASSERT(rec_ip_v6_port);
	llist_add_tail(&rec_ip_v6_port->list, &ans.records);

	msg = msgb_alloc(1024, __func__);
	rc = osmo_mdns_msg_answer_encode(ctx, msg, &ans);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(osmo_mdns_sock_send(server_mc, msg) == 0);
}

static int server_recv(struct osmo_fd *osmo_fd, unsigned int what)
{
	struct osmo_mdns_msg_request *req;
	int n;
	uint8_t buffer[1024];

	fprintf(stderr, "%s\n", __func__);

	/* Parse the message and print it */
	n = read(osmo_fd->fd, buffer, sizeof(buffer));
	OSMO_ASSERT(n >= 0);

	req = osmo_mdns_msg_request_decode(ctx, buffer, n);
	if (!req) {
		fprintf(stderr, "received something that is not a valid DNS request, ignoring\n");
		fprintf(stderr, "(server and client listen on same IP and port in this test, so this was probably the"
				" server's own answer, this is expected)\n");
		return -1;
	}
	fprintf(stderr, "received request for: %s\n", req->domain);
	server_reply(req);
	talloc_free(req);
	return n;
}

static void server_init()
{
	fprintf(stderr, "%s\n", __func__);
	server_mc = osmo_mdns_sock_init(ctx, TEST_IP, TEST_PORT, true, server_recv, NULL, 0);
	OSMO_ASSERT(server_mc);
}

static void server_stop()
{
	fprintf(stderr, "%s\n", __func__);
	osmo_mdns_sock_cleanup(server_mc);
}

struct osmo_mslookup_client* client;
struct osmo_mslookup_client_method* client_method;

static void client_init()
{
	fprintf(stderr, "%s\n", __func__);
	client = osmo_mslookup_client_new(ctx);
	OSMO_ASSERT(client);
	client_method = osmo_mslookup_client_add_mdns(client, TEST_IP, TEST_PORT, true);
	OSMO_ASSERT(client_method);
}

static void client_recv(struct osmo_mslookup_client *client, uint32_t request_handle,
			const struct osmo_mslookup_query *query, const struct osmo_mslookup_result *result)
{
	fprintf(stderr, "%s\n", __func__);
	fprintf(stderr, "client_recv(): %s\n", osmo_mslookup_result_name_c(ctx, query, result));

	osmo_mslookup_client_request_cleanup(client, request_handle);
}

static void client_query()
{
	struct osmo_mslookup_id id = {.type = OSMO_MSLOOKUP_ID_IMSI,
				      .imsi = "123456789012345"};
	const struct osmo_mslookup_query query = {
		.service = OSMO_MSLOOKUP_SERVICE_HLR_GSUP,
		.id = id,
	};
	struct osmo_mslookup_query_handling handling = {
		.result_timeout_milliseconds = 2000,
		.result_cb = client_recv,
	};

	fprintf(stderr, "%s\n", __func__);
	osmo_mslookup_client_request(client, &query, &handling);
}

static void client_stop()
{
	fprintf(stderr, "%s\n", __func__);
}
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
static void test_server_client()
{
	fprintf(stderr, "-- %s --\n", __func__);
	server_init();
	client_init();
	client_query();

	/* Let the server receive the query and indirectly call server_recv(). As side effect of using the same IP and
	 * port, the client will also receive its own question. The client will dismiss its own question, as it is just
	 * looking for answers. */
	OSMO_ASSERT(osmo_select_main_ctx(1) == 1);

	/* Let the mslookup client receive the answer (also same side effect as above). It does not call the callback
         * (client_recv()) just yet, because it is waiting for the best result within two seconds. */
	OSMO_ASSERT(osmo_select_main_ctx(1) == 1);

	/* Time flies by, client_recv() gets called. */
	fake_time_passes(5, 0);

	server_stop();
	client_stop();
}

/*
 * Decoding test for result_from_answer()
 */
enum test_records {
	RECORD_NONE,
	RECORD_A,
	RECORD_AAAA,
	RECORD_TXT_AGE,
	RECORD_TXT_PORT_444,
	RECORD_TXT_PORT_666,
	RECORD_TXT_INVALID_KEY,
	RECORD_TXT_INVALID_NO_KEY_VALUE,
	RECORD_INVALID,
};
struct result_from_answer_test {
	const char *desc;
	const enum test_records records[5];
	bool error;
	const struct osmo_mslookup_result res;
};

static void test_result_from_answer()
{
	struct osmo_sockaddr_str test_host_v4 = {.af = AF_INET, .port=444, .ip = "42.42.42.42"};
	struct osmo_sockaddr_str test_host_v6 = {.af = AF_INET6, .port=666,
						 .ip = "1122:3344:5566:7788:99aa:bbcc:ddee:ff00"};
	struct osmo_mslookup_result test_result_v4 = {.rc = OSMO_MSLOOKUP_RC_OK, .age = 3,
						      .host_v4 = test_host_v4};
	struct osmo_mslookup_result test_result_v6 = {.rc = OSMO_MSLOOKUP_RC_OK, .age = 3,
						      .host_v6 = test_host_v6};
	struct osmo_mslookup_result test_result_v4_v6 = {.rc = OSMO_MSLOOKUP_RC_OK, .age = 3,
							 .host_v4 = test_host_v4, .host_v6 = test_host_v6};
	struct result_from_answer_test result_from_answer_data[] = {
		{
			.desc = "IPv4",
			.records = {RECORD_TXT_AGE, RECORD_A, RECORD_TXT_PORT_444},
			.res = test_result_v4
		},
		{
			.desc = "IPv6",
			.records = {RECORD_TXT_AGE, RECORD_AAAA, RECORD_TXT_PORT_666},
			.res = test_result_v6
		},
		{
			.desc = "IPv4 + IPv6",
			.records = {RECORD_TXT_AGE, RECORD_A, RECORD_TXT_PORT_444, RECORD_AAAA, RECORD_TXT_PORT_666},
			.res = test_result_v4_v6
		},
		{
			.desc = "A twice",
			.records = {RECORD_TXT_AGE, RECORD_A, RECORD_TXT_PORT_444, RECORD_A},
			.error = true
		},
		{
			.desc = "AAAA twice",
			.records = {RECORD_TXT_AGE, RECORD_AAAA, RECORD_TXT_PORT_444, RECORD_AAAA},
			.error = true
		},
		{
			.desc = "invalid TXT: no key/value pair",
			.records = {RECORD_TXT_AGE, RECORD_AAAA, RECORD_TXT_INVALID_NO_KEY_VALUE},
			.error = true
		},
		{
			.desc = "age twice",
			.records = {RECORD_TXT_AGE, RECORD_TXT_AGE},
			.error = true
		},
		{
			.desc = "port as first record",
			.records = {RECORD_TXT_PORT_444},
			.error = true
		},
		{
			.desc = "port without previous ip record",
			.records = {RECORD_TXT_AGE, RECORD_TXT_PORT_444},
			.error = true
		},
		{
			.desc = "invalid TXT: invalid key",
			.records = {RECORD_TXT_AGE, RECORD_AAAA, RECORD_TXT_INVALID_KEY},
			.error = true
		},
		{
			.desc = "unexpected record type",
			.records = {RECORD_TXT_AGE, RECORD_INVALID},
			.error = true
		},
		{
			.desc = "missing record: age",
			.records = {RECORD_A, RECORD_TXT_PORT_444},
			.error = true
		},
		{
			.desc = "missing record: port for ipv4",
			.records = {RECORD_TXT_AGE, RECORD_A},
			.error = true
		},
		{
			.desc = "missing record: port for ipv4 #2",
			.records = {RECORD_TXT_AGE, RECORD_AAAA, RECORD_TXT_PORT_666, RECORD_A},
			.error = true
		},
	};
	int i = 0;
	int j = 0;

	fprintf(stderr, "-- %s --\n", __func__);
	for (i = 0; i < ARRAY_SIZE(result_from_answer_data); i++) {
		struct result_from_answer_test *t = &result_from_answer_data[i];
		struct osmo_mdns_msg_answer ans = {0};
		struct osmo_mslookup_result res = {0};
		void *ctx_test = talloc_named_const(ctx, 0, t->desc);
		bool is_error;

		fprintf(stderr, "---\n");
		fprintf(stderr, "test: %s\n", t->desc);
		fprintf(stderr, "error: %s\n", t->error ? "true" : "false");
		fprintf(stderr, "records:\n");
		/* Build records list */
		INIT_LLIST_HEAD(&ans.records);
		for (j = 0; j < ARRAY_SIZE(t->records); j++) {
			struct osmo_mdns_record *rec = NULL;

			switch (t->records[j]) {
				case RECORD_NONE:
					break;
				case RECORD_A:
					fprintf(stderr, "- A 42.42.42.42\n");
					rec = talloc_zero(ctx_test, struct osmo_mdns_record);
					rec->type = OSMO_MDNS_RFC_RECORD_TYPE_A;
					rec->data = ip_v4_n;
					rec->length = sizeof(ip_v4_n);
					break;
				case RECORD_AAAA:
					fprintf(stderr, "- AAAA 1122:3344:5566:7788:99aa:bbcc:ddee:ff00\n");
					rec = talloc_zero(ctx_test, struct osmo_mdns_record);
					rec->type = OSMO_MDNS_RFC_RECORD_TYPE_AAAA;
					rec->data = ip_v6_n;
					rec->length = sizeof(ip_v6_n);
					break;
				case RECORD_TXT_AGE:
					fprintf(stderr, "- TXT age=3\n");
					rec = osmo_mdns_record_txt_encode(ctx_test, "age", "3");
					break;
				case RECORD_TXT_PORT_444:
					fprintf(stderr, "- TXT port=444\n");
					rec = osmo_mdns_record_txt_encode(ctx_test, "port", "444");
					break;
				case RECORD_TXT_PORT_666:
					fprintf(stderr, "- TXT port=666\n");
					rec = osmo_mdns_record_txt_encode(ctx_test, "port", "666");
					break;
				case RECORD_TXT_INVALID_KEY:
					fprintf(stderr, "- TXT hello=world\n");
					rec = osmo_mdns_record_txt_encode(ctx_test, "hello", "world");
					break;
				case RECORD_TXT_INVALID_NO_KEY_VALUE:
					fprintf(stderr, "- TXT 12345\n");
					rec = osmo_mdns_record_txt_encode(ctx_test, "12", "45");
					rec->data[3] = '3';
					break;
				case RECORD_INVALID:
					fprintf(stderr, "- (invalid)\n");
					rec = talloc_zero(ctx, struct osmo_mdns_record);
					rec->type = OSMO_MDNS_RFC_RECORD_TYPE_UNKNOWN;
					break;
			}

			if (rec)
				llist_add_tail(&rec->list, &ans.records);
		}

		/* Verify output */
		is_error = (result_from_answer(&res, &ans) != 0);
		OSMO_ASSERT(t->error == is_error);
		if (!t->error) {
			fprintf(stderr, "exp: %s\n", osmo_hexdump((unsigned char *)&t->res, sizeof(t->res)));
			fprintf(stderr, "res: %s\n", osmo_hexdump((unsigned char *)&res, sizeof(t->res)));
			OSMO_ASSERT(memcmp(&res, &t->res, sizeof(t->res)) == 0);
		}

		talloc_free(ctx_test);
		printf("=> OK\n");
	}
}

/*
 * Run all tests
 */
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

	test_server_client();
	test_result_from_answer();

	return 0;
}
