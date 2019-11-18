#include "../../src/mslookup/mdns_rfc.h"
#include "../../src/mslookup/mdns_record.h"
#include "../../src/mslookup/mdns_msg.h"
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>

struct qname_enc_dec_test {
	const char *domain;
	const char *qname;
	size_t qname_max_len; /* default: strlen(qname) + 1 */
};

static const struct qname_enc_dec_test qname_enc_dec_test_data[] = {
	{
		/* OK: typical mslookup domain */
		.domain = "hlr.1234567.imsi",
		.qname = "\x03" "hlr" "\x07" "1234567" "\x04" "imsi",
	},
	{
		/* Wrong format: double dot */
		.domain = "hlr..imsi",
		.qname = NULL,
	},
	{
		/* Wrong format: double dot */
		.domain = "hlr",
		.qname = "\x03hlr\0\x03imsi",
	},
	{
		/* Wrong format: dot at end */
		.domain = "hlr.",
		.qname = NULL,
	},
	{
		/* Wrong format: dot at start */
		.domain = ".hlr",
		.qname = NULL,
	},
	{
		/* Wrong format: empty */
		.domain = "",
		.qname = NULL,
	},
	{
		/* OK: maximum length */
		.domain =
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"12345"
			,
		.qname =
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\x05" "12345"
	},
	{
		/* Error: too long domain */
		.domain =
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"123456789." "123456789." "123456789." "123456789." "123456789."
			"12345toolong"
			,
		.qname = NULL,
	},
	{
		/* Error: too long qname */
		.domain = NULL,
		.qname =
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
			"\t123456789\t123456789\t123456789\t123456789\t123456789"
	},
	{
		/* Error: wrong token length in qname */
		.domain = NULL,
		.qname = "\x03" "hlr" "\x07" "1234567" "\x05" "imsi",
	},
	{
		/* Error: wrong token length in qname */
		.domain = NULL,
		.qname = "\x02" "hlr" "\x07" "1234567" "\x04" "imsi",
	},
	{
		/* Wrong format: token length at end of qname */
		.domain = NULL,
		.qname = "\x03hlr\x03",
	},
	{
		/* Error: overflow in label length */
		.domain = NULL,
		.qname = "\x03" "hlr" "\x07" "1234567" "\x04" "imsi",
		.qname_max_len = 17,
	},
};

void test_enc_dec_rfc_qname(void *ctx)
{
	char quote_buf[300];
	int i;

	printf("-- %s --\n", __func__);

	for (i = 0; i < ARRAY_SIZE(qname_enc_dec_test_data); i++) {
		const struct qname_enc_dec_test *t = &qname_enc_dec_test_data[i];
		char *res;

		if (t->domain) {
			printf("domain: %s\n", osmo_quote_str_buf2(quote_buf, sizeof(quote_buf), t->domain, -1));
			printf("exp: %s\n", osmo_quote_str_buf2(quote_buf, sizeof(quote_buf), t->qname, -1));
			res = osmo_mdns_rfc_qname_encode(ctx, t->domain);
			printf("res: %s\n", osmo_quote_str_buf2(quote_buf, sizeof(quote_buf), res, -1));
			if (t->qname == res || (t->qname && res && strcmp(t->qname, res) == 0))
				printf("=> OK\n");
			else
				printf("=> ERROR\n");
			if (res)
				talloc_free(res);
			printf("\n");
		}

		if (t->qname) {
			size_t qname_max_len = t->qname_max_len;
			if (qname_max_len)
				printf("qname_max_len: %lu\n", qname_max_len);
			else
				qname_max_len = strlen(t->qname) + 1;

			printf("qname: %s\n", osmo_quote_str_buf2(quote_buf, sizeof(quote_buf), t->qname, -1));
			printf("exp: %s\n", osmo_quote_str_buf2(quote_buf, sizeof(quote_buf), t->domain, -1));
			res = osmo_mdns_rfc_qname_decode(ctx, t->qname, qname_max_len);
			printf("res: %s\n", osmo_quote_str_buf2(quote_buf, sizeof(quote_buf), res, -1));
			if (t->domain == res || (t->domain && res && strcmp(t->domain, res) == 0))
				printf("=> OK\n");
			else
				printf("=> ERROR\n");
			if (res)
				talloc_free(res);
			printf("\n");
		}
	}
}

#define PRINT_HDR(hdr, name) \
	printf("header %s:\n" \
	       ".id = %i\n" \
	       ".qr = %i\n" \
	       ".opcode = %x\n" \
	       ".aa = %i\n" \
	       ".tc = %i\n" \
	       ".rd = %i\n" \
	       ".ra = %i\n" \
	       ".z = %x\n" \
	       ".rcode = %x\n" \
	       ".qdcount = %u\n" \
	       ".ancount = %u\n" \
	       ".nscount = %u\n" \
	       ".arcount = %u\n", \
	       name, hdr.id, hdr.qr, hdr.opcode, hdr.aa, hdr.tc, hdr.rd, hdr.ra, hdr.z, hdr.rcode, hdr.qdcount, \
	       hdr.ancount, hdr.nscount, hdr.arcount)

static const struct osmo_mdns_rfc_header header_enc_dec_test_data[] = {
	{
		/* Typical use case for mslookup */
		.id = 1337,
		.qdcount = 1,
	},
	{
		/* Fill out everything */
		.id = 42,
		.qr = 1,
		.opcode = 0x02,
		.aa = 1,
		.tc = 1,
		.rd = 1,
		.ra = 1,
		.z  = 0x02,
		.rcode = 0x03,
		.qdcount = 1234,
		.ancount = 1111,
		.nscount = 2222,
		.arcount = 3333,
	},
};

void test_enc_dec_rfc_header()
{
	int i;

	printf("-- %s --\n", __func__);
	for (i = 0; i< ARRAY_SIZE(header_enc_dec_test_data); i++) {
		const struct osmo_mdns_rfc_header in = header_enc_dec_test_data[i];
		struct osmo_mdns_rfc_header out = {0};
		struct msgb *msg = msgb_alloc(4096, "dns_test");

		PRINT_HDR(in, "in");
		osmo_mdns_rfc_header_encode(msg, &in);
		printf("encoded: %s\n", osmo_hexdump(msgb_data(msg), msgb_length(msg)));
		assert(osmo_mdns_rfc_header_decode(msgb_data(msg), msgb_length(msg), &out) == 0);
		PRINT_HDR(out, "out");

		printf("in (hexdump):  %s\n", osmo_hexdump((unsigned char *)&in, sizeof(in)));
		printf("out (hexdump): %s\n", osmo_hexdump((unsigned char *)&out, sizeof(out)));
		assert(memcmp(&in, &out, sizeof(in)) == 0);

		printf("=> OK\n\n");
		msgb_free(msg);
	}
}

void test_enc_dec_rfc_header_einval()
{
	struct osmo_mdns_rfc_header out = {0};
	struct msgb *msg = msgb_alloc(4096, "dns_test");
	printf("-- %s --\n", __func__);

	assert(osmo_mdns_rfc_header_decode(msgb_data(msg), 11, &out) == -EINVAL);
	printf("=> OK\n\n");

	msgb_free(msg);
}

#define PRINT_QST(qst, name) \
	printf("question %s:\n" \
	       ".domain = %s\n" \
	       ".qtype = %i\n" \
	       ".qclass = %i\n", \
	       name, (qst)->domain, (qst)->qtype, (qst)->qclass)

static const struct osmo_mdns_rfc_question question_enc_dec_test_data[] = {
	{
		.domain = "hlr.1234567.imsi",
		.qtype = OSMO_MDNS_RFC_RECORD_TYPE_ALL,
		.qclass = OSMO_MDNS_RFC_CLASS_IN,
	},
	{
		.domain = "hlr.1234567.imsi",
		.qtype = OSMO_MDNS_RFC_RECORD_TYPE_A,
		.qclass = OSMO_MDNS_RFC_CLASS_ALL,
	},
	{
		.domain = "hlr.1234567.imsi",
		.qtype = OSMO_MDNS_RFC_RECORD_TYPE_AAAA,
		.qclass = OSMO_MDNS_RFC_CLASS_ALL,
	},
};

void test_enc_dec_rfc_question(void *ctx)
{
	int i;

	printf("-- %s --\n", __func__);
	for (i = 0; i< ARRAY_SIZE(question_enc_dec_test_data); i++) {
		const struct osmo_mdns_rfc_question in = question_enc_dec_test_data[i];
		struct osmo_mdns_rfc_question *out;
		struct msgb *msg = msgb_alloc(4096, "dns_test");

		PRINT_QST(&in, "in");
		assert(osmo_mdns_rfc_question_encode(ctx, msg, &in) == 0);
		printf("encoded: %s\n", osmo_hexdump(msgb_data(msg), msgb_length(msg)));
		out = osmo_mdns_rfc_question_decode(ctx, msgb_data(msg), msgb_length(msg));
		assert(out);
		PRINT_QST(out, "out");

		if (strcmp(in.domain, out->domain) != 0)
			printf("=> ERROR: domain does not match\n");
		else if (in.qtype != out->qtype)
			printf("=> ERROR: qtype does not match\n");
		else if (in.qclass != out->qclass)
			printf("=> ERROR: qclass does not match\n");
		else
			printf("=> OK\n");

		printf("\n");
		msgb_free(msg);
		talloc_free(out);
	}
}

void test_enc_dec_rfc_question_null(void *ctx)
{
	uint8_t data[5] = {0};

	printf("-- %s --\n", __func__);
	assert(osmo_mdns_rfc_question_decode(ctx, data, sizeof(data)) == NULL);
	printf("=> OK\n\n");
}

#define PRINT_REC(rec, name) \
	printf("question %s:\n" \
	       ".domain = %s\n" \
	       ".type = %i\n" \
	       ".class = %i\n" \
	       ".ttl = %i\n" \
	       ".rdlength = %i\n" \
	       ".rdata = %s\n", \
	       name, (rec)->domain, (rec)->type, (rec)->class, (rec)->ttl, (rec)->rdlength, \
	       osmo_quote_str((char *)(rec)->rdata, (rec)->rdlength))

static const struct osmo_mdns_rfc_record record_enc_dec_test_data[] = {
	{
		.domain = "hlr.1234567.imsi",
		.type = OSMO_MDNS_RFC_RECORD_TYPE_A,
		.class = OSMO_MDNS_RFC_CLASS_IN,
		.ttl = 1234,
		.rdlength = 9,
		.rdata = (uint8_t *)"10.42.2.1",
	},
};

void test_enc_dec_rfc_record(void *ctx)
{
	int i;

	printf("-- %s --\n", __func__);
	for (i=0; i< ARRAY_SIZE(record_enc_dec_test_data); i++) {
		const struct osmo_mdns_rfc_record in = record_enc_dec_test_data[i];
		struct osmo_mdns_rfc_record *out;
		struct msgb *msg = msgb_alloc(4096, "dns_test");
		size_t record_len;

		PRINT_REC(&in, "in");
		assert(osmo_mdns_rfc_record_encode(ctx, msg, &in) == 0);
		printf("encoded: %s\n", osmo_hexdump(msgb_data(msg), msgb_length(msg)));
		out = osmo_mdns_rfc_record_decode(ctx, msgb_data(msg), msgb_length(msg), &record_len);
		printf("record_len: %lu\n", record_len);
		assert(out);
		PRINT_REC(out, "out");

		if (strcmp(in.domain, out->domain) != 0)
			printf("=> ERROR: domain does not match\n");
		else if (in.type != out->type)
			printf("=> ERROR: type does not match\n");
		else if (in.class != out->class)
			printf("=> ERROR: class does not match\n");
		else if (in.ttl != out->ttl)
			printf("=> ERROR: ttl does not match\n");
		else if (in.rdlength != out->rdlength)
			printf("=> ERROR: rdlength does not match\n");
		else if (memcmp(in.rdata, out->rdata, in.rdlength) != 0)
			printf("=> ERROR: rdata does not match\n");
		else
			printf("=> OK\n");

		printf("\n");
		msgb_free(msg);
		talloc_free(out);
	}
}

int main()
{
	void *ctx = talloc_named_const(NULL, 0, "main");
	osmo_init_logging2(ctx, NULL);

	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);

	test_enc_dec_rfc_qname(ctx);
	test_enc_dec_rfc_header();
	test_enc_dec_rfc_header_einval();
	test_enc_dec_rfc_question(ctx);
	test_enc_dec_rfc_question_null(ctx);
	test_enc_dec_rfc_record(ctx);

	return 0;
}
