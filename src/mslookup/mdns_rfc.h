/*! \file mdns_rfc.h */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/endian.h>
#include <osmocom/mslookup/mdns.h>

/* RFC 1035 2.3.4 */
#define OSMO_MDNS_RFC_MAX_NAME_LEN 255

enum osmo_mdns_rfc_record_type {
	OSMO_MDNS_RFC_RECORD_TYPE_UNKNOWN = 0,

	/* RFC 1035 3.2.2 */
	OSMO_MDNS_RFC_RECORD_TYPE_A = 1, /* IPv4 address */
	OSMO_MDNS_RFC_RECORD_TYPE_TXT = 16, /* Text strings */

	/* RFC 3596 2.1 */
	OSMO_MDNS_RFC_RECORD_TYPE_AAAA = 28, /* IPv6 address */

	/* RFC 1035 3.2.3 */
	OSMO_MDNS_RFC_RECORD_TYPE_ALL = 255, /* Request only: ask for all */
};

enum osmo_mdns_rfc_class {
	OSMO_MDNS_RFC_CLASS_UNKNOWN = 0,

	/* RFC 1035 3.2.4 */
	OSMO_MDNS_RFC_CLASS_IN = 1, /* Internet and IP networks */

	/* RFC 1035 3.2.5 */
	OSMO_MDNS_RFC_CLASS_ALL = 255, /* Request only: ask for all */
};

/* RFC 1035 4.1.1 */
struct osmo_mdns_rfc_header {
#if OSMO_IS_LITTLE_ENDIAN
	uint16_t id;
	uint8_t rd:1,
		tc:1,
		aa:1,
		opcode:4,
		qr:1; /* QR (0: query, 1: response) */
	uint8_t rcode:4,
		z:3,
		ra:1;
	uint16_t qdcount; /* Number of questions */
	uint16_t ancount; /* Number of answers */
	uint16_t nscount; /* Number of authority records */
	uint16_t arcount; /* Number of additional records */
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	uint16_t id;
	uint8_t qr:1, opcode:4, aa:1, tc:1, rd:1;
	uint8_t ra:1, z:3, rcode:4;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
#endif
} __attribute__ ((packed));

/* RFC 1035 4.1.2 */
struct osmo_mdns_rfc_question {
	char *domain; /* Domain to be encoded as qname (e.g. "hlr.1234567.imsi") */
	enum osmo_mdns_rfc_record_type qtype;
	enum osmo_mdns_rfc_class qclass;
};

/* RFC 1035 4.1.3 */
struct osmo_mdns_rfc_record {
	char *domain; /* Domain to be encoded as name (e.g. "hlr.1234567.imsi") */
	enum osmo_mdns_rfc_record_type type;
	enum osmo_mdns_rfc_class class;
	uint32_t ttl;
	uint16_t rdlength;
	uint8_t *rdata;
};

char *osmo_mdns_rfc_qname_encode(void *ctx, const char *domain);
char *osmo_mdns_rfc_qname_decode(void *ctx, const char *qname, size_t qname_len);

void osmo_mdns_rfc_header_encode(struct msgb *msg, const struct osmo_mdns_rfc_header *hdr);
int osmo_mdns_rfc_header_decode(const uint8_t *data, size_t data_len, struct osmo_mdns_rfc_header *hdr);

int osmo_mdns_rfc_question_encode(void *ctx, struct msgb *msg, const struct osmo_mdns_rfc_question *qst);
struct osmo_mdns_rfc_question *osmo_mdns_rfc_question_decode(void *ctx, const uint8_t *data, size_t data_len);

int osmo_mdns_rfc_record_encode(void *ctx, struct msgb *msg, const struct osmo_mdns_rfc_record *rec);
struct osmo_mdns_rfc_record *osmo_mdns_rfc_record_decode(void *ctx, const uint8_t *data, size_t data_len,
							 size_t *record_len);
