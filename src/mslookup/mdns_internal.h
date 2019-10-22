#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/endian.h>
#include <osmocom/mslookup/mdns.h>

/* RFC 1035 2.3.4 */
#define OSMO_MSLOOKUP_MDNS_MAX_NAME_LEN 255

/* RFC 1035 4.1.1 */
struct osmo_mdns_section_header {
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
struct osmo_mdns_section_question {
	char *domain; /* Domain to be encoded as qname (e.g. "hlr.1234567.imsi") */
	enum osmo_mdns_record_type qtype;
	enum osmo_mdns_class qclass;
};

/* RFC 1035 4.1.3 */
struct osmo_mdns_resource_record {
	char *domain; /* Domain to be encoded as name (e.g. "hlr.1234567.imsi") */
	enum osmo_mdns_record_type type;
	enum osmo_mdns_class class;
	uint32_t ttl;
	uint16_t rdlength;
	uint8_t *rdata;
};

char *osmo_mdns_encode_qname(void *ctx, const char *domain);
char *osmo_mdns_decode_qname(void *ctx, const char *qname, size_t qname_len);

void osmo_mdns_encode_section_header(struct msgb *msg, const struct osmo_mdns_section_header *hdr);
int osmo_mdns_decode_section_header(const uint8_t *data, size_t data_len, struct osmo_mdns_section_header *hdr);
int osmo_mdns_encode_section_question(void *ctx, struct msgb *msg, const struct osmo_mdns_section_question *qst);
struct osmo_mdns_section_question *osmo_mdns_decode_section_question(void *ctx, const uint8_t *data, size_t data_len);

int osmo_mdns_encode_resource_record(void *ctx, struct msgb *msg, const struct osmo_mdns_resource_record *rec);
struct osmo_mdns_resource_record *osmo_mdns_decode_resource_record(void *ctx, const uint8_t *data, size_t data_len,
							     size_t *record_len);
