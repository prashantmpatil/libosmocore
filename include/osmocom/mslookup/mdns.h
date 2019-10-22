#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>

/*! Only listing record types that we actually use for now. */
enum osmo_mdns_record_type {
	OSMO_MSLOOKUP_MDNS_RECORD_TYPE_UNKNOWN = 0,

	/* RFC 1035 3.2.2 */
	OSMO_MSLOOKUP_MDNS_RECORD_TYPE_A = 1, /* IPv4 address */
	OSMO_MSLOOKUP_MDNS_RECORD_TYPE_TXT = 16, /* Text strings */

	/* RFC 3596 2.1 */
	OSMO_MSLOOKUP_MDNS_RECORD_TYPE_AAAA = 28, /* IPv6 address */

	/* RFC 1035 3.2.3 */
	OSMO_MSLOOKUP_MDNS_RECORD_TYPE_ALL = 255, /* Request only: ask for all */
};

enum osmo_mdns_class {
	OSMO_MSLOOKUP_MDNS_CLASS_UNKNOWN = 0,

	/* RFC 1035 3.2.4 */
	OSMO_MSLOOKUP_MDNS_CLASS_IN = 1, /* Internet and IP networks */

	/* RFC 1035 3.2.5 */
	OSMO_MSLOOKUP_MDNS_CLASS_ALL = 255, /* Request only: ask for all */
};

struct osmo_mdns_request {
	uint16_t id;
	char *domain;
	enum osmo_mdns_record_type type;
};

struct osmo_mdns_record {
	struct llist_head list;
	enum osmo_mdns_record_type type;
	uint16_t length;
	uint8_t *data;
};

struct osmo_mdns_answer {
	uint16_t id;
	char *domain;
	struct llist_head records;
};

void osmo_mdns_answer_init(struct osmo_mdns_answer *answer);

int osmo_mdns_encode_request(void *ctx, struct msgb *msg, const struct osmo_mdns_request *req);
struct osmo_mdns_request *osmo_mdns_decode_request(void *ctx, const uint8_t *data, size_t data_len);

int osmo_mdns_encode_answer(void *ctx, struct msgb *msg, const struct osmo_mdns_answer *ans);
struct osmo_mdns_answer *osmo_mdns_decode_answer(void *ctx, const uint8_t *data, size_t data_len);

struct osmo_mdns_record *osmo_mdns_encode_txt_record(void *ctx, const char *key, const char *value_fmt, ...);
int osmo_mdns_decode_txt_record(void *ctx, const struct osmo_mdns_record *rec, char **key, char **value);
