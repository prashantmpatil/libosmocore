#pragma once

#include <stdint.h>

/*! MS Lookup mDNS server bind default IP. Taken from the Administratevly Scoped block, particularly the Organizational
 * Scoped range, https://tools.ietf.org/html/rfc2365 . */
#define OSMO_MSLOOKUP_MDNS_IP4 "239.192.23.42"
#define OSMO_MSLOOKUP_MDNS_IP6 "ff08::23:42" // <-- TODO: sane?
#define OSMO_MSLOOKUP_MDNS_PORT 4266

struct osmo_mslookup_client_method *osmo_mslookup_client_add_mdns(struct osmo_mslookup_client *client, const char *ip,
								  uint16_t port, bool reuse_addr);

const struct osmo_sockaddr_str *osmo_mslookup_client_method_mdns_get_bind_addr(struct osmo_mslookup_client_method *dns_method);
