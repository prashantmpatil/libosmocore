#pragma once
#include <osmocom/core/msgb.h>

struct osmo_mdns_sock {
	struct osmo_fd osmo_fd;
	struct addrinfo *ai;
};

struct osmo_mdns_sock *osmo_mdns_sock_init(void *ctx, const char *ip, unsigned int port, bool reuse_addr,
						   int (*cb)(struct osmo_fd *fd, unsigned int what),
						   void *data, unsigned int priv_nr);
int osmo_mdns_sock_send(const struct osmo_mdns_sock *mdns_sock, struct msgb *msg);
void osmo_mdns_sock_cleanup(struct osmo_mdns_sock *mdns_sock);
