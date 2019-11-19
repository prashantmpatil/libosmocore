/*! \file osmo-mslookup-client.c
 * Distributed GSM: find the location of subscribers, for example by multicast DNS,
 * to obtain HLR, SIP or SMPP server addresses (or arbitrary service names).
 */
/*
 * (C) 2019 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * (C) 2019 by Neels Hofmeyr <neels@hofmeyr.de>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <talloc.h>
#include <sys/un.h>

#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/mslookup/mslookup_client.h>
#include <osmocom/mslookup/mslookup_client_mdns.h>

#include "config.h"

#define CSV_HEADERS "QUERY\tRESULT\tV4_IP\tV4_PORT\tV6_IP\tV6_PORT"

static void print_version(void)
{
	printf("osmo-mslookup-client version %s\n", PACKAGE_VERSION);
	printf("\n"
	"Copyright (C) 2019 by sysmocom - s.f.m.c. GmbH\n"
	"Copyright (C) 2019 by Neels Hofmeyr <neels@hofmeyr.de>\n"
	"This program is free software; you can redistribute it and/or modify\n"
	"it under the terms of the GNU General Public License as published by\n"
	"the Free Software Foundation; either version 2 of the License, or\n"
	"(at your option) any later version.\n"
	"\n");
}

static void print_help()
{
	print_version();
	printf(
"Standalone mslookup client for Distributed GSM\n"
"\n"
"Receiving mslookup results means listening for responses on a socket. Often,\n"
"integration (e.g. FreeSwitch dialplan.py) makes it hard to select() on a socket\n"
"to read responses, because that interferes with the main program (e.g.\n"
"FreeSwitch's dialplan.py seems to be integrated with an own select() main loop\n"
"that interferes with osmo_select_main(), or an smpp.py uses\n"
"smpplib.client.listen() as main loop, etc.).\n"
"\n"
"This program provides a trivial solution, by outsourcing the mslookup main loop\n"
"to a separate process. Communication is done via stdin/stdout pipe or unix\n"
"domain socket in a simple ascii text format.\n"
"\n"
"This can be done one-shot, i.e. exit as soon as the response has been\n"
"determined, or in daemon form, i.e. continuously listen for requests and return\n"
"responses.\n"
"\n"
"Output is in CSV or json, see --format. The default is tab-separated CSV\n"
"with these columns:\n"
CSV_HEADERS "\n"
"\n"
"One-shot operation example:\n"
"$ osmo-mslookup-client gsup.hlr.1234567.imsi\n"
"gsup.hlr.1234567.imsi\tok\t1.2.3.4\t4222\taaaa:bbb:cc:d::1\t4222\n"
"$\n"
"\n"
"Daemon operation example:\n"
"$ cat requests.txt | osmo-mslookup-client -d\n"
"gsup.hlr.1234567.imsi\tok\t1.2.3.4\t4222\t\t\n"
"sip.voice.123.msisdn\tok\t\t\t555:66:7::8\t5060\n"
"smpp.sms.123.msisdn\tok\t5.6.7.8\t2775\t555:66:7::8\t2775\n"
"...\n"
"\n"
"Integrating with calling programs can be done by:\n"
"- call osmo-mslookup-client with the query string as argument.\n"
"  It will open a multicast DNS socket, send out a query and wait for the\n"
"  matching response. It will print the result on stdout and exit.\n"
"  This method launches a new process for every mslookup query,\n"
"  and creates a short-lived multicast listener for each invocation.\n"
"  This is fine for low activity, but does not scale well.\n"
"\n"
"- invoke osmo-mslookup-client --socket /tmp/mslookup -d.\n"
"  Individual queries can be sent by connecting to that unix domain socket,\n"
"  blockingly reading the response when it arrives and disconnecting.\n"
"  This way only one process keeps one multicast listener open.\n"
"  Callers can connect to this socket without spawning processes.\n"
"  This is recommended for scale.\n"
"\n"
"Python examples for both methods follow;\n"
"The first exaple decodes as json, the second decodes CSV.\n"
"\n"
"----- mslookup_pipe.py -----\n"
"import subprocess\n"
"import json\n"
"def query_mslookup(query_str):\n"
"	result_line = subprocess.check_output([\n"
"		'osmo-mslookup-client', query_str, '-f', 'json'])\n"
"	result_line = result_line.decode('ascii')\n"
"	return json.loads(result_line)\n"
"if __name__ == '__main__':\n"
"	import sys\n"
"	query_str = 'sip.voice.12345.msisdn'\n"
"	if len(sys.argv) > 1:\n"
"		query_str = sys.argv[1]\n"
"	print('Result: %%r' %% query_mslookup(query_str))\n"
"\n"
"----- mslookup_socket.py -----\n"
"import socket\n"
"MSLOOKUP_SOCKET_PATH = '/tmp/mslookup'\n"
"def query_mslookup_socket(query_str, socket_path=MSLOOKUP_SOCKET_PATH):\n"
"	mslookup_socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)\n"
"	mslookup_socket.connect(socket_path)\n"
"	mslookup_socket.sendall(query_str.encode('ascii'))\n"
"	result_csv = mslookup_socket.recv(1024).decode('ascii')\n"
"	return dict(zip(('query', 'result', 'v4_ip', 'v4_port', 'v6_ip', 'v6_port'),\n"
"			result_csv.split('\\t')))\n"
"if __name__ == '__main__':\n"
"	import sys\n"
"	print('\\nPlease run separately: osmo-mslookup-client --socket /tmp/mslookup -d\\n')\n"
"	query_str = 'sip.voice.12345.msisdn'\n"
"	if len(sys.argv) > 1:\n"
"		query_str = sys.argv[1]\n"
"	print('Result: %%r' %% query_mslookup_socket(query_str))\n"
"\n"
"\n"
"Options:\n"
"\n"
"--format -f=csv (default)\n"
"	Format result lines in CSV format. Also see --csv-headers.\n"
"--csv-headers -H\n"
"	In the first output line, output the CSV headers used for CSV output format.\n"
"\n"
"--format -f=json\n"
"	Format result lines in json instead of semicolon separated, like:\n"
"	{\"query\": \"sip.voice.12345.msisdn\", \"result\": \"ok\", \"v4\": [\"10.9.8.7\", \"5060\"]}\n"
"\n"
"--daemon -d\n"
"	Keep running after a request has been serviced\n"
"\n"
"--mdns-ip -m=" OSMO_MSLOOKUP_MDNS_IP4 " -m=" OSMO_MSLOOKUP_MDNS_IP6 "\n"
"--mdns-port -M=" OSMO_STRINGIFY_VAL(OSMO_MSLOOKUP_MDNS_PORT) "\n"
"	Set multicast IP address / port to send mDNS requests and listen for\n"
"	mDNS reponses\n"
"\n"
"--timeout -t=1000\n"
"	Set timeout in milliseconds after which to evaluate received responses.\n"
"	(A response with age of zero leads to immediate evaluation.)\n"
"\n"
"--socket -s=/path/to/unix-domain-socket\n"
"	Listen to requests from and write responses to a UNIX domain socket.\n"
"\n"
"--quiet -q\n"
"	Do not print errors to stderr, do not log to stderr.\n"
"\n"
"--help -h\n"
"	This help\n"
);
}

enum result_format {
	FORMAT_CSV = 0,
	FORMAT_JSON,
};

static struct {
	bool daemon;
	struct osmo_sockaddr_str mdns_addr;
	uint32_t timeout;
	const char *socket_path;
	const char *format_str;
	bool csv_headers;
	bool quiet;
} cmdline_opts = {
	.mdns_addr = { .af=AF_INET, .ip=OSMO_MSLOOKUP_MDNS_IP4, .port=OSMO_MSLOOKUP_MDNS_PORT },
	.timeout = 1000,
};

char buf[1024];

static struct {
	void *ctx;
	unsigned int requests_handled;
	struct osmo_fd socket_ofd;
	struct osmo_mslookup_client *mslookup_client;
	struct llist_head queries;
	struct llist_head socket_clients;
	enum result_format format;
} globals = {
	.queries = LLIST_HEAD_INIT(globals.queries),
	.socket_clients = LLIST_HEAD_INIT(globals.socket_clients),
};

#define print_error(fmt, args...) do { \
		if (!cmdline_opts.quiet) \
			fprintf(stderr, fmt, ##args); \
	} while (0)

void respond_str_stdout(const char *str) {
	fprintf(stdout, "%s\n", str);
}

void start_query_str(const char *query_str);
void start_query_strs(char **query_strs, size_t query_strs_len);

struct socket_client {
	struct llist_head entry;
	struct osmo_fd ofd;
	char query_str[1024];
};

static void socket_client_close(struct socket_client *c)
{
	struct osmo_fd *ofd = &c->ofd;

	close(ofd->fd);
	ofd->fd = -1;
	osmo_fd_unregister(ofd);

	llist_del(&c->entry);
	talloc_free(c);
}

static int socket_read_cb(struct osmo_fd *ofd)
{
	struct socket_client *c = ofd->data;
	int rc;

	rc = recv(ofd->fd, c->query_str, sizeof(c->query_str), 0);
	if (rc == 0)
		goto close;

	if (rc < 0) {
		if (errno == EAGAIN)
			return 0;
		goto close;
	}

	if (rc >= sizeof(c->query_str))
		goto close;

	c->query_str[rc] = '\0';
	start_query_str(strtok(c->query_str, "\r\n"));
	return rc;

close:
	socket_client_close(c);
	return -1;
}

static int socket_cb(struct osmo_fd *ofd, unsigned int flags)
{
	int rc = 0;

	if (flags & BSC_FD_READ)
		rc = socket_read_cb(ofd);
	if (rc < 0)
		return rc;

	return rc;
}

int socket_accept(struct osmo_fd *ofd, unsigned int flags)
{
	struct socket_client *c;
	struct sockaddr_un un_addr;
	socklen_t len;
	int rc;

	len = sizeof(un_addr);
	rc = accept(ofd->fd, (struct sockaddr*)&un_addr, &len);
	if (rc < 0) {
		print_error("Failed to accept a new connection\n");
		return -1;
	}

	c = talloc_zero(globals.ctx, struct socket_client);
	OSMO_ASSERT(c);
	c->ofd.fd = rc;
	c->ofd.when = BSC_FD_READ;
	c->ofd.cb = socket_cb;
	c->ofd.data = c;

	if (osmo_fd_register(&c->ofd) != 0) {
		print_error("Failed to register new connection fd\n");
		close(c->ofd.fd);
		c->ofd.fd = -1;
		talloc_free(c);
		return -1;
	}

	print_error("accept\n");
	llist_add(&c->entry, &globals.socket_clients);
	return 0;
}

int socket_init(const char *sock_path)
{
	struct osmo_fd *ofd = &globals.socket_ofd;
	int rc;

	ofd->fd = osmo_sock_unix_init(SOCK_SEQPACKET, 0, sock_path, OSMO_SOCK_F_BIND);
	if (ofd->fd < 0) {
		print_error("Could not create unix socket: %s: %s\n", sock_path, strerror(errno));
		return -1;
	}

	ofd->when = BSC_FD_READ;
	ofd->cb = socket_accept;

	rc = osmo_fd_register(ofd);
	if (rc < 0) {
		print_error("Could not register listen fd: %d\n", rc);
		close(ofd->fd);
		return rc;
	}
	return 0;
}

void socket_close()
{
	struct socket_client *c, *n;
	llist_for_each_entry_safe(c, n, &globals.socket_clients, entry)
		socket_client_close(c);
	if (osmo_fd_is_registered(&globals.socket_ofd)) {
		close(globals.socket_ofd.fd);
		globals.socket_ofd.fd = -1;
		osmo_fd_unregister(&globals.socket_ofd);
	}
}

void socket_client_respond_result(struct socket_client *c, const char *query_str, const char *response)
{
	if (strcmp(query_str, c->query_str))
		return;
	write(c->ofd.fd, response, strlen(response));
	socket_client_close(c);
}

struct query {
	struct llist_head entry;

	char query_str[128];
	struct osmo_mslookup_query query;
	uint32_t handle;
};

typedef void (*formatter_t)(char *buf, size_t buflen, const char *query_str, const struct osmo_mslookup_result *r);

void formatter_csv(char *buf, size_t buflen, const char *query_str, const struct osmo_mslookup_result *r)
{
	struct osmo_strbuf sb = { .buf=buf, .len=buflen };
	OSMO_STRBUF_PRINTF(sb, "%s", query_str);

	if (!r)
		OSMO_STRBUF_PRINTF(sb, "\tERROR\t\t\t\t");
	else {
		switch (r->rc) {
		case OSMO_MSLOOKUP_RC_OK:
			OSMO_STRBUF_PRINTF(sb, "\tok");
			if (osmo_sockaddr_str_is_nonzero(&r->host_v4))
				OSMO_STRBUF_PRINTF(sb, "\t%s\t%u", r->host_v4.ip, r->host_v4.port);
			else
				OSMO_STRBUF_PRINTF(sb, "\t\t");
			if (osmo_sockaddr_str_is_nonzero(&r->host_v6))
				OSMO_STRBUF_PRINTF(sb, "\t%s\t%u", r->host_v6.ip, r->host_v6.port);
			else
				OSMO_STRBUF_PRINTF(sb, "\t\t");
			break;
		default:
			OSMO_STRBUF_PRINTF(sb, "\tnot-found\t\t\t\t");
			break;
		}
	}
}

void formatter_json(char *buf, size_t buflen, const char *query_str, const struct osmo_mslookup_result *r)
{
	struct osmo_strbuf sb = { .buf=buf, .len=buflen };
	OSMO_STRBUF_PRINTF(sb, "{\"query\": \"%s\"", query_str);

	if (!r)
		OSMO_STRBUF_PRINTF(sb, ", \"result\": \"ERROR\"");
	else {
		switch (r->rc) {
		case OSMO_MSLOOKUP_RC_OK:
			OSMO_STRBUF_PRINTF(sb, ", \"result\": \"ok\"");
			if (osmo_sockaddr_str_is_nonzero(&r->host_v4))
				OSMO_STRBUF_PRINTF(sb, ", \"v4\": [\"%s\", \"%u\"]", r->host_v4.ip, r->host_v4.port);
			if (osmo_sockaddr_str_is_nonzero(&r->host_v6))
				OSMO_STRBUF_PRINTF(sb, ", \"v6\": [\"%s\", \"%u\"]", r->host_v6.ip, r->host_v6.port);
			break;
		default:
			OSMO_STRBUF_PRINTF(sb, ", \"result\": \"not-found\"");
			break;
		}
	}
	OSMO_STRBUF_PRINTF(sb, "}");
}

formatter_t formatters[] = {
	[FORMAT_CSV] = formatter_csv,
	[FORMAT_JSON] = formatter_json,
};

void respond_result(const char *query_str, const struct osmo_mslookup_result *r)
{
	struct socket_client *c, *n;
	formatters[globals.format](buf, sizeof(buf), query_str, r);
	respond_str_stdout(buf);

	llist_for_each_entry_safe(c, n, &globals.socket_clients, entry)
		socket_client_respond_result(c, query_str, buf);
	globals.requests_handled++;
}

void respond_err(const char *query_str)
{
	respond_result(query_str, NULL);
}

struct query *query_by_handle(uint32_t request_handle)
{
	struct query *q;
	llist_for_each_entry(q, &globals.queries, entry) {
		if (request_handle == q->handle)
			return q;
	}
	return NULL;
}

void mslookup_result_cb(struct osmo_mslookup_client *client,
			uint32_t request_handle,
			const struct osmo_mslookup_query *query,
			const struct osmo_mslookup_result *result)
{
	struct query *q = query_by_handle(request_handle);
	if (!q)
		return;
	respond_result(q->query_str, result);
	llist_del(&q->entry);
	talloc_free(q);
}

void start_query_str(const char *query_str)
{
	struct query *q;
	struct osmo_mslookup_query_handling h = {
		.result_timeout_milliseconds = cmdline_opts.timeout,
		.result_cb = mslookup_result_cb,
	};

	if (strlen(query_str) >= sizeof(q->query_str)) {
		print_error("ERROR: query string is too long: '%s'\n", query_str);
		respond_err(query_str);
		return;
	}

	q = talloc_zero(globals.ctx, struct query);
	OSMO_ASSERT(q);
	OSMO_STRLCPY_ARRAY(q->query_str, query_str);

	if (osmo_mslookup_query_from_domain_str(&q->query, q->query_str)) {
		print_error("ERROR: cannot parse query string: '%s'\n", query_str);
		respond_err(query_str);
		talloc_free(q);
		return;
	}

	q->handle = osmo_mslookup_client_request(globals.mslookup_client, &q->query, &h);
	if (!q->handle) {
		print_error("ERROR: cannot send query: '%s'\n", query_str);
		respond_err(query_str);
		talloc_free(q);
		return;
	}

	llist_add(&q->entry, &globals.queries);
}

void start_query_strs(char **query_strs, size_t query_strs_len)
{
	int i;
	for (i = 0; i < query_strs_len; i++)
		start_query_str(query_strs[i]);
}

int main(int argc, char **argv)
{
	int rc = EXIT_FAILURE;
	globals.ctx = talloc_named_const(NULL, 0, "osmo-mslookup-client");

	osmo_init_logging2(globals.ctx, NULL);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_level(osmo_stderr_target, 1);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_print_category_hex(osmo_stderr_target, 0);
	log_set_print_extended_timestamp(osmo_stderr_target, 1);
	log_set_use_color(osmo_stderr_target, 0);

	while (1) {
		int c;
		long long int val;
		char *endptr;
		int option_index = 0;

		static struct option long_options[] = {
			{ "format", 1, 0, 'f' },
			{ "csv-headers", 0, 0, 'H' },
			{ "daemon", 0, 0, 'd' },
			{ "mdns-ip", 1, 0, 'm' },
			{ "mdns-port", 1, 0, 'M' },
			{ "timeout", 1, 0, 't' },
			{ "socket", 1, 0, 's' },
			{ "quiet", 0, 0, 'q' },
			{ "help", 0, 0, 'h' },
			{ "version", 0, 0, 'V' },
			{}
		};

		c = getopt_long(argc, argv, "f:Hdm:M:t:s:qhV", long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'f':
			cmdline_opts.format_str = optarg;
			break;
		case 'H':
			cmdline_opts.csv_headers = true;
			break;
		case 'd':
			cmdline_opts.daemon = true;
			break;
		case 'm':
			if (osmo_sockaddr_str_from_str(&cmdline_opts.mdns_addr, optarg, cmdline_opts.mdns_addr.port)
			    || !osmo_sockaddr_str_is_nonzero(&cmdline_opts.mdns_addr)) {
				print_error("Invalid mDNS IP address: %s\n", optarg);
				goto program_exit;
			}
			break;
		case 'M':
			errno = 0;
			val = strtoll(optarg, &endptr, 10);
			if (errno || val < 1 || val > 65535 || *endptr) {
				print_error("Invalid mDNS UDP port: %s\n", optarg);
				goto program_exit;
			}
			cmdline_opts.mdns_addr.port = val;
			break;
		case 't':
			errno = 0;
			val = strtoll(optarg, &endptr, 10);
			if (errno || val < 1 || val > UINT32_MAX || *endptr) {
				print_error("Invalid timeout: %s\n", optarg);
				goto program_exit;
			}
			cmdline_opts.timeout = val;
			break;
		case 's':
			cmdline_opts.socket_path = optarg;
			break;
		case 'q':
			cmdline_opts.quiet = true;
			break;

		case 'h':
			print_help();
			rc = 0;
			goto program_exit;
		case 'V':
			print_version();
			rc = 0;
			goto program_exit;

		default:
			/* catch unknown options *as well as* missing arguments. */
			print_error("Error in command line options. Exiting.\n");
			goto program_exit;
		}
	}

	if (!cmdline_opts.daemon && !(argc - optind)) {
		print_help();
		goto program_exit;
	}

	if (cmdline_opts.quiet)
		log_target_destroy(osmo_stderr_target);

	if (cmdline_opts.format_str) {
		if (osmo_str_startswith("json", cmdline_opts.format_str))
			globals.format = FORMAT_JSON;
		else if (osmo_str_startswith("csv", cmdline_opts.format_str))
			globals.format = FORMAT_CSV;
		else {
			print_error("Invalid format: %s\n", cmdline_opts.format_str);
			goto program_exit;
		}
	}

	if (globals.format == FORMAT_CSV && cmdline_opts.csv_headers)
		respond_str_stdout(CSV_HEADERS);

	globals.mslookup_client = osmo_mslookup_client_new(globals.ctx);
	if (!globals.mslookup_client
	    || !osmo_mslookup_client_add_mdns(globals.mslookup_client,
					      cmdline_opts.mdns_addr.ip, cmdline_opts.mdns_addr.port,
					      true, -1)) {
		print_error("Failed to start mDNS client\n");
		goto program_exit;
	}

	if (cmdline_opts.socket_path) {
		if (socket_init(cmdline_opts.socket_path))
			goto program_exit;
	}

	start_query_strs(&argv[optind], argc - optind);

	while (1) {
		osmo_select_main_ctx(0);

		if (!cmdline_opts.daemon
		    && globals.requests_handled
		    && llist_empty(&globals.queries))
			break;
	}

	rc = 0;
program_exit:
	osmo_mslookup_client_free(globals.mslookup_client);
	socket_close();
	log_fini();
	talloc_free(globals.ctx);
	return rc;
}
