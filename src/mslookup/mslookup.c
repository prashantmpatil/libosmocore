#include <string.h>
#include <errno.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/mslookup/mslookup.h>

#define CMP(a,b) (a < b? -1 : (a > b? 1 : 0))

const struct value_string osmo_mslookup_id_type_names[] = {
	{ OSMO_MSLOOKUP_ID_NONE, "none" },
	{ OSMO_MSLOOKUP_ID_IMSI, "imsi" },
	{ OSMO_MSLOOKUP_ID_MSISDN, "msisdn" },
	{}
};


int osmo_mslookup_id_cmp(const struct osmo_mslookup_id *a, const struct osmo_mslookup_id *b)
{
	int cmp;
	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;

	cmp = CMP(a->type, b->type);
	if (cmp)
		return cmp;

	switch (a->type) {
	case OSMO_MSLOOKUP_ID_IMSI:
		return strncmp(a->imsi, b->imsi, sizeof(a->imsi));
	case OSMO_MSLOOKUP_ID_MSISDN:
		return strncmp(a->msisdn, b->msisdn, sizeof(a->msisdn));
	default:
		return 0;
	}
}

bool osmo_mslookup_id_valid(const struct osmo_mslookup_id *id)
{
	switch (id->type) {
	case OSMO_MSLOOKUP_ID_IMSI:
		return osmo_imsi_str_valid(id->imsi);
	case OSMO_MSLOOKUP_ID_MSISDN:
		return osmo_msisdn_str_valid(id->msisdn);
	default:
		return false;
	}
}

bool osmo_mslookup_service_valid(const char *service)
{
	return strlen(service) > 0;
}

size_t osmo_mslookup_id_name_buf(char *buf, size_t buflen, const struct osmo_mslookup_id *id)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	switch (id->type) {
	case OSMO_MSLOOKUP_ID_IMSI:
		OSMO_STRBUF_PRINTF(sb, "%s", id->imsi);
		break;
	case OSMO_MSLOOKUP_ID_MSISDN:
		OSMO_STRBUF_PRINTF(sb, "%s", id->msisdn);
		break;
	default:
		OSMO_STRBUF_PRINTF(sb, "?");
		break;
	}
	OSMO_STRBUF_PRINTF(sb, ".%s", osmo_mslookup_id_type_name(id->type));
	return sb.chars_needed;
}

/*! Same as osmo_mslookup_id_name_buf(), but return a talloc allocated string of sufficient size. */
char *osmo_mslookup_id_name_c(void *ctx, const struct osmo_mslookup_id *id)
{
	OSMO_NAME_C_IMPL(ctx, 64, "ERROR", osmo_mslookup_id_name_buf, id)
}

/*! Same as osmo_mslookup_id_name_buf(), but directly return the char* (for printf-like string formats). */
char *osmo_mslookup_id_name_b(char *buf, size_t buflen, const struct osmo_mslookup_id *id)
{
	int rc = osmo_mslookup_id_name_buf(buf, buflen, id);
	if (rc < 0 && buflen)
		buf[0] = '\0';
	return buf;
}

size_t osmo_mslookup_result_name_buf(char *buf, size_t buflen,
				     const struct osmo_mslookup_query *query,
				     const struct osmo_mslookup_result *result)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	if (query) {
		OSMO_STRBUF_PRINTF(sb, "%s.", query->service);
		OSMO_STRBUF_APPEND(sb, osmo_mslookup_id_name_buf, &query->id);
	}
	if (result && result->rc == OSMO_MSLOOKUP_RC_NONE && result->rc == OSMO_MSLOOKUP_RC_NONE)
		result = NULL;
	if (result) {
		switch (result->rc) {
		case OSMO_MSLOOKUP_RC_NONE:
			break;
		case OSMO_MSLOOKUP_RC_OK:
			if (result->host_v4.ip[0]) {
				OSMO_STRBUF_PRINTF(sb, " -> ipv4: " OSMO_SOCKADDR_STR_FMT,
						   OSMO_SOCKADDR_STR_FMT_ARGS(&result->host_v4));
			}
			if (result->host_v6.ip[0]) {
				OSMO_STRBUF_PRINTF(sb, " -> ipv6: " OSMO_SOCKADDR_STR_FMT,
						   OSMO_SOCKADDR_STR_FMT_ARGS(&result->host_v6));
			}
			OSMO_STRBUF_PRINTF(sb, " (age=%u)", result->age);
			break;
		case OSMO_MSLOOKUP_RC_TIMEOUT:
			OSMO_STRBUF_PRINTF(sb, " -> timeout");
			break;
		default:
			OSMO_STRBUF_PRINTF(sb, " -> rc=%d", result->rc);
			break;
		}
	}
	return sb.chars_needed;
}

/*! Same as osmo_mslookup_result_name_buf(), but return a talloc allocated string of sufficient size. */
char *osmo_mslookup_result_name_c(void *ctx,
				  const struct osmo_mslookup_query *query,
				  const struct osmo_mslookup_result *result)
{
	OSMO_NAME_C_IMPL(ctx, 64, "ERROR", osmo_mslookup_result_name_buf, query, result)
}

/*! Same as osmo_mslookup_result_name_buf(), but directly return the char* (for printf-like string formats). */
char *osmo_mslookup_result_name_b(char *buf, size_t buflen,
				  const struct osmo_mslookup_query *query,
				  const struct osmo_mslookup_result *result)
{
	int rc = osmo_mslookup_result_name_buf(buf, buflen, query, result);
	if (rc < 0 && buflen)
		buf[0] = '\0';
	return buf;
}

static int token(char *dest, size_t dest_size, const char *start, const char *end)
{
	int len;
	if (start >= end)
		return -10;
	len = end - start;
	if (len >= dest_size)
		return -11;
	strncpy(dest, start, len);
	dest[len] = '\0';
	return 0;
}

/*! Parse a string like "foo.moo.goo.123456789012345.msisdn" into service="foo.moo.goo", id="123456789012345" and
 * id_type="msisdn", placed in a struct osmo_mslookup_query. */
int osmo_mslookup_query_from_domain_str(struct osmo_mslookup_query *q, const char *domain)
{
	const char *last_dot;
	const char *second_last_dot;
	const char *id_type;
	const char *id;
	int rc;

	*q = (struct osmo_mslookup_query){};

	if (!domain)
		return -1;

	last_dot = strrchr(domain, '.');

	if (!last_dot)
		return -2;

	if (last_dot <= domain)
		return -3;

	for (second_last_dot = last_dot - 1; second_last_dot > domain && *second_last_dot != '.'; second_last_dot--);
	if (second_last_dot == domain || *second_last_dot != '.')
		return -3;

	id_type = last_dot + 1;
	if (!*id_type)
		return -4;

	q->id.type = get_string_value(osmo_mslookup_id_type_names, id_type);

	id = second_last_dot + 1;
	switch (q->id.type) {
	case OSMO_MSLOOKUP_ID_IMSI:
		rc = token(q->id.imsi, sizeof(q->id.imsi), id, last_dot);
		if (rc)
			return rc;
		if (!osmo_imsi_str_valid(q->id.imsi))
			return -5;
		break;
	case OSMO_MSLOOKUP_ID_MSISDN:
		rc = token(q->id.msisdn, sizeof(q->id.msisdn), id, last_dot);
		if (rc)
			return rc;
		if (!osmo_msisdn_str_valid(q->id.msisdn))
			return -6;
		break;
	default:
		return -7;
	}

	return token(q->service, sizeof(q->service), domain, second_last_dot);
}
