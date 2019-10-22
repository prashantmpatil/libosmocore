#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/bitvec.h>
#include <osmocom/core/logging.h>
#include <osmocom/mslookup/mdns.h>
#include "mdns_internal.h"

/*
 * Encode/decode IEs
 */

char *osmo_mdns_encode_qname(void *ctx, const char *domain)
{
	char *domain_dup;
	char *domain_iter;
	char buf[OSMO_MSLOOKUP_MDNS_MAX_NAME_LEN + 2] = ""; /* len(qname) is len(domain) +1 */
	struct osmo_strbuf sb = { .buf = buf, .len = sizeof(buf) };
	char *label;

	if (strlen(domain) > OSMO_MSLOOKUP_MDNS_MAX_NAME_LEN)
		return NULL;

	domain_iter = domain_dup = talloc_strdup(ctx, domain);
	while ((label = strsep(&domain_iter, "."))) {
		size_t len = strlen(label);

		/* Empty domain, dot at start, two dots in a row, or ending with a dot */
		if (!len)
			goto error;

		OSMO_STRBUF_PRINTF(sb, "%c%s", (char)len, label);
	}

	talloc_free(domain_dup);
	return talloc_strdup(ctx, buf);

error:
	talloc_free(domain_dup);
	return NULL;
}

/*!
 * \qname_max_len amount of bytes that can be read at most from the memory location that qname points to.
 * */
char *osmo_mdns_decode_qname(void *ctx, const char *qname, size_t qname_max_len)
{
	const char *next_label, *qname_end = qname + qname_max_len;
	char buf[OSMO_MSLOOKUP_MDNS_MAX_NAME_LEN + 1];
	int i = 0;

	if (qname_max_len < 1)
		return NULL;

	while (*qname) {
		size_t len = *qname;
		next_label = qname + len + 1;

		if (next_label >= qname_end || i + len > OSMO_MSLOOKUP_MDNS_MAX_NAME_LEN)
			return NULL;

		if (i) {
			/* Two dots in a row is not allowed */
			if (buf[i - 1] == '.')
				return NULL;

			buf[i] = '.';
			i++;
		}

		memcpy(buf + i, qname + 1, len);
		i += len;
		qname = next_label;
	}
	buf[i] = '\0';

	return talloc_strdup(ctx, buf);
}

/*
 * Encode/decode message sections
 */

void osmo_mdns_encode_section_header(struct msgb *msg, const struct osmo_mdns_section_header *hdr)
{
	struct osmo_mdns_section_header *buf = (struct osmo_mdns_section_header *) msgb_put(msg, sizeof(*hdr));
	memcpy(buf, hdr, sizeof(*hdr));

	osmo_store16be(buf->id, &buf->id);
	osmo_store16be(buf->qdcount, &buf->qdcount);
	osmo_store16be(buf->ancount, &buf->ancount);
	osmo_store16be(buf->nscount, &buf->nscount);
	osmo_store16be(buf->arcount, &buf->arcount);
}

int osmo_mdns_decode_section_header(const uint8_t *data, size_t data_len, struct osmo_mdns_section_header *hdr)
{
	if (data_len != sizeof(*hdr))
		return -EINVAL;

	memcpy(hdr, data, data_len);

	hdr->id = osmo_load16be(&hdr->id);
	hdr->qdcount = osmo_load16be(&hdr->qdcount);
	hdr->ancount = osmo_load16be(&hdr->ancount);
	hdr->nscount = osmo_load16be(&hdr->nscount);
	hdr->arcount = osmo_load16be(&hdr->arcount);

	return 0;
}

int osmo_mdns_encode_section_question(void *ctx, struct msgb *msg, const struct osmo_mdns_section_question *qst)
{
	char *qname;
	size_t qname_len;
	uint8_t *qname_buf;

	/* qname */
	qname = osmo_mdns_encode_qname(ctx, qst->domain);
	if (!qname)
		return -EINVAL;
	qname_len = strlen(qname) + 1;
	qname_buf = msgb_put(msg, qname_len);
	memcpy(qname_buf, qname, qname_len);
	talloc_free(qname);

	/* qtype and qclass */
	msgb_put_u16(msg, qst->qtype);
	msgb_put_u16(msg, qst->qclass);

	return 0;
}

struct osmo_mdns_section_question *osmo_mdns_decode_section_question(void *ctx, const uint8_t *data, size_t data_len)
{
	struct osmo_mdns_section_question *ret;
	size_t qname_len = data_len - 4;

	if (data_len < 6)
		return NULL;

	/* qname */
	ret = talloc_zero(ctx, struct osmo_mdns_section_question);
	if (!ret)
		return NULL;
	ret->domain = osmo_mdns_decode_qname(ret, (const char *)data, qname_len);
	if (!ret->domain) {
		talloc_free(ret);
		return NULL;
	}

	/* qtype and qclass */
	ret->qtype = osmo_load16be(data + qname_len);
	ret->qclass = osmo_load16be(data + qname_len + 2);

	return ret;
}

/*
 * Encode/decode resource records
 */

int osmo_mdns_encode_resource_record(void *ctx, struct msgb *msg, const struct osmo_mdns_resource_record *rec)
{
	char *name;
	size_t name_len;
	uint8_t *buf;

	/* name */
	name = osmo_mdns_encode_qname(ctx, rec->domain);
	if (!name)
		return -EINVAL;
	name_len = strlen(name) + 1;
	buf = msgb_put(msg, name_len);
	memcpy(buf, name, name_len);
	talloc_free(name);

	/* type, class, ttl, rdlength */
	msgb_put_u16(msg, rec->type);
	msgb_put_u16(msg, rec->class);
	msgb_put_u32(msg, rec->ttl);
	msgb_put_u16(msg, rec->rdlength);

	/* rdata */
	buf = msgb_put(msg, rec->rdlength);
	memcpy(buf, rec->rdata, rec->rdlength);
	return 0;
}

struct osmo_mdns_resource_record *osmo_mdns_decode_resource_record(void *ctx, const uint8_t *data, size_t data_len,
						       size_t *record_len)
{
	struct osmo_mdns_resource_record *ret = talloc_zero(ctx, struct osmo_mdns_resource_record);
	size_t name_len;

	/* name */
	ret->domain = osmo_mdns_decode_qname(ret, (const char *)data, data_len - 10);
	if (!ret->domain)
		goto error;
	name_len = strlen(ret->domain) + 2;
	if (name_len + 10 > data_len)
		goto error;

	/* type, class, ttl, rdlength */
	ret->type = osmo_load16be(data + name_len);
	ret->class = osmo_load16be(data + name_len + 2);
	ret->ttl = osmo_load32be(data + name_len + 4);
	ret->rdlength = osmo_load16be(data + name_len + 8);
	if (name_len + 10 + ret->rdlength > data_len)
		goto error;

	/* rdata */
	ret->rdata = talloc_memdup(ret, data + name_len + 10, ret->rdlength);
	if (!ret->rdata)
		return NULL;

	*record_len = name_len + 10 + ret->rdlength;
	return ret;
error:
	talloc_free(ret);
	return NULL;
}

/*
 * High level encoders/decoders (in dns.h)
 */

static struct osmo_mdns_record *_osmo_mdns_encode_txt_record(void *ctx, const char *key, const char *value)
{
	struct osmo_mdns_record *ret = talloc_zero(ctx, struct osmo_mdns_record);
	size_t len = strlen(key) + 1 + strlen(value);

	ret->data = (uint8_t *)talloc_asprintf(ctx, "%c%s=%s", (char)len, key, value);
	if (!ret->data)
		return NULL;
	ret->type = OSMO_MSLOOKUP_MDNS_RECORD_TYPE_TXT;
	ret->length = len + 1;
	return ret;
}

struct osmo_mdns_record *osmo_mdns_encode_txt_record(void *ctx, const char *key, const char *value_fmt, ...)
{
	va_list ap;
	char *value = NULL;
	struct osmo_mdns_record *r;

	if (!value_fmt)
		return _osmo_mdns_encode_txt_record(ctx, key, "");

	va_start(ap, value_fmt);
	value = talloc_vasprintf(ctx, value_fmt, ap);
	if (!value)
		return NULL;
	va_end(ap);
	r = _osmo_mdns_encode_txt_record(ctx, key, value);
	talloc_free(value);
	return r;
}

int osmo_mdns_decode_txt_record(void *ctx, const struct osmo_mdns_record *rec, char **key, char **value)
{
	size_t key_length;
	size_t value_length;
	const char *key_value;
	const char *sep;

	if (rec->type != OSMO_MSLOOKUP_MDNS_RECORD_TYPE_TXT)
		return -EINVAL;

	key_value = (const char *)rec->data;

	/* Verify and then skip the redundant string length byte */
	if (*key_value != rec->length - 1)
		return -EINVAL;
	key_value++;

	/* Find equals sign */
	sep = strchr(key_value, '=');
	if (!sep)
		return -EINVAL;

	/* Parse key */
	key_length = sep - key_value;
	*key = talloc_memdup(ctx, key_value, key_length + 1);
	if (!*key)
		return -ENOMEM;
	(*key)[key_length] = '\0';

	/* Parse value */
	value_length = rec->length - key_length - 2;
	*value = talloc_size(ctx, value_length + 1);
	if (!*value) {
		talloc_free(*key);
		return -ENOMEM;
	}
	memcpy(*value, sep + 1, value_length);
	(*value)[value_length] = '\0';

	return 0;
}

int osmo_mdns_encode_request(void *ctx, struct msgb *msg, const struct osmo_mdns_request *req)
{
	struct osmo_mdns_section_header hdr = {0};
	struct osmo_mdns_section_question qst = {0};

	hdr.id = req->id;
	hdr.qdcount = 1;
	osmo_mdns_encode_section_header(msg, &hdr);

	qst.domain = req->domain;
	qst.qtype = req->type;
	qst.qclass = OSMO_MSLOOKUP_MDNS_CLASS_IN;
	if (osmo_mdns_encode_section_question(ctx, msg, &qst) != 0)
		return -EINVAL;

	return 0;
}

struct osmo_mdns_request *osmo_mdns_decode_request(void *ctx, const uint8_t *data, size_t data_len)
{
	struct osmo_mdns_section_header hdr = {0};
	size_t hdr_len = sizeof(struct osmo_mdns_section_header);
	struct osmo_mdns_section_question* qst = NULL;
	struct osmo_mdns_request *ret = NULL;

	if (data_len < hdr_len || osmo_mdns_decode_section_header(data, hdr_len, &hdr) != 0 || hdr.qr != 0)
		return NULL;

	qst = osmo_mdns_decode_section_question(ctx, data + hdr_len, data_len - hdr_len);
	if (!qst)
		return NULL;

	ret = talloc(ctx, struct osmo_mdns_request);
	ret->id = hdr.id;
	ret->domain = talloc_strdup(ret, qst->domain);
	ret->type = qst->qtype;

	talloc_free(qst);
	return ret;
}

void osmo_mdns_answer_init(struct osmo_mdns_answer *ans)
{
	*ans = (struct osmo_mdns_answer){};
	INIT_LLIST_HEAD(&ans->records);
}

int osmo_mdns_encode_answer(void *ctx, struct msgb *msg, const struct osmo_mdns_answer *ans)
{
	struct osmo_mdns_section_header hdr = {0};
	struct osmo_mdns_record *ans_record;

	hdr.id = ans->id;
	hdr.qr = 1;
	hdr.ancount = llist_count(&ans->records);
	osmo_mdns_encode_section_header(msg, &hdr);

	llist_for_each_entry(ans_record, &ans->records, list) {
		struct osmo_mdns_resource_record rec = {0};

		rec.domain = ans->domain;
		rec.type = ans_record->type;
		rec.class = OSMO_MSLOOKUP_MDNS_CLASS_IN;
		rec.ttl = 0;
		rec.rdlength = ans_record->length;
		rec.rdata = ans_record->data;

		if (osmo_mdns_encode_resource_record(ctx, msg, &rec) != 0)
			return -EINVAL;
	}

	return 0;
}

struct osmo_mdns_answer *osmo_mdns_decode_answer(void *ctx, const uint8_t *data, size_t data_len)
{
	struct osmo_mdns_section_header hdr = {0};
	size_t hdr_len = sizeof(struct osmo_mdns_section_header);
	struct osmo_mdns_answer *ret = talloc_zero(ctx, struct osmo_mdns_answer);

	/* Parse header section */
	if (data_len < hdr_len || osmo_mdns_decode_section_header(data, hdr_len, &hdr) != 0 || hdr.qr != 1)
		goto error;
	ret->id = hdr.id;
	data_len -= hdr_len;
	data += hdr_len;

	/* Parse resource records */
	INIT_LLIST_HEAD(&ret->records);
	while (data_len) {
		size_t record_len;
		struct osmo_mdns_resource_record *rec;
		struct osmo_mdns_record* ret_record;

		rec = osmo_mdns_decode_resource_record(ret, data, data_len, &record_len);
		if (!rec)
			goto error;

		/* Copy domain to ret */
		if (ret->domain) {
			if (strcmp(ret->domain, rec->domain) != 0) {
				LOGP(DLMSLOOKUP, LOGL_ERROR, "domain mismatch in resource records ('%s' vs '%s')\n",
				     ret->domain, rec->domain);
				goto error;
			}
		}
		else
			ret->domain = talloc_strdup(ret, rec->domain);

		/* Add simplified record to ret */
		ret_record = talloc(ret, struct osmo_mdns_record);
		ret_record->type = rec->type;
		ret_record->length = rec->rdlength;
		ret_record->data = talloc_memdup(ret_record, rec->rdata, rec->rdlength);
		llist_add_tail(&ret_record->list, &ret->records);

		data += record_len;
		data_len -= record_len;
		talloc_free(rec);
	}

	/* Verify record count */
	if (llist_count(&ret->records) != hdr.ancount) {
		LOGP(DLMSLOOKUP, LOGL_ERROR, "amount of parsed records (%i) doesn't match count in header (%i)\n",
		     llist_count(&ret->records), hdr.ancount);
		goto error;
	}

	return ret;
error:
	talloc_free(ret);
	return NULL;
}
