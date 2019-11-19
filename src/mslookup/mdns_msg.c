#include "mdns_msg.h"
#include "mdns_record.h"
#include <errno.h>
#include <osmocom/core/logging.h>


int osmo_mdns_msg_request_encode(void *ctx, struct msgb *msg, const struct osmo_mdns_msg_request *req)
{
	struct osmo_mdns_rfc_header hdr = {0};
	struct osmo_mdns_rfc_question qst = {0};

	hdr.id = req->id;
	hdr.qdcount = 1;
	osmo_mdns_rfc_header_encode(msg, &hdr);

	qst.domain = req->domain;
	qst.qtype = req->type;
	qst.qclass = OSMO_MDNS_RFC_CLASS_IN;
	if (osmo_mdns_rfc_question_encode(ctx, msg, &qst) != 0)
		return -EINVAL;

	return 0;
}

struct osmo_mdns_msg_request *osmo_mdns_msg_request_decode(void *ctx, const uint8_t *data, size_t data_len)
{
	struct osmo_mdns_rfc_header hdr = {0};
	size_t hdr_len = sizeof(struct osmo_mdns_rfc_header);
	struct osmo_mdns_rfc_question* qst = NULL;
	struct osmo_mdns_msg_request *ret = NULL;

	if (data_len < hdr_len || osmo_mdns_rfc_header_decode(data, hdr_len, &hdr) != 0 || hdr.qr != 0)
		return NULL;

	qst = osmo_mdns_rfc_question_decode(ctx, data + hdr_len, data_len - hdr_len);
	if (!qst)
		return NULL;

	ret = talloc(ctx, struct osmo_mdns_msg_request);
	ret->id = hdr.id;
	ret->domain = talloc_strdup(ret, qst->domain);
	ret->type = qst->qtype;

	talloc_free(qst);
	return ret;
}

void osmo_mdns_msg_answer_init(struct osmo_mdns_msg_answer *ans)
{
	*ans = (struct osmo_mdns_msg_answer){};
	INIT_LLIST_HEAD(&ans->records);
}

int osmo_mdns_msg_answer_encode(void *ctx, struct msgb *msg, const struct osmo_mdns_msg_answer *ans)
{
	struct osmo_mdns_rfc_header hdr = {0};
	struct osmo_mdns_record *ans_record;

	hdr.id = ans->id;
	hdr.qr = 1;
	hdr.ancount = llist_count(&ans->records);
	osmo_mdns_rfc_header_encode(msg, &hdr);

	llist_for_each_entry(ans_record, &ans->records, list) {
		struct osmo_mdns_rfc_record rec = {0};

		rec.domain = ans->domain;
		rec.type = ans_record->type;
		rec.class = OSMO_MDNS_RFC_CLASS_IN;
		rec.ttl = 0;
		rec.rdlength = ans_record->length;
		rec.rdata = ans_record->data;

		if (osmo_mdns_rfc_record_encode(ctx, msg, &rec) != 0)
			return -EINVAL;
	}

	return 0;
}

struct osmo_mdns_msg_answer *osmo_mdns_msg_answer_decode(void *ctx, const uint8_t *data, size_t data_len)
{
	struct osmo_mdns_rfc_header hdr = {};
	size_t hdr_len = sizeof(struct osmo_mdns_rfc_header);
	struct osmo_mdns_msg_answer *ret = talloc_zero(ctx, struct osmo_mdns_msg_answer);

	/* Parse header section */
	if (data_len < hdr_len || osmo_mdns_rfc_header_decode(data, hdr_len, &hdr) != 0 || hdr.qr != 1)
		goto error;
	ret->id = hdr.id;
	data_len -= hdr_len;
	data += hdr_len;

	/* Parse resource records */
	INIT_LLIST_HEAD(&ret->records);
	while (data_len) {
		size_t record_len;
		struct osmo_mdns_rfc_record *rec;
		struct osmo_mdns_record* ret_record;

		rec = osmo_mdns_rfc_record_decode(ret, data, data_len, &record_len);
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
