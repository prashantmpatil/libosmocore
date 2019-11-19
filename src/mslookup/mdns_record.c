#include <errno.h>
#include <talloc.h>
#include "mdns_record.h"

static struct osmo_mdns_record *_osmo_mdns_record_txt_encode(void *ctx, const char *key, const char *value)
{
	struct osmo_mdns_record *ret = talloc_zero(ctx, struct osmo_mdns_record);
	size_t len = strlen(key) + 1 + strlen(value);

	ret->data = (uint8_t *)talloc_asprintf(ctx, "%c%s=%s", (char)len, key, value);
	if (!ret->data)
		return NULL;
	ret->type = OSMO_MDNS_RFC_RECORD_TYPE_TXT;
	ret->length = len + 1;
	return ret;
}

struct osmo_mdns_record *osmo_mdns_record_txt_keyval_encode(void *ctx, const char *key, const char *value_fmt, ...)
{
	va_list ap;
	char *value = NULL;
	struct osmo_mdns_record *r;

	if (!value_fmt)
		return _osmo_mdns_record_txt_encode(ctx, key, "");

	va_start(ap, value_fmt);
	value = talloc_vasprintf(ctx, value_fmt, ap);
	if (!value)
		return NULL;
	va_end(ap);
	r = _osmo_mdns_record_txt_encode(ctx, key, value);
	talloc_free(value);
	return r;
}

int osmo_mdns_record_txt_keyval_decode(const struct osmo_mdns_record *rec,
				       char *key_buf, size_t key_size, char *value_buf, size_t value_size)
{
	const char *key_value;
	const char *key_value_end;
	const char *sep;
	const char *value;

	if (rec->type != OSMO_MDNS_RFC_RECORD_TYPE_TXT)
		return -EINVAL;

	key_value = (const char *)rec->data;
	key_value_end = key_value + rec->length;

	/* Verify and then skip the redundant string length byte */
	if (*key_value != rec->length - 1)
		return -EINVAL;
	key_value++;

	if (key_value >= key_value_end)
		return -EINVAL;

	/* Find equals sign */
	sep = osmo_strnchr(key_value, key_value_end - key_value, '=');
	if (!sep)
		return -EINVAL;

	/* Parse key */
	osmo_token_copy(key_buf, key_size, key_value, sep - key_value);

	/* Parse value */
	value = sep + 1;
	osmo_token_copy(value_buf, value_size, value, key_value_end - value);
	return 0;
}
