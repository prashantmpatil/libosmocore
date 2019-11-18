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

struct osmo_mdns_record *osmo_mdns_record_txt_encode(void *ctx, const char *key, const char *value_fmt, ...)
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

int osmo_mdns_record_txt_decode(void *ctx, const struct osmo_mdns_record *rec, char **key, char **value)
{
	size_t key_length;
	size_t value_length;
	const char *key_value;
	const char *sep;

	if (rec->type != OSMO_MDNS_RFC_RECORD_TYPE_TXT)
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
