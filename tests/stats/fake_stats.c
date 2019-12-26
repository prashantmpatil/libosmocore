#include <talloc.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/stats.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/misc.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/stats.h>

static struct vty_app_info vty_info = {
	.name		= "fake_stats",
	.version	= "1",
};

static const struct log_info_cat categories[] = {
};

const struct log_info log_info = {
	.cat = categories,
	.num_cat = ARRAY_SIZE(categories),
};

int main(int argc, char **argv)
{
	int rc;
	void *ctx = talloc_named_const(NULL, 1, "fake_stats");
	vty_info.tall_ctx = ctx;

	osmo_init_logging2(ctx, &log_info);

	osmo_stats_init(ctx);
//int osmo_stat_item_init(void *tall_ctx);

	vty_init(&vty_info);
	osmo_stats_vty_add_cmds();

	logging_vty_add_cmds();
	osmo_talloc_vty_add_cmds();

//void rate_ctr_add(struct rate_ctr *ctr, int inc);
// osmo_stat_item

	/* start telnet after reading config for vty_get_bind_addr() */
	rc = telnet_init_dynif(ctx, NULL,
			       vty_get_bind_addr(), 12345);
	if (rc < 0)
		return 2;

	while (1) {
		log_reset_context();
		osmo_select_main_ctx(0);
	}
	return 0;
}

// telnet localhost 12345
