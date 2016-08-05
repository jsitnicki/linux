#include <linux/bug.h>		/* XXX: net/flow.h should pull this in */
#include "fib_lookup.h"


void test_fib_select_multipath(void)
{
	struct fib_info *fi;
	struct fib_config cfg = {
		.fc_protocol = RTPROT_UNSPEC,
		.fc_type = 0,
		.fc_dst = 0,
		.fc_dst_len = 0,
		.fc_prefsrc = 0,
		.fc_oif = 0,
		.fc_nlflags = 0,
		.fc_nlinfo = {
			.nl_net = &init_net,
		},
	};

	fi = fib_create_info(&cfg);
	BUG_ON(!fi);
	fib_release_info(fi);
}
EXPORT_SYMBOL_GPL(test_fib_select_multipath);
