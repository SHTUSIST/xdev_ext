// SPDX-License-Identifier: GPL-2.0
/* Final transport verdicts must include work outside completed payloads. */
#include <assert.h>
#include <stdio.h>
#include "tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"

int main(void)
{
	struct xdev_ext_mech_stats main = {
		.session_id = 1, .state = XDEV_EXT_MECH_SESSION_ACTIVE,
		.batches_done = 1, .held = 1, .recycled = 1,
		.submitted = { 1, 1 }, .completed = { 1, 1 },
	};
	char line[512];

	_Static_assert(sizeof(main) == 168, "legacy stats ABI");
	assert(xdev_ext_mech_ctl_nic_nvme_ok(&main, 1, 1));
	main.last_err = -ENXIO;
	assert(!xdev_ext_mech_ctl_nic_nvme_ok(&main, 1, 1));
	assert(!xdev_ext_mech_ctl_report_nvme_nic(line, sizeof(line), &main, 1));
	main.last_err = 0;
	main.state = XDEV_EXT_MECH_SESSION_STOPPING;
	assert(!xdev_ext_mech_ctl_nic_nvme_ok(&main, 1, 1));
	assert(!xdev_ext_mech_ctl_report_nvme_nic(line, sizeof(line), &main, 1));
#ifdef XDEV_EXT_MECH_TRANSPORT_STATS_VERSION
	{
		struct xdev_ext_mech_transport_stats transport = {
			.size = sizeof(transport),
			.version = XDEV_EXT_MECH_TRANSPORT_STATS_VERSION,
			.session_id = 1,
		};

		_Static_assert(sizeof(transport) == 32, "transport stats ABI");
		assert(xdev_ext_mech_ctl_transport_ok(&transport));
		transport.native_controls = 1;
		assert(!xdev_ext_mech_ctl_transport_ok(&transport));
		transport.native_controls = 0;
		transport.pending_acks = 1;
		assert(!xdev_ext_mech_ctl_transport_ok(&transport));
		transport.pending_acks = 0;
		transport.uncertain_controls = 1;
		assert(!xdev_ext_mech_ctl_transport_ok(&transport));
		transport.uncertain_controls = 0;
		transport.rsvd = 1;
		assert(!xdev_ext_mech_ctl_transport_ok(&transport));
		transport.rsvd = 0;
		transport.version++;
		assert(!xdev_ext_mech_ctl_transport_ok(&transport));
		transport.version--;
		transport.size--;
		assert(!xdev_ext_mech_ctl_transport_ok(&transport));
		transport.size++;
		transport.session_id = 0;
		assert(!xdev_ext_mech_ctl_transport_ok(&transport));
	}
#else
	assert(!"transport observation ABI is absent");
#endif
	puts("transport result verdicts: PASS");
	return 0;
}
