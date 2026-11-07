// SPDX-License-Identifier: GPL-2.0
/* Separate added tests: original request-builder cases/wants stay unchanged. */
#define main request_builder_frozen_driver
#include "request_builders.c"
#undef main

static struct xdev_ext_mech_ctx prepare_context(void)
{
	struct xdev_ext_mech_ctx c = initialize();
	/* CREATE has no live batch. Keep only actual layout/geometry inputs. */
	c.batch_id = 0; c.base.request_id = 0; c.nr_frames = 0; c.desc_cap = 0;
	c.base.src_offset = 0; c.base.length = 0;
	c.callsite = XDEV_EXT_MECH_SITE_CREATE;
	c.member = XDEV_EXT_MECH_MEMBER_PREPARE;
	ce_info[0].nr_frames = 0;
	memset(ce_info[0].f, 0, sizeof(ce_info[0].f));
	ce_info[0].window_slot = UINT32_MAX;
	ce_info[0].window_depth = 0;
	ce_info[0].lease_generation = 0;
	missing = 1; /* No records exist until after successful CREATE. */
	ce_call = 1;
	return c;
}
int main(void)
{
	struct xdev_ext_mech_ctx c = prepare_context();
	struct xdev_ext_ce_copy_desc d = {0};
	expect("CREATE 1MiB alloffset64K fits48", request_ce_prepare(NULL, &c), 0);
	expect("CREATE no map lookup", map_lookups, 0);
	ce_info[0].gpu_seg_size = 32768; ce_info[0].max_entry_len = 32768;
	expect("CREATE alloffset32K fits64", request_ce_prepare(NULL, &c), 0);
	ce_info[0].gpu_seg_size = 131072; ce_info[0].max_entry_len = 131072;
	expect("CREATE alloffset128K fits40", request_ce_prepare(NULL, &c), 0);
	ce_info[0].gpu_seg_size = 0; ce_info[0].max_entry_len = 0;
	expect("CREATE unsegmented unbounded fits32", request_ce_prepare(NULL, &c), 0);
	ce_info[0].max_entry_len = 16384;
	expect("CREATE S0 explicitM16K fits64", request_ce_prepare(NULL, &c), 0);
	ce_info[0].max_entry_len = 16383;
	expect("CREATE S0 explicit smallerM requires96", request_ce_prepare(NULL, &c), -EMSGSIZE);
	c = prepare_context(); ce_info[0].gpu_seg_size = 16384;
	ce_info[0].max_entry_len = 16384;
	expect("CREATE alloffset16K requires96", request_ce_prepare(NULL, &c), -EMSGSIZE);
	c = prepare_context(); ce_info[0].max_entry_len = 16384;
	expect("CREATE S64K M16K requires80", request_ce_prepare(NULL, &c), -EMSGSIZE);
	c = prepare_context(); ce_info[0].l.seg_len = 0;
	expect("CREATE zero layout segment", request_ce_prepare(NULL, &c), -EINVAL);
	c = prepare_context(); ce_info[0].l.hdr_room = 65536;
	expect("CREATE header consumes frame", request_ce_prepare(NULL, &c), -EINVAL);
	c = prepare_context(); ce_info[0].l.seg_len = 65536;
	expect("CREATE span beyond frame", request_ce_prepare(NULL, &c), -EINVAL);
	c = prepare_context(); ce_info[0].gpu_window_len = PAYLOAD - 1;
	expect("CREATE entire group must fit window", request_ce_prepare(NULL, &c), -EINVAL);
	c = prepare_context(); ce_info[0].l.group_bytes = UINT32_MAX;
	ce_info[0].gpu_window_len = UINT64_MAX;
	expect("CREATE huge framecount does not wrap", request_ce_prepare(NULL, &c), -EMSGSIZE);
	c = prepare_context(); ce_info[0].gpu_seg_size = UINT32_MAX;
	ce_info[0].max_entry_len = UINT32_MAX;
	expect("CREATE bound numerator computedwide", request_ce_prepare(NULL, &c), 0);
	expect("CREATE still never looks up missing table", map_lookups, 0);
	ce_call = 0;
	expect("CREATE namespace geometry without request", request_nvme_prepare(NULL, &c), 0);
	expect("NVMe CREATE no table lookup", map_lookups, 0);
	nvme_info.max_nlb = 2047;
	expect("CREATE actual queue NLB refusal", request_nvme_prepare(NULL, &c), -EMSGSIZE);
	nvme_info.max_nlb = 2048; nvme_info.window_slba = UINT64_MAX - 1;
	expect("CREATE namespace window overflow", request_nvme_prepare(NULL, &c), -EINVAL);
	expect("new helper first piece of final frame", xdev_ext_mp_ce_piece(&d,
		31, false, 64, 32767, 1015809, WINDOW, 0, 65536), 0);
	expect("first piece of final frame does not complete", d.flags, 0);
	expect("new helper final piece", xdev_ext_mp_ce_piece(&d,
		31, true, 32831, 1, 1048576, WINDOW, 65536, 65536), 0);
	expect("final piece completes", d.flags, 1);
	expect("old wrapper keeps finalframe completion", xdev_ext_mp_ce_entry(&d,
		31, 32, 64, 32767, 1015809, WINDOW, 0, 65536), 0);
	expect("old wrapper completion unchanged", d.flags, 1);
	printf("prepare: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
