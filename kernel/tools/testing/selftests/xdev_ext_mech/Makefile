# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := xdev_ext_mech_core_test xdev_ext_mech_ce_core_test
TEST_GEN_PROGS += xdev_ext_mech_window_copy_core_test
TEST_GEN_PROGS += xdev_ext_mech_step_test
TEST_GEN_PROGS += xdev_ext_mech_lifecycle_test
# Four-state references replace the previous single-consumer lifecycle contract.
TEST_GEN_PROGS += xdev_ext_mech_refs_test xdev_ext_mech_lifecycle_contract_test
TEST_GEN_PROGS += xdev_ext_mech_fanout_step_test xdev_ext_mech_cpu_xform_test
TEST_GEN_PROGS += xdev_ext_mech_ctl_chains_test
TEST_GEN_PROGS += xdev_ext_mech_rx_stages_test
TEST_GEN_PROGS += xdev_ext_mech_window_offset_test xdev_ext_mech_window_pipeline_test
TEST_GEN_PROGS += xdev_ext_mech_ce_exact_completion_test
TEST_GEN_PROGS += xdev_ext_mech_ce_lease_test
TEST_GEN_PROGS += provider/xdev_ext_mech_dma_core_test
TEST_PROGS := xdev_ext_mech_source_test.py xdev_ext_mech_ce_source_test.py
TEST_PROGS += xdev_ext_mech_call_active_test.py
TEST_PROGS += call_identity_test.py
TEST_FILES += call_identity_fixture.c.in
TEST_PROGS += independent_ce_lease.py
TEST_PROGS += xdev_ext_mech_zc_source_test.py xdev_ext_mech_dma_test.py
TEST_PROGS += xdev_ext_mech_nvme_nowait_test.py
TEST_PROGS += xdev_ext_mech_recycle_tail_test.py xdev_ext_mech_ce_positive_test.py
TEST_PROGS += reliable/run.sh reliable/wire_fault_test.py
TEST_PROGS += model/run.sh model/refs_run.sh xdev_ext_mech_refs_source_test.py
TEST_FILES += model/refs_explore.c model/refs_mutants.py xform_oracle.h refs_suite.py
TEST_FILES += model/life_explore.c model/mutants.py model/Makefile
TEST_FILES += $(wildcard model/shim/linux/*.h)
TEST_PROGS += reliable/regressions/control_stop_admission_test.py
TEST_PROGS += reliable/regressions/native_done_map_teardown_test.py
TEST_PROGS += provider/faults/run.py
TEST_PROGS += transport_pending/portable_test.py transport_pending/native_ack_test.py
TEST_PROGS += transport_pending/api_dispatch_test.py transport_pending/final_result_test.py
TEST_PROGS += transport_pending/stop_finalize_test.py transport_pending/provider_stats_test.py
TEST_PROGS += transport_pending/finite_rx_test.py transport_pending/legacy_cancel_test.py
TEST_FILES += transport_pending/portable_test.c transport_pending/native_ack_fixture.c
TEST_FILES += xdev_ext_mech_nvme_nowait_fixture.c
TEST_FILES += xdev_ext_mech_recycle_tail_fixture.c xdev_ext_mech_ce_positive_fixture.c
TEST_PROGS += xdev_ext_mech_nvme_pool_test.py
TEST_FILES += xdev_ext_mech_nvme_pool_fixture.c
TEST_PROGS += iaa_transform/run.sh xdev_ext_mech_variable_length_test.py
TEST_FILES += $(wildcard iaa_transform/*.py iaa_transform/*.c iaa_transform/*.h iaa_transform/*.md)

TEST_PROGS += core_lifecycle/detach_generation_test.py
TEST_FILES += core_lifecycle/detach_generation_fixture.c.in
TEST_PROGS += core_lifecycle/teardown_test.py core_lifecycle/stop_work_rearm_test.py core_lifecycle/start_keys_test.py
TEST_PROGS += core_lifecycle/frames_release_test.py core_lifecycle/transform_alias_test.py core_lifecycle/alias_table_test.py core_lifecycle/stage_get_cmd_test.py
TEST_FILES += core_lifecycle/lease_boundary.py
TEST_PROGS += reliable/slow_downstream_run.sh
TEST_FILES += reliable/slow_downstream_test.c
TEST_PROGS += reliable/regressions/downstream_failure_terminal_test.py reliable/regressions/held_reply_provider_test.py
TEST_PROGS += reliable/regressions/single_crc_pass_test.py reliable/regressions/backpressure_skip_payload_test.py
TEST_PROGS += transport_pending/transport_counters_test.py
TEST_PROGS += peer_graph/test_native_owner_teardown.py peer_graph/test_native_admission_profile.py
TEST_FILES += peer_graph/native_owner_fixture.h peer_graph/native_owner_cases.c peer_graph/NATIVE_TEARDOWN.md peer_graph/native_admission_fixture.py

TEST_PROGS += socket_sink/adapter_test.py
TEST_PROGS += socket_guest/key_contract_test.py
TEST_PROGS += socket_sink/independent_credentials.py
TEST_PROGS += user_spans/test_user_spans.py user_spans/independent_start_boundaries.py
TEST_FILES += socket_sink/shim.h socket_sink/fixture.c
# Track S: NIC-boundary copy receive, fallback choice and copy-mode accounting.
TEST_PROGS += socket_sink/rx_adapter_test.py socket_sink/rx_create_check_test.py
TEST_PROGS += socket_sink/produced_trim_test.py socket_sink/bpf_both_directions_test.py
TEST_PROGS += socket_sink/nic_accounting_test.py socket_sink/nic_fallback_choice_test.py
TEST_PROGS += socket_sink/produced_core_test.py socket_sink/ctl_socket_test.py socket_sink/rx_core_fifo_test.py
TEST_PROGS += socket_guest/nic_fallback_harness_test.py
TEST_FILES += socket_sink/rx_fixture.c socket_sink/nxp_interop_fixture.c
TEST_PROGS += socket_sink/nxp_interop_test.py

LOCAL_HDRS += $(abspath ../../../../include/linux/xdev_ext_mech.h)
LOCAL_HDRS += $(abspath ../../../../include/uapi/linux/xdev_ext_mech.h)
LOCAL_HDRS += $(abspath ../../../../include/uapi/linux/xdev_ext_binding.h)
LOCAL_HDRS += $(abspath ../../../../include/uapi/linux/io_uring.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_core.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_step.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_lifecycle.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_ce_core.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_window_copy_core.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_ce_lease.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_window.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_dma_core.h)
LOCAL_HDRS += $(abspath ../../../xdev_ext_mech/xdev_ext_mech_ctl_core.h)
LOCAL_HDRS += $(abspath ../../../../nvme_xdp_pipeline_core.h)

CFLAGS += -std=gnu11 -O2 -g -Wall -Wextra -Werror $(KHDR_INCLUDES)
CFLAGS += -I$(abspath ../../../..)

# Sanitizer runtimes belong to the build host, so do not inject them into a
# cross or LLVM build.  Native GCC remains strict and sanitized by default.
ifeq ($(strip $(CROSS_COMPILE)$(LLVM)),)
XDEV_EXT_MECH_UBSAN ?= 1
else
XDEV_EXT_MECH_UBSAN ?= 0
endif

ifeq ($(XDEV_EXT_MECH_UBSAN),1)
CFLAGS += -fsanitize=undefined -fno-sanitize-recover=undefined
LDFLAGS += -fsanitize=undefined
endif

# Native lifecycle scheduler and teardown extraction, with independent failure schedules.
TEST_PROGS += fanout_scheduler/run.py fanout_scheduler/produced_test.py
TEST_PROGS += fanout_scheduler/recycle_test.py
TEST_PROGS += lifecycle_runtime/guest_harness_test.py
TEST_PROGS += lifecycle_runtime/recycle_input_test.py teardown_checked/test_ce_unbind.py
TEST_FILES += fanout_scheduler/fixture.c fanout_scheduler/shim.h
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_cpu_core.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_life_pool.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_produced.h)

include ../lib.mk

$(OUTPUT)/xdev_ext_mech_lifecycle_test: CFLAGS += -pthread
$(OUTPUT)/xdev_ext_mech_lifecycle_test: LDLIBS += -pthread
$(OUTPUT)/xdev_ext_mech_rx_stages_test: $(abspath ../../../xdev_ext_mech/xdev_ext_mech_ctl_core.h)

# lib.mk links every program straight into $(OUTPUT)/<name>, so a program in a
# subdirectory needs that subdirectory to exist below an out-of-tree OUTPUT.
$(OUTPUT)/provider:
	mkdir -p $@
$(OUTPUT)/provider/xdev_ext_mech_dma_core_test: | $(OUTPUT)/provider

.PHONY: run model-check
run: run_tests

# Bounded model check of the lifecycle, completion and teardown words; the
# same check runs as model/run.sh under run_tests.
model-check:
	$(MAKE) -C model OUTPUT=$(OUTPUT)/model CC="$(CC)" \
		XDEV_EXT_MECH_UBSAN=$(XDEV_EXT_MECH_UBSAN) model-check

# Instrument the real kernel-form lifecycle header with the existing atomic shim.
$(OUTPUT)/xdev_ext_mech_refs_test $(OUTPUT)/xdev_ext_mech_lifecycle_contract_test: CFLAGS += -pthread -I$(CURDIR)/model/shim
$(OUTPUT)/xdev_ext_mech_refs_test $(OUTPUT)/xdev_ext_mech_lifecycle_contract_test: LDLIBS += -pthread
$(OUTPUT)/xdev_ext_mech_cpu_xform_test $(OUTPUT)/xdev_ext_mech_ctl_chains_test: $(CURDIR)/xform_oracle.h

# Real Kbuild linkage guard; requires an isolated prepared x86 output tree.
.PHONY: kernel-popcount-check
kernel-popcount-check:
	@test -n "$(KERNEL_SOURCE)" -a -n "$(KERNEL_OUTPUT)" || \
		{ echo 'Set KERNEL_SOURCE and KERNEL_OUTPUT to matching prepared kernel trees'; exit 2; }
	python3 "$(CURDIR)/kernel_popcount/run.py" --kernel-source "$(KERNEL_SOURCE)" \
		--kernel-output "$(KERNEL_OUTPUT)" --build-dir "$(OUTPUT)/.kernel-popcount" --cc "$(CC)"

TEST_PROGS += peer_graph/test_native_rep_rx.py peer_graph/test_native_teardown.py
TEST_FILES += peer_graph/native_rep_fixture.py peer_graph/native_eswitch_fixture.h peer_graph/native_eswitch_cases.c peer_graph/native_suspend_fixture.py peer_graph/fixtures/native_destroy_wrappers.c

# Sleepable Thunderbolt registry and real tbnet work teardown.
TEST_PROGS += peer_graph/tb_protocol_handler_lifetime_test.py peer_graph/tbnet_handler_teardown_test.py
TEST_FILES += peer_graph/tb_protocol_handler_lifetime_fixture.c.in peer_graph/tb_protocol_handler_lifetime_cases.c.in peer_graph/tbnet_handler_teardown_fixture.c.in
