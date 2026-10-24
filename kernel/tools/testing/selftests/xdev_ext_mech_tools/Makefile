# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := xdev_ext_mech_prog_test xdev_ext_mech_ctl_core_test \
	xdev_ext_mech_notify_test xdev_ext_mech_notify_compat_test
TEST_PROGS := xdev_ext_mech_timeout_test.py xdev_ext_mech_tools_source_test.py
TEST_PROGS += xdev_ext_mech_rx_admission_test.py xdev_ext_mech_rx_private_test.py
TEST_PROGS += xdev_ext_mech_cuda_lifecycle_test.py
TEST_PROGS += xdev_ext_cpu_bpf_test.py
TEST_FILES += xdev_ext_mech_rx_admission_fixture.c
TEST_FILES += xdev_ext_mech_rx_private_fixture.c xdev_ext_mech_rx_result_fixture.c
TEST_FILES += xdev_ext_mech_ce_window_test.c
TEST_FILES += xdev_ext_mech_cuda_fake.c xdev_ext_mech_cuda_probe.c

LOCAL_HDRS += $(abspath ../../../xdev_ext_mech/xdev_ext_mech_prog.h)
LOCAL_HDRS += $(abspath ../../../xdev_ext_mech/xdev_ext_mech_ctl_core.h)
LOCAL_HDRS += $(abspath ../../../../include/linux/xdev_ext_mech.h)
LOCAL_HDRS += $(abspath ../../../../include/linux/nvme_xdev_ext_passthru.h)
LOCAL_HDRS += $(abspath ../../../../include/uapi/linux/xdev_ext_mech.h)
LOCAL_HDRS += $(abspath ../../../../include/uapi/linux/xdev_ext_binding.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_core.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_ce_core.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_window.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_notify.h)
LOCAL_HDRS += $(abspath ../../../../net/xdp/xsk_xdev_ext_mech_tx_core.h)
LOCAL_HDRS += $(abspath ../../../../net/xdp/xsk_xdev_ext_mech_core.h)
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

include ../lib.mk

.PHONY: run
run: run_tests
