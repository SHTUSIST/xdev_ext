# SPDX-License-Identifier: GPL-2.0
#
# Host unit test of the C reference callbacks.  The kernel module in this
# directory is built by kbuild from the Kbuild file instead:
#   make -C <XDEV_EXT kernel build dir> M=<copy of this directory> modules

TEST_GEN_PROGS := xdev_ext_mech_cref_test
TEST_PROGS := xdev_ext_mech_cref_source_test.py

LOCAL_HDRS += $(abspath xdev_ext_mech_cref.h)
LOCAL_HDRS += $(abspath host/vmlinux.h)
LOCAL_HDRS += $(abspath host/bpf/bpf_helpers.h)
LOCAL_HDRS += $(abspath host/bpf/bpf_tracing.h)
LOCAL_HDRS += $(abspath ../../../../xdev_ext_mech/nxp_mech.bpf.c)
LOCAL_HDRS += $(abspath ../../../../xdev_ext_mech/xdev_ext_mech_prog.h)
LOCAL_HDRS += $(abspath ../../../../xdev_ext_mech/xdev_ext_mech_kfunc.h)
LOCAL_HDRS += $(abspath ../../../../../include/linux/xdev_ext_mech.h)
LOCAL_HDRS += $(abspath ../../../../../include/uapi/linux/xdev_ext_mech.h)
LOCAL_HDRS += $(abspath ../../../../../include/uapi/linux/xdev_ext_binding.h)
LOCAL_HDRS += $(abspath ../../../../../io_uring/xdev_ext_mech_core.h)
LOCAL_HDRS += $(abspath ../../../../../net/xdp/xsk_xdev_ext_mech_core.h)

# host/ first: its vmlinux.h and bpf/ headers stand in for the BPF build's.
CFLAGS += -std=gnu11 -O2 -g -Wall -Wextra -Werror
CFLAGS += -I$(abspath host) -I$(abspath ../../../../..)

ifeq ($(strip $(CROSS_COMPILE)$(LLVM)),)
XDEV_EXT_MECH_UBSAN ?= 1
else
XDEV_EXT_MECH_UBSAN ?= 0
endif

ifeq ($(XDEV_EXT_MECH_UBSAN),1)
CFLAGS += -fsanitize=undefined -fno-sanitize-recover=undefined
LDFLAGS += -fsanitize=undefined
endif

include ../../lib.mk

.PHONY: run
run: run_tests
