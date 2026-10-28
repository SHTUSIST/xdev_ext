# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := xdev_ext_umem_registry_test xdev_ext_umem_account_test \
	xdev_ext_umem_custody_test

CFLAGS += -std=gnu11 -O2 -g -Wall -Wextra -Werror -Wno-sign-compare -pthread \
	-I$(CURDIR)/fake_include -I$(CURDIR)
LDLIBS += -pthread

LOCAL_HDRS += $(abspath xdev_ext_umem_kernel_shim.h)
LOCAL_HDRS += $(abspath xdev_ext_umem_mech_shim.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_umem.c)

include ../lib.mk

.PHONY: run
run: run_tests
