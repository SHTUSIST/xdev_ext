# SPDX-License-Identifier: GPL-2.0
# The logical source view also supports standalone host execution:
# python3 tools/run.py --cwd tests/core/memory/umem make run
# Registry/provider code and lifecycle helpers are real; OS/pins are shims.

TEST_GEN_PROGS := xdev_ext_umem_registry_test xdev_ext_umem_account_test \
	xdev_ext_umem_custody_test

CFLAGS += -std=gnu11 -O2 -g -Wall -Wextra -Werror -Wno-sign-compare -pthread \
	-I$(CURDIR)/fake_include -I$(CURDIR)
LDLIBS += -pthread

LOCAL_HDRS += $(abspath xdev_ext_umem_kernel_shim.h)
LOCAL_HDRS += $(abspath xdev_ext_umem_mech_shim.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_umem.c)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_life_pool.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_lifecycle.h)

ifneq ($(wildcard ../lib.mk),)
include ../lib.mk
else
.PHONY: all run_tests clean
all: $(TEST_GEN_PROGS)
$(TEST_GEN_PROGS): %: %.c $(LOCAL_HDRS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)
run_tests: all
	@set -e; for test in $(TEST_GEN_PROGS); do ./$$test; done
clean:
	rm -f $(TEST_GEN_PROGS)
endif

.PHONY: run
run: run_tests
