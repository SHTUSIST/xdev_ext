# SPDX-License-Identifier: MIT
# Standalone overlay build: no kernel selftest lib.mk or liburing installation.
CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2 -g
STRICT_FLAGS := -std=gnu11 -Wall -Wextra -Werror
LDLIBS := -lz
UAPI := ../../kernel/include/uapi/linux/io_uring.h
CORE := ../../kernel/io_uring/iaa/xdev_ext_iaa_core.h ../../kernel/xdev_ext_frame_sm.h
MINI := ../../kernel/tools/include/io_uring/mini_liburing.h
.PHONY: all check preflight run clean
all: test_iaa_unified_ops test_contract test_lifetime
test_iaa_unified_ops: test_iaa_unified_ops.c $(UAPI) $(MINI)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(STRICT_FLAGS) $< -o $@ $(LDLIBS)
test_contract: test_contract.c test_iaa_unified_ops.c $(UAPI) $(MINI) $(CORE)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(STRICT_FLAGS) $< -o $@ $(LDLIBS)
test_lifetime: test_lifetime.c test_iaa_unified_ops.c $(UAPI) $(MINI)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(STRICT_FLAGS) $< -o $@ $(LDLIBS)
check: test_contract test_lifetime
	./test_contract
	./test_lifetime
preflight: test_iaa_unified_ops
	./test_iaa_unified_ops --preflight
run: test_iaa_unified_ops
	./test_iaa_unified_ops
clean:
	rm -f test_iaa_unified_ops test_contract test_lifetime
