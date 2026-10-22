# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := xdev_ext_binding_test

LOCAL_HDRS += $(abspath ../../../../include/linux/xdev_ext_binding.h)
LOCAL_HDRS += $(abspath ../../../../include/uapi/linux/xdev_ext_binding.h)

CFLAGS += -std=gnu11 -O2 -g -Wall -Wextra -Werror $(KHDR_INCLUDES)

# Sanitizer runtimes belong to the build host, so do not inject them into a
# cross or LLVM build.  Native GCC remains strict and sanitized by default.
ifeq ($(strip $(CROSS_COMPILE)$(LLVM)),)
XDEV_EXT_BINDING_UBSAN ?= 1
else
XDEV_EXT_BINDING_UBSAN ?= 0
endif

ifeq ($(XDEV_EXT_BINDING_UBSAN),1)
CFLAGS += -fsanitize=undefined -fno-sanitize-recover=undefined
LDFLAGS += -fsanitize=undefined
endif

include ../lib.mk

.PHONY: run
run: run_tests
