# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := xdev_ext_iaa_core_test

LOCAL_HDRS += $(abspath ../../../../io_uring/iaa/xdev_ext_iaa_core.h)
LOCAL_HDRS += $(abspath ../../../../xdev_ext_frame_sm.h)

CFLAGS += -std=gnu11 -O2 -g -Wall -Wextra -Werror -I../../../.. \
	  $(KHDR_INCLUDES)

ifeq ($(strip $(CROSS_COMPILE)$(LLVM)),)
XDEV_EXT_IAA_UBSAN ?= 1
else
XDEV_EXT_IAA_UBSAN ?= 0
endif

ifeq ($(XDEV_EXT_IAA_UBSAN),1)
CFLAGS += -fsanitize=undefined -fno-sanitize-recover=undefined
LDFLAGS += -fsanitize=undefined
endif

include ../lib.mk

.PHONY: run
run: run_tests
