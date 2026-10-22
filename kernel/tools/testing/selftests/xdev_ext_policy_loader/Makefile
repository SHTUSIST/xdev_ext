# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := xdev_ext_reference_policy_core_test
TEST_PROGS := xdev_ext_reference_policy_source_test.py

ifeq ($(OUTPUT),)
OUTPUT := $(CURDIR)
endif

CFLAGS += -std=gnu11 -O2 -g -Wall -Wextra -Werror
LOCAL_HDRS += $(abspath ../../../xdev_ext_reference_policy_core.h)

include ../lib.mk

.PHONY: run sanitize
run: run_tests

sanitize:
	@set -eu; \
	bin="$(OUTPUT)/.xdev_ext_reference_policy_core_test_sanitize"; \
	trap 'rm -f "$$bin"' EXIT; \
	$(CC) $(CFLAGS) -O1 \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		xdev_ext_reference_policy_core_test.c $(LDFLAGS) \
		-fsanitize=address,undefined -o "$$bin"; \
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 "$$bin"
