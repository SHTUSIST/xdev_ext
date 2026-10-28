# SPDX-License-Identifier: GPL-2.0
#
# The eval session guest run: its independent oracle and the prebuilt
# binaries the KVM image carries to /opt/xdev_ext/eval.
#   make guest GUEST_OUT=DIR CC=... CLANG=...   build every guest file into DIR
#   make check                                  host tests of the oracle
# The guest itself compiles nothing.  chain_bench needs libbpf >= 1.0,
# libelf and zlib (LIBBPF_CFLAGS/LIBBPF_LIBS as in ../chains/Makefile).
CC ?= cc
CLANG ?= clang
PYTHON ?= python3
BUILD ?= .build
GUEST_OUT ?= $(BUILD)/guest
KERNEL := ../../../kernel
GUEST_SH := $(KERNEL)/tools/testing/selftests/xdev_ext_integration/xdev_ext_eval_session_guest.sh
CFLAGS ?= -O2 -g
LIBBPF_CFLAGS ?=
LIBBPF_LIBS ?= -lbpf
WARN := -std=gnu11 -Wall -Wextra -Werror
OUT = $(abspath $(GUEST_OUT))

.PHONY: oracle guest check clean
oracle: $(BUILD)/eval_session_oracle

$(BUILD):
	mkdir -p $@

$(BUILD)/eval_session_oracle: eval_session_oracle.c | $(BUILD)
	$(CC) $(CFLAGS) $(WARN) $< -o $@ -lz

# Files of /opt/xdev_ext/eval in the guest image.
guest:
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(WARN) eval_session_oracle.c -o $(OUT)/eval_session_oracle -lz
	$(CC) $(CFLAGS) $(WARN) ../nvme_gpu/session_nvme_ce.c $(KERNEL)/tools/xdev_ext_gpu_identity.c \
		-o $(OUT)/session_nvme_ce -ldl
	$(CC) $(CFLAGS) $(WARN) $(LIBBPF_CFLAGS) -msse4.2 ../gpu_nic/session_gpu_nic.c \
		$(KERNEL)/tools/xdev_ext_xsk_redirect.c $(KERNEL)/tools/xdev_ext_gpu_identity.c \
		-o $(OUT)/session_gpu_nic $(LIBBPF_LIBS) -lelf -lz -ldl
	# Nested targets omit some transitive headers; rebuild both for each guest image.
	$(MAKE) -B -C ../chains BUILD=$(OUT)/chains CC="$(CC)" CLANG="$(CLANG)" bench bpf
	cp $(OUT)/chains/chain_bench $(OUT)/chains/chain_plan.bpf.o $(OUT)/
	cp $(GUEST_SH) $(OUT)/

check: | $(BUILD)
	$(CC) $(CFLAGS) $(WARN) test_fd_check.c -o $(BUILD)/test_fd_check
	$(BUILD)/test_fd_check
	$(PYTHON) test_oracle.py -v
	$(PYTHON) test_cleanup.py -v
	$(PYTHON) test_rebuild.py -v
	$(PYTHON) $(KERNEL)/tools/testing/selftests/xdev_ext_integration/xdev_ext_eval_session_harness_test.py -v
	$(PYTHON) $(KERNEL)/tools/testing/selftests/xdev_ext_integration/xdev_ext_eval_session_validate_test.py -v

clean:
	rm -rf $(BUILD)
