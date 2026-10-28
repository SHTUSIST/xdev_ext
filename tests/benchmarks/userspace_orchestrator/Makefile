# SPDX-License-Identifier: GPL-2.0
#
# uo_bench, the user-space shared-region baseline, and its host tests.
#   make bench			no CUDA: the GPU chains refuse (exit 4)
#   make bench UO_CUDA=1		cuMemHostRegister and async copies through
#				dlopen("libcuda.so.1"); no CUDA SDK is needed
#   make check			host tests only: no device, no root, no network
CC ?= cc
PYTHON ?= python3
BUILD ?= .build
KERNEL := ../../../kernel
UO_CUDA ?= 0
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror -D_FILE_OFFSET_BITS=64
LDLIBS += -lelf -lz -ldl
LIBBPF_CFLAGS ?=
LIBBPF_LIBS ?= -lbpf
ifeq ($(UO_CUDA),1)
CFLAGS += -DUO_CUDA
endif

HEADERS := ../common/cpu_timer.h uo_core.h uo_native_trace.h ../common/native_process.h ../chains/chain_json.h ../chains/chain_spec.h ../chains/chain_check.h \
	../chains/chain_crc.h ../chains/chain_timing.h \
	../chains/chain_oracle.h ../chains/chain_nxp.h ../chains/chain_cuda.h \
	../chains/uring_min.h $(KERNEL)/tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h

.PHONY: all bench test check clean
all: bench

bench: $(BUILD)/uo_bench
test: $(BUILD)/test_uo_core

$(BUILD):
	mkdir -p $@

# The redirect helper uses libbpf only for the XDP program and map.
$(BUILD)/uo_bench: uo_bench.c $(KERNEL)/tools/xdev_ext_xsk_redirect.c $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) uo_bench.c $(KERNEL)/tools/xdev_ext_xsk_redirect.c \
		-o $@ $(LDFLAGS) $(LIBBPF_LIBS) $(LDLIBS)

$(BUILD)/test_uo_core: test_uo_core.c $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@

check: test
	$(BUILD)/test_uo_core
	$(PYTHON) test_run.py -v

clean:
	rm -rf $(BUILD)
