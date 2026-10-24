# SPDX-License-Identifier: GPL-2.0
#
# chain_bench (session and staged arms), its IAA plan object and the host
# tests.  Builds land in BUILD (default .build, ignored by git).  The guest
# build runs `make BUILD=<dir> bench bpf` against the guest's kernel tree;
# chain_bench links libbpf, libelf, zlib and libdl (CUDA is dlopen()ed).
#   make check	host tests only: no device, no root, no network
CC ?= cc
CLANG ?= clang
PYTHON ?= python3
BUILD ?= .build
KERNEL := ../../../kernel
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror -D_FILE_OFFSET_BITS=64
# A libbpf >= 1.0 (bpf_map__set_autocreate); point these at another one
# when the system's is older, e.g. one built from kernel/tools/lib/bpf.
LIBBPF_CFLAGS ?=
LIBBPF_LIBS ?= -lbpf
LDLIBS += $(LIBBPF_LIBS) -lelf -lz -ldl
BPF_ARCH ?= x86
MULTIARCH ?= $(shell $(CC) -print-multiarch 2>/dev/null)
BPF_CFLAGS ?= -O2 -g -Wall -Wextra -Werror -target bpf -D__TARGET_ARCH_$(BPF_ARCH)

HEADERS := ../common/native_process.h chain_json.h chain_spec.h chain_check.h chain_crc.h chain_timing.h chain_oracle.h chain_bench.h chain_cuda.h chain_nxp.h \
	uring_min.h $(KERNEL)/tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h
SOURCES := chain_bench.c chain_session.c chain_staged.c \
	$(KERNEL)/tools/xdev_ext_xsk_redirect.c $(KERNEL)/tools/xdev_ext_gpu_identity.c

.PHONY: all bench bpf test check clean
all: bench bpf

bench: $(BUILD)/chain_bench
bpf: $(BUILD)/chain_plan.bpf.o
test: $(BUILD)/test_chain_spec

$(BUILD):
	mkdir -p $@

$(BUILD)/chain_bench: $(SOURCES) $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(SOURCES) -o $@ $(LDFLAGS) $(LDLIBS)

$(BUILD)/chain_plan.bpf.o: chain_plan.bpf.c | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL) -idirafter /usr/include/$(MULTIARCH) -c $< -o $@

$(BUILD)/test_chain_spec: test_chain_spec.c $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@

check: test
	$(BUILD)/test_chain_spec
	$(PYTHON) test_run.py -v

clean:
	rm -rf $(BUILD)
