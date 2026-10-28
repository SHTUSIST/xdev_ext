# SPDX-License-Identifier: GPL-2.0
CC ?= cc
CLANG ?= clang
BPFTOOL ?= bpftool
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
BPF_ARCH ?= x86
BUILD_DIR ?= .build
ROOT := ../../../..
KERNEL := $(ROOT)/kernel
MECH := $(KERNEL)/tools/xdev_ext_mech
HOST := $(KERNEL)/tools/testing/selftests/xdev_ext_mech/cref/host
MV := $(abspath ..)
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror
CPPFLAGS += -I$(HOST) -I$(KERNEL) -I$(MECH)

.PHONY: check baseline-red bpf clean
check: $(BUILD_DIR)/reverse $(BUILD_DIR)/gray
	$(BUILD_DIR)/reverse reverse
	$(BUILD_DIR)/gray gray

# Explicit pre-feature comparison, never used by check or guest acceptance.
baseline-red: $(BUILD_DIR)/baseline
	$(BUILD_DIR)/baseline reverse

$(BUILD_DIR):
	mkdir -p $@
$(BUILD_DIR)/baseline: bpf_body.c $(MECH)/nvme_s0.bpf.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DMV_BASELINE $< -o $@
$(BUILD_DIR)/reverse: bpf_body.c $(MV)/nvme_reverse.bpf.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DMV_BPF_SOURCE='"$(MV)/nvme_reverse.bpf.c"' $< -o $@
$(BUILD_DIR)/gray: bpf_body.c $(MV)/nvme_gray.bpf.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DMV_BPF_SOURCE='"$(MV)/nvme_gray.bpf.c"' $< -o $@

# Real BPF compilation uses target-kernel BTF and real libbpf headers.
# A successful host check does not satisfy this target or a verifier run.
bpf: $(BUILD_DIR)/nvme_reverse.bpf.o $(BUILD_DIR)/nvme_gray.bpf.o
$(BUILD_DIR)/vmlinux.h: $(VMLINUX_BTF) | $(BUILD_DIR)
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@.tmp
	mv $@.tmp $@
$(BUILD_DIR)/%.bpf.o: $(MV)/%.bpf.c $(BUILD_DIR)/vmlinux.h
	$(CLANG) -O2 -g -Wall -Wextra -Werror -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
		-I$(BUILD_DIR) -I$(MECH) -c $< -o $@
	readelf -h $@ | sed -n '/Machine:/p'
clean:
	rm -rf $(BUILD_DIR)
