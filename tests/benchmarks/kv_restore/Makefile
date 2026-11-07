# SPDX-License-Identifier: GPL-2.0
#
# K-KV restore: run from the source view (tests/eval/kv_restore).
#   make check                 host tests (no device, no timing)
#   make driver                kv_restore + nvmeof_worker (libbpf >= 1.0)
#   make bpf VMLINUX_BTF=...   kv_nvme_read.bpf.o for the target kernel's BTF
# A host check, a build or a bytecode object is not device evidence.

CC ?= cc
CLANG ?= clang
BPFTOOL ?= bpftool
PYTHON ?= python3
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
BPF_ARCH ?= x86
BUILD ?= build
KERNEL := ../../../kernel
MECH := $(KERNEL)/tools/xdev_ext_mech
HOST := $(KERNEL)/tools/testing/selftests/xdev_ext_mech/cref/host
CFLAGS ?= -O2 -g
WARN = -std=gnu11 -Wall -Wextra -Werror
SAN = -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all

.PHONY: all check driver bpf clean
all: driver

$(BUILD):
	mkdir -p $@

$(BUILD)/test_kv_plan: test_kv_plan.c kv_plan.h | $(BUILD)
	$(CC) $(WARN) $(SAN) -I$(KERNEL) $< -o $@

$(BUILD)/test_kv_bpf: test_kv_bpf.c kv_nvme_read.bpf.c | $(BUILD)
	$(CC) $(WARN) $(SAN) -I$(HOST) -I$(KERNEL) -I$(MECH) -I. $< -o $@

$(BUILD)/kv_plan_cli: kv_plan_cli.c kv_plan.h | $(BUILD)
	$(CC) $(WARN) $(CFLAGS) $< -o $@

$(BUILD)/nvmeof_worker: nvmeof_worker.c kv_plan.h | $(BUILD)
	$(CC) $(WARN) $(CFLAGS) $< -o $@ -ldl

$(BUILD)/lib/libxdev_ext.a: | $(BUILD)
	$(MAKE) -C $(MECH)/lib BUILD_DIR=$(abspath $(BUILD))/lib CC=$(CC)

$(BUILD)/kv_restore: kv_restore.c kv_plan.h $(BUILD)/lib/libxdev_ext.a | $(BUILD)
	$(CC) $(WARN) $(CFLAGS) $< -o $@ $(BUILD)/lib/libxdev_ext.a -lbpf -lelf -lz -ldl

driver: $(BUILD)/kv_restore $(BUILD)/nvmeof_worker $(BUILD)/kv_plan_cli

check: $(BUILD)/test_kv_plan $(BUILD)/test_kv_bpf
	$(BUILD)/test_kv_plan
	$(BUILD)/test_kv_bpf
	$(PYTHON) -m unittest discover -s . -p 'test_*.py'

bpf: $(BUILD)/kv_nvme_read.bpf.o
$(BUILD)/vmlinux.h: $(VMLINUX_BTF) | $(BUILD)
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@.tmp
	mv $@.tmp $@
$(BUILD)/kv_nvme_read.bpf.o: kv_nvme_read.bpf.c $(BUILD)/vmlinux.h
	$(CLANG) -O2 -g -Wall -Wextra -Werror -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
		-I$(BUILD) -I$(MECH) -c $< -o $@

clean:
	rm -rf $(BUILD) __pycache__
