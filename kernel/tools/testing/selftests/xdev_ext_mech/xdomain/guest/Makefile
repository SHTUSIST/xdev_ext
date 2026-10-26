# SPDX-License-Identifier: GPL-2.0
here := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
KERNEL_SRC ?= $(abspath $(here)/../../../../../..)
OUT ?= $(here)/build
TOOLS ?= $(OUT)/tools
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
CLANG ?= clang
BPFTOOL ?= bpftool
HOSTCC ?= gcc
LDLIBS ?= -lbpf -lelf -lz
BPF_CFLAGS ?= -O2 -g -Wall -Wextra -Werror -target bpf -mcpu=v3 -D__TARGET_ARCH_x86

all:
	mkdir -p $(OUT)
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c >$(OUT)/vmlinux.h
	$(HOSTCC) -O2 -g -Wall -Wextra -Werror $(here)/load.c -o $(OUT)/load $(LDFLAGS) $(LDLIBS)
	python3 $(here)/generate.py $(OUT)
	@set -eu; for c in $(OUT)/*.bpf.c; do \
		$(CLANG) $(BPF_CFLAGS) -I$(OUT) -I$(KERNEL_SRC)/tools/xdev_ext_mech -c $$c -o $${c%.c}.o; \
	done
	$(CLANG) $(BPF_CFLAGS) -I$(OUT) -I$(KERNEL_SRC)/tools/xdev_ext_mech \
		-c $(KERNEL_SRC)/tools/xdev_ext_mech/xdomain_peer.bpf.c -o $(OUT)/xdomain_peer.bpf.o

	$(CLANG) $(BPF_CFLAGS) -I$(OUT) -I$(KERNEL_SRC)/tools/xdev_ext_mech \
		-c $(KERNEL_SRC)/tools/xdev_ext_mech/xdomain_check.bpf.c -o $(OUT)/xdomain_check.bpf.o

.PHONY: all
