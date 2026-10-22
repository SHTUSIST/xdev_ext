# SPDX-License-Identifier: GPL-2.0
#
# The mechanism control tool and the mechanism BPF objects.  The KVM harness
# runs
#	make -C tools/xdev_ext_mech BUILD_DIR=<dir> VMLINUX_BTF=<vmlinux> \
#		CC=<gcc> CLANG=<clang> BPFTOOL=bpftool all
# and installs BUILD_DIR/xdev_ext_mech_ctl (dynamically linked) and every
# BUILD_DIR/*.bpf.o.  The BPF objects need the target kernel's BTF:
# vmlinux.h is generated from VMLINUX_BTF.

CC ?= gcc
CLANG ?= clang
BPFTOOL ?= bpftool
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
BUILD_DIR ?= .xdev_ext-mech-build

CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror
LDLIBS += -lbpf -lelf -lz -ldl

BPF_ARCH ?= x86
BPF_CFLAGS ?= -O2 -g -Wall -Wextra -Werror -target bpf \
	-D__TARGET_ARCH_$(BPF_ARCH)

BPF_NAMES := nvme_s0 nxp_mech nxp_reliable ce_plan dma_plan socket_sink
BPF_OBJECTS := $(BPF_NAMES:%=$(BUILD_DIR)/%.bpf.o)
VMLINUX_H := $(BUILD_DIR)/vmlinux.h
CTL := $(BUILD_DIR)/xdev_ext_mech_ctl

.DEFAULT_GOAL := all

all: $(CTL) $(BPF_OBJECTS)

ctl: $(CTL)

bpf: $(BPF_OBJECTS)

$(BUILD_DIR):
	mkdir -p $@

$(VMLINUX_H): $(VMLINUX_BTF) | $(BUILD_DIR)
	@set -eu; \
	temporary="$@.tmp"; \
	trap 'rm -f "$$temporary"' EXIT; \
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c >"$$temporary"; \
	mv -f "$$temporary" "$@"

$(BUILD_DIR)/%.bpf.o: %.bpf.c xdev_ext_mech_prog.h xdev_ext_mech_kfunc.h ../../include/linux/xdev_ext_mech_reliable_core.h $(VMLINUX_H) \
		| $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -I$(BUILD_DIR) -c $< -o $@

$(CTL): xdev_ext_mech_ctl.c xdev_ext_mech_ctl_core.h xdev_ext_mech_prog.h xdev_ext_mech_cuda.h \
		../xdev_ext_gpu_identity.c ../include/xdev_ext_gpu_identity.h \
		../xdev_ext_xsk_redirect.c ../include/xdev_ext_xsk_redirect.h \
		../include/xdev_ext_xsk_redirect_prog.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) xdev_ext_mech_ctl.c ../xdev_ext_xsk_redirect.c ../xdev_ext_gpu_identity.c -o $@ \
		$(LDFLAGS) $(LDLIBS)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all bpf clean ctl
