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
PAHOLE ?= pahole
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
BUILD_DIR ?= .xdev_ext-mech-build

CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror
LDLIBS += -lbpf -lelf -lz -ldl

BPF_ARCH ?= x86
BPF_CFLAGS ?= -O2 -g -Wall -Wextra -Werror -target bpf \
	-D__TARGET_ARCH_$(BPF_ARCH)

BPF_NAMES := nvme_s0 nxp_mech nxp_reliable ce_plan dma_plan socket_sink net_peer cpu_plan
BPF_OBJECTS := $(BPF_NAMES:%=$(BUILD_DIR)/%.bpf.o)
VMLINUX_H := $(BUILD_DIR)/vmlinux.h
CTL := $(BUILD_DIR)/xdev_ext_mech_ctl
PEER_CTL := $(BUILD_DIR)/xdev_ext_peer_chain

.DEFAULT_GOAL := all

all: $(CTL) $(PEER_CTL) $(BPF_OBJECTS)

ctl: $(CTL)

bpf: $(BPF_OBJECTS)

check-cpu-bpf:
	CC="$(CC)" CLANG="$(CLANG)" python3 ../testing/selftests/xdev_ext_mech_tools/xdev_ext_cpu_bpf_test.py

# Requires io_uring/xdev_ext_mech_ops.o and net/xdp/xsk.o from an actual
# SOCKET-off Kbuild with DWARF. This is separate from the fast CPU ABI check.
check-optional-btf:
	@test -n "$(KBUILD_OUTPUT)" || { echo "set KBUILD_OUTPUT to the prepared O= directory"; exit 1; }
	python3 ../testing/selftests/xdev_ext_mech_tools/xdev_ext_optional_btf_test.py \
		--kbuild-output "$(KBUILD_OUTPUT)" --results "$(abspath $(BUILD_DIR))/optional-btf" \
		--pahole "$(PAHOLE)" --bpftool "$(BPFTOOL)" --clang "$(CLANG)"

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

$(BUILD_DIR)/cpu_plan.bpf.o: xdev_ext_mech_cpu_abi.h

$(CTL): xdev_ext_mech_ctl.c xdev_ext_mech_ctl_fallback.h xdev_ext_mech_ctl_core.h xdev_ext_mech_prog.h xdev_ext_mech_cuda.h \
		../xdev_ext_gpu_identity.c ../include/xdev_ext_gpu_identity.h \
		../xdev_ext_xsk_redirect.c ../include/xdev_ext_xsk_redirect.h \
		../include/xdev_ext_xsk_redirect_prog.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) xdev_ext_mech_ctl.c ../xdev_ext_xsk_redirect.c ../xdev_ext_gpu_identity.c -o $@ \
		$(LDFLAGS) $(LDLIBS)

# The thin session library (lib/SPEC.md); not part of all.
lib:
	$(MAKE) -C lib BUILD_DIR=$(abspath $(BUILD_DIR))/lib CC="$(CC)"

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all bpf check-cpu-bpf check-optional-btf clean ctl lib

$(PEER_CTL): xdev_ext_peer_chain.c xdev_ext_mech_cuda.h ../../include/uapi/linux/xdev_ext_mech.h ../../include/uapi/linux/xdev_ext_peer.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)
