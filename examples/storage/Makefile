# SPDX-License-Identifier: GPL-2.0
CLANG ?= clang
OUT ?= .build
BPF_ARCH ?= x86
VMLINUX_DIR ?= ../../.xdev_ext-mech-build
BPF_HEADERS ?= ../..
.PHONY: all
all: $(OUT)/nvme_blocktable.bpf.o $(OUT)/block_rw.bpf.o
$(OUT):
	mkdir -p $@
$(OUT)/nvme_blocktable.bpf.o: nvme_blocktable.bpf.c nvme_blocktable.h $(VMLINUX_DIR)/vmlinux.h $(BPF_HEADERS)/xdev_ext_mech_prog.h $(BPF_HEADERS)/xdev_ext_mech_kfunc.h | $(OUT)
	$(CLANG) -O2 -g -Wall -Wextra -Werror -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -I$(VMLINUX_DIR) -I$(BPF_HEADERS) -c $< -o $@
$(OUT)/block_rw.bpf.o: block_rw.bpf.c $(VMLINUX_DIR)/vmlinux.h $(BPF_HEADERS)/xdev_ext_mech_prog.h $(BPF_HEADERS)/xdev_ext_mech_kfunc.h | $(OUT)
	$(CLANG) -O2 -g -Wall -Wextra -Werror -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -I$(VMLINUX_DIR) -I$(BPF_HEADERS) -c $< -o $@
