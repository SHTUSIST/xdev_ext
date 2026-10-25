# SPDX-License-Identifier: GPL-2.0
# Guest BPF objects of the compute KVM run. Clang is used only as the BPF
# bytecode compiler; nothing here is a host or kernel build.
guest_dir := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
KERNEL_SRC ?= $(abspath $(guest_dir)/../../../../../..)
OUT ?= $(guest_dir)/build
CLANG ?= /usr/bin/clang-21
HOSTCC ?= cc
LIBBPF_INCLUDE ?= /usr/include
MULTIARCH ?= $(shell $(HOSTCC) -print-multiarch)
BPF_CFLAGS ?= -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86
BPF_INCLUDES := -I$(LIBBPF_INCLUDE) -I$(KERNEL_SRC)/tools/include/uapi \
	-I$(KERNEL_SRC)/include/uapi -I$(KERNEL_SRC)/tools/testing/selftests/bpf/progs
ifneq ($(MULTIARCH),)
BPF_INCLUDES += -idirafter /usr/include/$(MULTIARCH)
endif
OBJECTS := $(OUT)/compute_test.bpf.o $(OUT)/compute_old_layout.bpf.o

all: $(OBJECTS)

$(OUT):
	mkdir -p $@

$(OUT)/%.bpf.o: $(guest_dir)/%.bpf.c $(KERNEL_SRC)/include/uapi/linux/xdev_ext_mech.h \
		$(KERNEL_SRC)/tools/testing/selftests/bpf/progs/xdev_ext_mech_common.h | $(OUT)
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

.PHONY: all
