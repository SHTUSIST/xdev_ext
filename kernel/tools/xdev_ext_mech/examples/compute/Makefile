# SPDX-License-Identifier: GPL-2.0
#
# The BPF compute examples (README.md).  Clang is used only as the BPF
# bytecode compiler.
#	make -C tools/xdev_ext_mech/examples/compute VMLINUX_DIR=<dir> CLANG=<clang> OUT=<dir>
# VMLINUX_DIR holds the target kernel's vmlinux.h, for example the BUILD_DIR
# of tools/xdev_ext_mech.  Each CRC32C example is built twice: bytewise and
# slice-by-8.

examples_dir := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
CLANG ?= clang
OUT ?= $(examples_dir)/.build
VMLINUX_DIR ?= $(examples_dir)/../../.xdev_ext-mech-build
BPF_ARCH ?= x86
BPF_CFLAGS ?= -O2 -g -Wall -Wextra -Werror -target bpf -D__TARGET_ARCH_$(BPF_ARCH)
BPF_INCLUDES := -I$(VMLINUX_DIR) -I$(examples_dir)/../.. -I$(examples_dir)

COMMON := compute_example.h ../../xdev_ext_mech_prog.h ../../xdev_ext_mech_kfunc.h \
	$(VMLINUX_DIR)/vmlinux.h
CRC := crc32c.h crc32c_table.h

OBJECTS := $(addprefix $(OUT)/,crc32c_check_bytewise.bpf.o crc32c_check_slice8.bpf.o \
	crc32c_append_bytewise.bpf.o crc32c_append_slice8.bpf.o xxh64_append.bpf.o \
	parse_check.bpf.o sha256_append.bpf.o)

all: $(OBJECTS)

$(OUT):
	mkdir -p $@

$(OUT)/%_bytewise.bpf.o: %.bpf.c $(COMMON) $(CRC) | $(OUT)
	$(CLANG) $(BPF_CFLAGS) -DEX_CRC32C_SLICE8=0 $(BPF_INCLUDES) -c $< -o $@

$(OUT)/%_slice8.bpf.o: %.bpf.c $(COMMON) $(CRC) | $(OUT)
	$(CLANG) $(BPF_CFLAGS) -DEX_CRC32C_SLICE8=1 $(BPF_INCLUDES) -c $< -o $@

$(OUT)/xxh64_append.bpf.o: xxh64_append.bpf.c xxh64.h $(COMMON) | $(OUT)
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

$(OUT)/parse_check.bpf.o: parse_check.bpf.c parse.h $(COMMON) | $(OUT)
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

$(OUT)/sha256_append.bpf.o: sha256_append.bpf.c sha256.h $(COMMON) | $(OUT)
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

# Regenerate the CRC32C tables (checked in; the host tests compare them).
crc32c_table.h: gen_crc32c_table.py
	python3 $< $@

clean:
	rm -rf $(OUT)

.PHONY: all clean
