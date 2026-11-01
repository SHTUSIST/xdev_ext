# SPDX-License-Identifier: GPL-2.0
HERE := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ROOT := $(abspath $(HERE)/../../../..)
KERNEL_SRC ?= $(ROOT)
UAPI ?= $(if $(wildcard $(KERNEL_SRC)/src/core/include/uapi),$(KERNEL_SRC)/src/core/include/uapi,$(KERNEL_SRC)/include/uapi)
LIBBPF_INCLUDE ?= /usr/include
LIBBPF_HELPER_INCLUDE ?= $(LIBBPF_INCLUDE)/bpf
LIBBPF_EXTRA_LIBS ?=
LIBBPF_A ?= /usr/lib/$(shell gcc -print-multiarch)/libbpf.a
OUT ?= $(HERE)/build
CC := gcc
CLANG ?= clang
MULTIARCH := $(shell $(CC) -print-multiarch)
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall -Werror -I$(UAPI) -I$(LIBBPF_INCLUDE) -I$(LIBBPF_HELPER_INCLUDE) -idirafter /usr/include/$(MULTIARCH)
all: $(OUT)/token_guest $(OUT)/private_a.bpf.o $(OUT)/private_b.bpf.o $(OUT)/bad_helper.bpf.o
$(OUT):
	mkdir -p $@
$(OUT)/token_guest: $(HERE)/token_guest.c | $(OUT)
	$(CC) -O2 -g -Wall -Wextra -Werror -I$(UAPI) -I$(LIBBPF_INCLUDE) $< $(LDFLAGS) $(LIBBPF_A) -lelf -lz $(LIBBPF_EXTRA_LIBS) -o $@
$(OUT)/private_a.bpf.o: $(HERE)/private_cpu.bpf.c | $(OUT)
	$(CLANG) $(BPF_CFLAGS) -DINSTANCE=1 -c $< -o $@
$(OUT)/private_b.bpf.o: $(HERE)/private_cpu.bpf.c | $(OUT)
	$(CLANG) $(BPF_CFLAGS) -DINSTANCE=2 -c $< -o $@
$(OUT)/bad_helper.bpf.o: $(HERE)/private_cpu.bpf.c | $(OUT)
	$(CLANG) $(BPF_CFLAGS) -DBAD_HELPER -c $< -o $@
.PHONY: all
