# SPDX-License-Identifier: GPL-2.0
#
# setup_cost needs libbpf development files.  CUDA_ROOT=<SDK> adds the
# cudaHostRegister and cuFileBufRegister measures.  `make check` runs the
# host tests; it times nothing and loads no BPF program.

CC ?= cc
PYTHON ?= python3
BUILD ?= build
KERNEL := ../../../kernel
CFLAGS ?= -O2 -g
WARN = -std=gnu11 -Wall -Wextra -Werror
# The project's uapi bpf.h (verified_insns) and if_xdp.h before the system's.
CPPFLAGS += -I$(KERNEL)/tools/include/uapi
CUDA_ROOT ?=
ifneq ($(CUDA_ROOT),)
CUDA_CPPFLAGS = -DSETUP_COST_HAVE_CUDA -I$(CUDA_ROOT)/include
CUDA_LIBS = -L$(CUDA_ROOT)/lib64 -Wl,-rpath,$(CUDA_ROOT)/lib64 -lcudart -lcufile
endif

.PHONY: all check clean
all: $(BUILD)/setup_cost

$(BUILD):
	mkdir -p $@

$(BUILD)/setup_cost: setup_cost.c setup_cost_core.h Makefile | $(BUILD)
	$(CC) $(CPPFLAGS) $(CUDA_CPPFLAGS) $(CFLAGS) $(WARN) -o $@ $< -lbpf $(CUDA_LIBS)

$(BUILD)/test_setup_cost_core: test_setup_cost_core.c setup_cost_core.h Makefile | $(BUILD)
	$(CC) -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all $(WARN) -o $@ $<

HAVE_LIBBPF := $(shell pkg-config --exists libbpf 2>/dev/null && echo 1)

check: $(BUILD)/test_setup_cost_core $(if $(HAVE_LIBBPF),$(BUILD)/setup_cost)
	$(BUILD)/test_setup_cost_core
	SETUP_COST_BUILD=$(abspath $(BUILD)) $(PYTHON) test_setup_cost.py

clean:
	rm -rf $(BUILD) __pycache__
