# SPDX-License-Identifier: GPL-2.0
#
# E4 Thunderbolt VRAM<->VRAM tools; run from the source view (tests/eval/xdomain_gpu).
#   make check     host tests (no GPU, NCCL or link; numbers are not results)
#   make tools     tcp_cuda and nccl_pingpong (CUDA and NCCL are opened at run time)
#   make xdomain   xdomain_gpu (libxdev_ext; libbpf >= 1.0)
# A host check or a build is not device evidence.

CC ?= cc
PYTHON ?= python3
BUILD ?= build
KERNEL := ../../../kernel
MECH := $(KERNEL)/tools/xdev_ext_mech
CFLAGS ?= -O2 -g
WARN = -std=gnu11 -Wall -Wextra -Werror
SAN = -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all

.PHONY: all check tools xdomain clean
all: tools

$(BUILD):
	mkdir -p $@

$(BUILD)/test_xdg_core: test_xdg_core.c xdg_core.h | $(BUILD)
	$(CC) $(WARN) $(SAN) $< -o $@

$(BUILD)/tcp_cuda: tcp_cuda.c xdg_core.h xdg_gpu.h xdg_net.h | $(BUILD)
	$(CC) $(WARN) $(CFLAGS) $< -o $@ -ldl

$(BUILD)/nccl_pingpong: nccl_pingpong.c xdg_core.h xdg_gpu.h xdg_net.h | $(BUILD)
	$(CC) $(WARN) $(CFLAGS) $< -o $@ -ldl

$(BUILD)/lib/libxdev_ext.a: | $(BUILD)
	$(MAKE) -C $(MECH)/lib BUILD_DIR=$(abspath $(BUILD))/lib CC=$(CC)

$(BUILD)/xdomain_gpu: xdomain_gpu.c xdg_core.h xdg_net.h $(BUILD)/lib/libxdev_ext.a | $(BUILD)
	$(CC) $(WARN) $(CFLAGS) $< -o $@ $(BUILD)/lib/libxdev_ext.a -lbpf -lelf -lz -ldl

tools: $(BUILD)/tcp_cuda $(BUILD)/nccl_pingpong
xdomain: $(BUILD)/xdomain_gpu

check: $(BUILD)/test_xdg_core
	$(BUILD)/test_xdg_core
	$(PYTHON) -m unittest discover -s . -p 'test_*.py'

clean:
	rm -rf $(BUILD) __pycache__
