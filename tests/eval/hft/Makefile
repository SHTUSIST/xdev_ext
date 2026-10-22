# SPDX-License-Identifier: GPL-2.0
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Werror -pthread
ENABLE_URING ?= 0
ENABLE_SESSION ?= 0
BUILD_DIR ?= .build
SOURCES = hft_replay.c hft_posix.c hft_uring.c hft_session.c
ifeq ($(ENABLE_URING),1)
CPPFLAGS += -DHFT_HAVE_URING
LDLIBS += -luring
endif
ifeq ($(ENABLE_SESSION),1)
CPPFLAGS += -DHFT_HAVE_SESSION
LDLIBS += -lbpf -lelf -lz
endif
all: $(BUILD_DIR)/hft_replay $(BUILD_DIR)/test_ownership $(BUILD_DIR)/test_send_zc
$(BUILD_DIR):
	mkdir -p $@
# Rebuild when optional feature selection changes, as well as source changes.
.PHONY: FORCE
$(BUILD_DIR)/hft_replay: $(SOURCES) hft_core.h hft_runtime.h hft_send_zc.h FORCE | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) -o $@ $(LDFLAGS) $(LDLIBS)
	python3 hardware_build.py binary --artifact $@ --uring $(ENABLE_URING) --session $(ENABLE_SESSION)
$(BUILD_DIR)/test_ownership: test_ownership.c hft_core.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
$(BUILD_DIR)/test_send_zc: test_send_zc.c hft_send_zc.h hft_core.h hft_runtime.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
check: all
	$(BUILD_DIR)/test_ownership
	$(BUILD_DIR)/test_send_zc
	python3 -m unittest discover -s . -p 'test_*.py'
clean:
	rm -rf $(BUILD_DIR)
.PHONY: all check clean

# Build only the existing NXP object from the target running kernel BTF.
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
BPF_BUILD_DIR = $(abspath $(BUILD_DIR))/bpf
hardware-bpf:
	$(MAKE) -C ../../../kernel/tools/xdev_ext_mech BUILD_DIR=$(BPF_BUILD_DIR) VMLINUX_BTF=$(VMLINUX_BTF) $(BPF_BUILD_DIR)/nxp_mech.bpf.o
	python3 hardware_build.py bpf --artifact $(BPF_BUILD_DIR)/nxp_mech.bpf.o --btf $(VMLINUX_BTF)
.PHONY: hardware-bpf
