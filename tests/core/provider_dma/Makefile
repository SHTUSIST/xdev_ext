# SPDX-License-Identifier: GPL-2.0
ROOT := $(abspath ../../..)
CC := gcc
BUILD_DIR ?= $(ROOT)/build/tests/provider_dma
CPPFLAGS += -Ihost -I$(ROOT)/src/core/include/uapi/linux -I$(ROOT)/src/bpf
CFLAGS += -std=gnu11 -O2 -Wall -Wextra -Werror -Wno-unused-parameter
.PHONY: test clean
test: $(BUILD_DIR)/dma_reference_test
	$(BUILD_DIR)/dma_reference_test
$(BUILD_DIR)/dma_reference_test: dma_reference_test.c $(ROOT)/examples/compute/dma_plan.bpf.c $(wildcard host/*.h host/bpf/*.h) $(ROOT)/src/bpf/xdev_ext_mech_prog.h $(ROOT)/src/bpf/xdev_ext_mech_kfunc.h $(ROOT)/src/core/include/uapi/linux/xdev_ext_mech.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@
clean:
	rm -f $(BUILD_DIR)/dma_reference_test
