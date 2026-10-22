# SPDX-License-Identifier: GPL-2.0
CC ?= cc
CFLAGS ?= -O2 -g
WARN := -std=gnu11 -Wall -Wextra -Werror -pthread
SELF := ../../../kernel/tools/testing/selftests/xdev_ext_preload
TOOLS := ../../../kernel/tools
BUILD := build
ARTIFACTS := fallback_shapes mixed_hft_shape xdev_ext_preload_db_workload xdev_ext_preload_socket_smoke libio_uring_unified.so libxdev_ext_preload_kernel_model.so
HEADERS := $(wildcard $(TOOLS)/xdev_ext_preload*.h) $(wildcard $(TOOLS)/../include/uapi/linux/xdev_ext*.h) $(TOOLS)/include/io_uring/mini_liburing.h

.PHONY: all check run clean
all: $(addprefix $(BUILD)/,$(ARTIFACTS))
$(BUILD):
	mkdir -p $@
$(BUILD)/fallback_shapes: fallback_shapes.c | $(BUILD)
	$(CC) $(CFLAGS) $(WARN) $< -o $@
$(BUILD)/mixed_hft_shape: mixed_hft_shape.c | $(BUILD)
	$(CC) $(CFLAGS) $(WARN) $< -o $@
$(BUILD)/xdev_ext_preload_db_workload: $(SELF)/xdev_ext_preload_db_workload.c $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) $(WARN) -I$(TOOLS) $< -o $@
$(BUILD)/xdev_ext_preload_socket_smoke: $(SELF)/xdev_ext_preload_socket_smoke.c | $(BUILD)
	$(CC) $(CFLAGS) $(WARN) $< -o $@
$(BUILD)/libio_uring_unified.so: $(TOOLS)/io_uring_unified_preload.c $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) $(WARN) -I$(TOOLS) -shared -fPIC $< -o $@ -ldl
$(BUILD)/libxdev_ext_preload_kernel_model.so: $(SELF)/xdev_ext_preload_kernel_model.c $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) $(WARN) -I$(TOOLS) -shared -fPIC $< -o $@ -ldl
check: all
	python3 test_mixed_hft.py
	python3 test_contract.py
run: all
	python3 run.py
clean:
	rm -rf $(BUILD) __pycache__
