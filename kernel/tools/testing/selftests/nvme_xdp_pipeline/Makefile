# SPDX-License-Identifier: GPL-2.0

UAPI_SHIM_DIR := .uapi
UAPI_SHIM_HEADERS := $(UAPI_SHIM_DIR)/linux/io_uring.h \
	$(UAPI_SHIM_DIR)/linux/nvme_ioctl.h

TEST_GEN_PROGS := nvme_xdp_pipeline_test nvme_xdp_pipeline_adapter_test
TEST_PROGS := nvme_xdp_pipeline_source_test.py

CFLAGS += -std=c11 -O2 -Wall -Wextra -Werror -I../../../.. -I$(UAPI_SHIM_DIR)
LDLIBS += $(shell pkg-config --libs libxdp 2>/dev/null) \
	$(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf) \
	-luring -lpthread -ldl

LOCAL_HDRS += $(abspath ../../../../nvme_xdp_pipeline_core.h)
LOCAL_HDRS += $(abspath ../../../../xdev_ext_frame_sm.h)
LOCAL_HDRS += $(abspath ../../../../nvme_xdp_pipeline.c)
LOCAL_HDRS += $(abspath ../../../../tools/include/xdev_ext_xsk_redirect.h)
# Read-only: the core test checks the rx summary against the baseline's
# definitions (spb_nearest_rank) in this header.
LOCAL_HDRS += $(abspath ../../../../tools/xdev_ext_sendpath_baseline_core.h)
LOCAL_HDRS += $(UAPI_SHIM_HEADERS)
EXTRA_CLEAN += $(UAPI_SHIM_DIR)
EXTRA_CLEAN += .nvme_xdp_pipeline_test_sanitize \
	.nvme_xdp_pipeline_adapter_test_sanitize

$(UAPI_SHIM_DIR)/linux/%.h: ../../../../include/uapi/linux/%.h
	mkdir -p $(dir $@)
	cp $< $@

include ../lib.mk

$(OUTPUT)/nvme_xdp_pipeline_adapter_test: nvme_xdp_pipeline_adapter_test.c \
		../../../../tools/xdev_ext_xsk_redirect.c $(LOCAL_HDRS)
	$(CC) $(CFLAGS) $< ../../../../tools/xdev_ext_xsk_redirect.c \
		-o $@ $(LDFLAGS) $(LDLIBS)

.PHONY: run
run: run_tests

.PHONY: sanitize
sanitize: $(UAPI_SHIM_HEADERS)
	@set -eu; \
	trap 'rm -f .nvme_xdp_pipeline_test_sanitize \
		.nvme_xdp_pipeline_adapter_test_sanitize' EXIT; \
	$(CC) $(CFLAGS) -O1 -g -fsanitize=address,undefined \
		-fno-omit-frame-pointer nvme_xdp_pipeline_test.c \
		$(LDFLAGS) $(LDLIBS) -o .nvme_xdp_pipeline_test_sanitize; \
	$(CC) $(CFLAGS) -O1 -g -fsanitize=address,undefined \
		-fno-omit-frame-pointer nvme_xdp_pipeline_adapter_test.c \
		../../../../tools/xdev_ext_xsk_redirect.c $(LDFLAGS) $(LDLIBS) \
		-o .nvme_xdp_pipeline_adapter_test_sanitize; \
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 \
		./.nvme_xdp_pipeline_test_sanitize; \
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 \
		./.nvme_xdp_pipeline_adapter_test_sanitize; \
	python3 ./nvme_xdp_pipeline_source_test.py
