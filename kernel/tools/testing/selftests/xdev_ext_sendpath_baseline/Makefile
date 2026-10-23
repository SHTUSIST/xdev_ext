# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := sendpath_baseline_core_test sendpath_baseline_layout_test \
	sendpath_baseline_runtime_test
# Pins call sites in ../../../xdev_ext_sendpath_baseline.c that the C tests cannot
# observe: the receive guard, the partition check, and operation counting.
TEST_PROGS := sendpath_baseline_source_test.py
# Truth table of the SEND path selector (io_uring/unified_ops.c) and of the
# xsk_kernel_tx_capable() probe its dispatch calls, compiled from production.
TEST_PROGS += pick_send_path_test.py
TEST_FILES := pick_send_path_fixture.c
# The program under test; the runtime test executes it from $(OUTPUT).
TEST_GEN_PROGS_EXTENDED := xdev_ext_sendpath_baseline

ifeq ($(OUTPUT),)
OUTPUT := $(CURDIR)
endif

CFLAGS += -std=gnu11 -O2 -g -Wall -Wextra -Werror
LOCAL_HDRS += $(abspath ../../../xdev_ext_sendpath_baseline_core.h)
LOCAL_HDRS += $(abspath ../../../../nvme_xdp_pipeline_core.h)

# The layout test compiles nvme_xdp_pipeline.c itself, so it needs the same
# in-tree UAPI headers and libraries as the pipeline's own selftests.  The
# copies live below $(OUTPUT), never in the source tree, and make clean
# removes them.
UAPI_SHIM_DIR := $(OUTPUT)/.uapi
UAPI_SHIM_HEADERS := $(UAPI_SHIM_DIR)/linux/io_uring.h \
	$(UAPI_SHIM_DIR)/linux/nvme_ioctl.h
EXTRA_CLEAN += $(UAPI_SHIM_DIR)
PIPELINE_SOURCES := ../../../../nvme_xdp_pipeline.c \
	../../../../nvme_xdp_pipeline_core.h ../../../../xdev_ext_frame_sm.h \
	../../../xdev_ext_xsk_redirect.c ../../../include/xdev_ext_xsk_redirect.h
PIPELINE_CFLAGS := -I../../../.. -I$(UAPI_SHIM_DIR)
PIPELINE_LDLIBS := $(shell pkg-config --libs libxdp 2>/dev/null) \
	$(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf) \
	-luring -lpthread -ldl

include ../lib.mk

$(OUTPUT)/xdev_ext_sendpath_baseline: ../../../xdev_ext_sendpath_baseline.c $(LOCAL_HDRS)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -luring

$(UAPI_SHIM_DIR)/linux/%.h: ../../../../include/uapi/linux/%.h
	mkdir -p $(dir $@)
	cp $< $@

$(OUTPUT)/sendpath_baseline_layout_test: sendpath_baseline_layout_test.c \
		$(PIPELINE_SOURCES) $(LOCAL_HDRS) $(UAPI_SHIM_HEADERS)
	$(CC) $(CFLAGS) $(PIPELINE_CFLAGS) $< ../../../xdev_ext_xsk_redirect.c \
		-o $@ $(LDFLAGS) $(PIPELINE_LDLIBS)

.PHONY: run sanitize pick-send-path
run: run_tests

pick-send-path:
	python3 ./pick_send_path_test.py

sanitize: $(UAPI_SHIM_HEADERS)
	@set -eu; \
	dir="$(OUTPUT)/.sendpath_baseline_sanitize"; \
	san="-O1 -fsanitize=address,undefined -fno-omit-frame-pointer"; \
	trap 'rm -rf "$$dir"' EXIT; \
	mkdir -p "$$dir"; \
	$(CC) $(CFLAGS) $$san sendpath_baseline_core_test.c $(LDFLAGS) \
		-o "$$dir/sendpath_baseline_core_test"; \
	$(CC) $(CFLAGS) $$san $(PIPELINE_CFLAGS) \
		sendpath_baseline_layout_test.c ../../../xdev_ext_xsk_redirect.c \
		$(LDFLAGS) $(PIPELINE_LDLIBS) \
		-o "$$dir/sendpath_baseline_layout_test"; \
	$(CC) $(CFLAGS) $$san sendpath_baseline_runtime_test.c $(LDFLAGS) \
		-o "$$dir/sendpath_baseline_runtime_test"; \
	$(CC) $(CFLAGS) $$san ../../../xdev_ext_sendpath_baseline.c $(LDFLAGS) \
		-luring -o "$$dir/xdev_ext_sendpath_baseline"; \
	export ASAN_OPTIONS=detect_leaks=1:halt_on_error=1; \
	export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1; \
	for test in sendpath_baseline_core_test sendpath_baseline_layout_test \
			sendpath_baseline_runtime_test; do \
		status=0; \
		"$$dir/$$test" || status=$$?; \
		if [ "$$status" -eq 4 ]; then \
			echo "SKIP: sanitized $$test"; \
		elif [ "$$status" -ne 0 ]; then \
			echo "FAIL: sanitized $$test exit=$$status"; \
			exit "$$status"; \
		fi; \
	done; \
	python3 ./sendpath_baseline_source_test.py
