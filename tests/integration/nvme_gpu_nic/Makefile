# SPDX-License-Identifier: GPL-2.0

UAPI_SHIM_DIR := .uapi
UAPI_SHIM_HEADERS := $(UAPI_SHIM_DIR)/linux/io_uring.h \
	$(UAPI_SHIM_DIR)/linux/nvme_ioctl.h

TEST_GEN_PROGS := nvme_gpu_nic_chain_core_test \
	nvme_gpu_nic_pipeline_adapter_test nvme_gpu_nic_runtime_host_test
TEST_PROGS := nvme_gpu_nic_chain_source_test.py

CFLAGS += -std=c11 -O2 -g -Wall -Wextra -Werror -I../../../.. \
	-I$(UAPI_SHIM_DIR)
LOCAL_HDRS += $(abspath ../../../nvme_gpu_nic_chain_core.h)
LOCAL_HDRS += $(abspath ../../../nvme_gpu_nic_runtime.h)
LOCAL_HDRS += $(abspath ../../../include/xdev_ext_nv_p2p_ioctl.h)
LOCAL_HDRS += $(abspath ../../../include/xdev_ext_xsk_redirect.h)
LOCAL_HDRS += $(abspath ../../../../nvme_xdp_pipeline.c)
LOCAL_HDRS += $(abspath ../../../../nvme_xdp_pipeline_core.h)
LOCAL_HDRS += $(abspath ../../../../xdev_ext_frame_sm.h)
LOCAL_HDRS += $(UAPI_SHIM_HEADERS)
EXTRA_CLEAN += $(UAPI_SHIM_DIR)

PIPELINE_LDLIBS := $(shell pkg-config --libs libxdp 2>/dev/null) \
	$(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf) \
	-luring -lpthread -ldl

$(UAPI_SHIM_DIR)/linux/%.h: ../../../../include/uapi/linux/%.h
	mkdir -p $(dir $@)
	cp $< $@

include ../lib.mk

$(OUTPUT)/nvme_gpu_nic_runtime_host_test: nvme_gpu_nic_runtime_host_test.c \
					 ../../../nvme_gpu_nic_runtime.c $(LOCAL_HDRS)
	$(CC) $(CFLAGS) -I../../.. $< ../../../nvme_gpu_nic_runtime.c \
		-o $@

$(OUTPUT)/nvme_gpu_nic_pipeline_adapter_test: \
		nvme_gpu_nic_pipeline_adapter_test.c \
		../../../xdev_ext_xsk_redirect.c $(LOCAL_HDRS)
	$(CC) $(CFLAGS) $< ../../../xdev_ext_xsk_redirect.c \
		$(LDFLAGS) $(PIPELINE_LDLIBS) -o $@

.PHONY: run
run: run_tests

.PHONY: sanitize
sanitize:
	$(CC) $(CFLAGS) -O1 -fsanitize=address,undefined \
		-fno-omit-frame-pointer nvme_gpu_nic_chain_core_test.c \
		-o .core_test_sanitize
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 ./.core_test_sanitize
	$(CC) $(CFLAGS) -O1 -fsanitize=address,undefined \
		-fno-omit-frame-pointer -I../../.. nvme_gpu_nic_runtime_host_test.c \
		../../../nvme_gpu_nic_runtime.c -o .runtime_test_sanitize
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 ./.runtime_test_sanitize
	$(CC) $(CFLAGS) -O1 -fsanitize=address,undefined \
		-fno-omit-frame-pointer nvme_gpu_nic_pipeline_adapter_test.c \
		../../../xdev_ext_xsk_redirect.c $(LDFLAGS) $(PIPELINE_LDLIBS) \
		-o .adapter_test_sanitize
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 ./.adapter_test_sanitize
	rm -f .core_test_sanitize
	rm -f .runtime_test_sanitize
	rm -f .adapter_test_sanitize
