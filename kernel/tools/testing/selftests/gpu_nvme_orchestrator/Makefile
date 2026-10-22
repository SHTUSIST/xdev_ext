# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := gpu_nvme_orchestrator_core_test
TEST_GEN_FILES := gpu_nvme_orchestrator_host
TEST_PROGS := gpu_nvme_orchestrator_source_test.py
EXTRA_CLEAN += $(OUTPUT)/gpu_nvme_orchestrator_cuda

CUDA_HOME ?= /usr/local/cuda
CUDA_CPPFLAGS ?= -I$(CUDA_HOME)/include
CUDA_LDLIBS ?= -L$(CUDA_HOME)/lib64 -lcuda

LOCAL_HDRS += $(abspath ../../../gpu_nvme_orchestrator_core.h)
LOCAL_HDRS += $(abspath ../../../include/xdev_ext_nv_p2p_ioctl.h)
LOCAL_HDRS += $(abspath ../../../include/xdev_ext_gpu_identity.h)
LOCAL_HDRS += $(abspath ../../../../nvme_xdp_pipeline_core.h)

CFLAGS += -std=gnu11 -O2 -g -Wall -Wextra -Werror

include ../lib.mk

$(OUTPUT)/gpu_nvme_orchestrator_host: ../../../gpu_nvme_orchestrator.c \
				       $(LOCAL_HDRS)
	$(CC) $(CFLAGS) -I../../../.. -I../../.. $< \
		../../../xdev_ext_gpu_identity.c -o $@

$(OUTPUT)/gpu_nvme_orchestrator_cuda: ../../../gpu_nvme_orchestrator.c \
				       $(LOCAL_HDRS)
	$(CC) $(CFLAGS) $(CUDA_CPPFLAGS) -DXDEV_EXT_GPU_NVME_WITH_CUDA \
		-I../../../.. -I../../.. $< ../../../xdev_ext_gpu_identity.c \
		-o $@ $(LDFLAGS) $(CUDA_LDLIBS)

.PHONY: cuda
cuda: $(OUTPUT)/gpu_nvme_orchestrator_cuda

.PHONY: run
run: run_tests

.PHONY: sanitize
sanitize:
	$(CC) $(CFLAGS) -O1 -fsanitize=address,undefined \
		-fno-omit-frame-pointer -I../../../.. \
		gpu_nvme_orchestrator_core_test.c -o .core_test_sanitize
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 ./.core_test_sanitize
	rm -f .core_test_sanitize
