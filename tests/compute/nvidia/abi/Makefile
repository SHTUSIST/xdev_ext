# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := nvidia_p2p_abi_test gpu_xdp_frame_owner_test \
	xdev_ext_gpu_identity_test gpu_xdp_nocuda_loop_test nv_ce_runtime_cases_test
TEST_GEN_FILES := nv_ce_runtime_test_host
TEST_PROGS := gpu_xdp_sample_source_test.py nv_ce_runtime_source_test.py

LOCAL_HDRS += $(abspath ../../../include/xdev_ext_nv_p2p_ioctl.h)
LOCAL_HDRS += $(abspath ../../../include/xdev_ext_xsk_frame_owner.h)
LOCAL_HDRS += $(abspath ../../../../drivers/gpu/nvidia-p2p/samples/gpu_xdp_frame_runtime.h)
LOCAL_HDRS += $(abspath ../../../include/xdev_ext_gpu_identity.h)
LOCAL_HDRS += $(abspath nv_ce_runtime_cases.h)

CFLAGS += -std=gnu11 -O2 -g -Wall -Wextra -Werror

include ../lib.mk

$(OUTPUT)/xdev_ext_gpu_identity_test: xdev_ext_gpu_identity_test.c \
		../../../xdev_ext_gpu_identity.c $(LOCAL_HDRS)
	$(CC) $(CFLAGS) -I../../.. $< ../../../xdev_ext_gpu_identity.c -o $@

# Compiles the no-CUDA sample source itself, with poll() scripted.
NOCUDA_SAMPLE := ../../../../drivers/gpu/nvidia-p2p/samples/gpu_xdp_p2p_nocuda.c
$(OUTPUT)/gpu_xdp_nocuda_loop_test: gpu_xdp_nocuda_loop_test.c \
		$(NOCUDA_SAMPLE) ../../../include/xdev_ext_xsk_redirect.h \
		$(LOCAL_HDRS)
	$(CC) $(CFLAGS) $< -o $@

# Copy-engine round trips for a GPU window.  The -host build, part of
# "all", has no CUDA and only refuses; the CUDA build is made on request:
#	make nv_ce_runtime_test CUDA_HOME=/usr/local/cuda-12.8
CUDA_HOME ?= /usr/local/cuda
EXTRA_CLEAN += $(OUTPUT)/nv_ce_runtime_test
NV_CE_RUNTIME_DEPS := nv_ce_runtime_test.c ../../../include/xdev_ext_nv_p2p_ioctl.h \
	../../../xdev_ext_gpu_identity.c $(LOCAL_HDRS)

$(OUTPUT)/nv_ce_runtime_test_host: $(NV_CE_RUNTIME_DEPS)
	$(CC) $(CFLAGS) nv_ce_runtime_test.c -o $@

$(OUTPUT)/nv_ce_runtime_test: $(NV_CE_RUNTIME_DEPS)
	$(CC) $(CFLAGS) -DXDEV_EXT_NV_CE_WITH_CUDA -I$(CUDA_HOME)/include -I../../.. \
		nv_ce_runtime_test.c ../../../xdev_ext_gpu_identity.c -o $@ \
		-L$(CUDA_HOME)/lib64 -lcuda

.PHONY: nv_ce_runtime_test run
nv_ce_runtime_test: $(OUTPUT)/nv_ce_runtime_test
run: run_tests
