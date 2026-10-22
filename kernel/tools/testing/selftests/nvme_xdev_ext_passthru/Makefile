# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := nvme_xdev_ext_passthru_test nvme_xdev_ext_passthru_runtime \
	nvme_sgl_gap_runtime
TEST_PROGS := nvme_xdev_ext_passthru_source_test.py nvme_sgl_gap_source_test.py

LOCAL_HDRS += $(abspath ../../../../include/linux/nvme_xdev_ext_passthru.h)
LOCAL_HDRS += $(abspath ../../../../include/uapi/linux/nvme_ioctl.h)
LOCAL_HDRS += $(abspath ../../../../include/uapi/linux/io_uring.h)
LOCAL_HDRS += $(abspath nvme_xdev_ext_passthru_runtime.h)
LOCAL_HDRS += $(abspath ../../../xdev_ext_mech/xdev_ext_mech_prog.h)

CFLAGS += -std=gnu11 -O2 -g -Wall -Wextra -Werror $(KHDR_INCLUDES)

ifeq ($(strip $(CROSS_COMPILE)$(LLVM)),)
NVME_XDEV_EXT_UBSAN ?= 1
else
NVME_XDEV_EXT_UBSAN ?= 0
endif

ifeq ($(NVME_XDEV_EXT_UBSAN),1)
CFLAGS += -fsanitize=undefined -fno-sanitize-recover=undefined
LDFLAGS += -fsanitize=undefined
endif

include ../lib.mk

# The guest runtime harnesses use raw io_uring syscalls and are static so the
# minimal KVM rootfs needs neither liburing nor a matching host runtime.
GUEST_RUNTIMES := $(OUTPUT)/nvme_xdev_ext_passthru_runtime \
	$(OUTPUT)/nvme_sgl_gap_runtime
$(GUEST_RUNTIMES): CFLAGS := $(filter-out \
	-fsanitize=undefined -fno-sanitize-recover=undefined,$(CFLAGS))
$(GUEST_RUNTIMES): LDFLAGS := $(filter-out \
	-fsanitize=undefined,$(LDFLAGS)) -static

.PHONY: run
run: run_tests
