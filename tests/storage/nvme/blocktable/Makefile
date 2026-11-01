# SPDX-License-Identifier: GPL-2.0
CC := gcc
ROOT := ../../../../../..
KERNEL := $(ROOT)/kernel
MECH := $(KERNEL)/tools/xdev_ext_mech
BUILD ?= .build
HEADERS := $(MECH)/xdev_ext_mech_prog.h $(MECH)/xdev_ext_mech_kfunc.h \
	$(KERNEL)/include/linux/nvme_xdev_ext_passthru.h \
	$(KERNEL)/include/linux/xdev_ext_storfam_core.h \
	$(KERNEL)/include/uapi/linux/xdev_ext_mech.h
CFLAGS := -O2 -g -std=gnu11 -Wall -Wextra -Werror -fsanitize=undefined -fno-sanitize-recover=all
CPPFLAGS := -Ihost -I$(KERNEL)/tools/testing/selftests/xdev_ext_mech/cref/host -I$(KERNEL) -I$(MECH) -I$(MECH)/examples/storage
.PHONY: check baseline-red
check: $(BUILD)/test
	$(BUILD)/test
baseline-red: $(BUILD)/baseline
	$(BUILD)/baseline
$(BUILD):
	mkdir -p $@
$(BUILD)/test: test.c $(HEADERS) $(MECH)/examples/storage/nvme_blocktable.bpf.c $(MECH)/examples/storage/nvme_blocktable.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@
$(BUILD)/baseline: test.c $(HEADERS) $(MECH)/nvme_s0.bpf.c $(MECH)/examples/storage/nvme_blocktable.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DBLOCKTABLE_BASELINE $< -o $@
