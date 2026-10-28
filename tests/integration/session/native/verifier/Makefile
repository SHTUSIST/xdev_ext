# SPDX-License-Identifier: GPL-2.0
# Reuse the BTF-tagged selftest programs; no test_progs/skeleton build needed.
verifier_dir := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
SOURCE_TREE ?= $(abspath $(verifier_dir)/../../../../..)
BUILD_DIR ?= $(verifier_dir)/build
CLANG ?= /usr/bin/clang-21
HOSTCC ?= cc
BPF_ARCH ?= x86
MULTIARCH ?= $(shell $(HOSTCC) -print-multiarch)
# Point at the parent containing bpf/{bpf_helpers,bpf_helper_defs,...}.h.
# A kernel source checkout alone lacks the generated bpf_helper_defs.h.
LIBBPF_INCLUDE ?= /usr/include

PROGS := wrong_class_hold desc_complete sleepable_build forged_ctx frame_write \
	dma_wrong_class_hold dma_desc_complete
# BPF compute callback negatives, run by run_compute.sh.
COMPUTE_PROGS := compute_rw_build compute_set_len_complete compute_view_size \
	compute_view_past compute_wrong_class compute_sleepable compute_desc
PROG_DIR := $(SOURCE_TREE)/tools/testing/selftests/bpf/progs
OBJECTS := $(PROGS:%=$(BUILD_DIR)/xdev_ext_mech_fail_%.bpf.o) \
	$(COMPUTE_PROGS:%=$(BUILD_DIR)/xdev_ext_mech_fail_%.bpf.o)
STATE_PROGS := state_ce state_build
REL_PROGS := rel_view_write rel_view_complete
REL_OBJECTS := $(REL_PROGS:%=$(BUILD_DIR)/xdev_ext_mech_fail_%.bpf.o)
STATE_OBJECTS := $(STATE_PROGS:%=$(BUILD_DIR)/xdev_ext_mech_fail_%.bpf.o)
HELPER_PROGS := map_lookup_elem ktime_get_ns probe_read_kernel probe_read_kernel_str \
	probe_read_user probe_read_user_str get_current_task get_current_task_btf \
	trace_printk trace_vprintk timer_init tail_call ringbuf_output map_update_elem
HELPER_OBJECTS := $(HELPER_PROGS:%=$(BUILD_DIR)/helper_%.bpf.o)
# Literal UAPI IDs also select the corresponding call in helper_probe.bpf.c.
HELPER_ID_map_lookup_elem := 1
HELPER_ID_ktime_get_ns := 5
HELPER_ID_probe_read_kernel := 113
HELPER_ID_probe_read_kernel_str := 115
HELPER_ID_probe_read_user := 112
HELPER_ID_probe_read_user_str := 114
HELPER_ID_get_current_task := 35
HELPER_ID_get_current_task_btf := 158
HELPER_ID_trace_printk := 6
HELPER_ID_trace_vprintk := 177
HELPER_ID_timer_init := 169
HELPER_ID_tail_call := 12
HELPER_ID_ringbuf_output := 130
HELPER_ID_map_update_elem := 2
BPF_CFLAGS ?= -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_$(BPF_ARCH)
BPF_INCLUDES := -I$(LIBBPF_INCLUDE) \
	-I$(SOURCE_TREE)/tools/include/uapi -I$(SOURCE_TREE)/include/uapi
ifneq ($(MULTIARCH),)
BPF_INCLUDES += -idirafter /usr/include/$(MULTIARCH)
endif

.DEFAULT_GOAL := all
all: $(OBJECTS) $(STATE_OBJECTS) $(REL_OBJECTS) $(HELPER_OBJECTS) $(BUILD_DIR)/ce_abi_good.bpf.o $(BUILD_DIR)/ce_abi_old.bpf.o

helpers: $(HELPER_OBJECTS)

state: $(STATE_OBJECTS)

compute: $(COMPUTE_PROGS:%=$(BUILD_DIR)/xdev_ext_mech_fail_%.bpf.o)

$(BUILD_DIR)/ce_abi_good.bpf.o: $(verifier_dir)/ce_abi_probe.bpf.c | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -I$(PROG_DIR) -c $< -o $@

$(BUILD_DIR)/ce_abi_old.bpf.o: $(verifier_dir)/ce_abi_probe.bpf.c | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -I$(PROG_DIR) -DCE_TEST_ABI=1 -c $< -o $@

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/helper_%.bpf.o: $(verifier_dir)/helper_probe.bpf.c \
		$(PROG_DIR)/xdev_ext_mech_common.h $(PROG_DIR)/bpf_misc.h \
		$(PROG_DIR)/../xdev_ext_mech_test.h \
		$(SOURCE_TREE)/include/uapi/linux/xdev_ext_mech.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -I$(PROG_DIR) -DHELPER_ID=$(HELPER_ID_$*) -c $< -o $@

$(BUILD_DIR)/xdev_ext_mech_fail_%.bpf.o: $(PROG_DIR)/xdev_ext_mech_fail_%.c \
		$(PROG_DIR)/xdev_ext_mech_common.h $(PROG_DIR)/bpf_misc.h \
		$(PROG_DIR)/../xdev_ext_mech_test.h \
		$(SOURCE_TREE)/include/uapi/linux/xdev_ext_mech.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

$(STATE_OBJECTS) $(REL_OBJECTS): $(BUILD_DIR)/xdev_ext_mech_fail_%.bpf.o: \
		$(verifier_dir)/xdev_ext_mech_fail_%.c $(PROG_DIR)/xdev_ext_mech_common.h \
		$(PROG_DIR)/bpf_misc.h $(PROG_DIR)/../xdev_ext_mech_test.h \
		$(SOURCE_TREE)/include/uapi/linux/xdev_ext_mech.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -I$(PROG_DIR) -c $< -o $@

.PHONY: all state compute helpers
