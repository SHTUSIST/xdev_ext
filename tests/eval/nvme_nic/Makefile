# SPDX-License-Identifier: GPL-2.0
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror -pthread
ENABLE_URING ?= 0
ENABLE_SESSION ?= 0
BUILD_DIR ?= .build
KERNEL = ../../../kernel
PRODUCER_SOURCES = nnb_producer.c nnb_uring.c nnb_session.c
HEADERS = nnb.h nnb_wire.h
ifeq ($(ENABLE_URING),1)
CPPFLAGS += -DNNB_HAVE_URING
LDLIBS += -luring
URING_TESTS = $(BUILD_DIR)/test_uring_shape
endif
ifeq ($(ENABLE_SESSION),1)
CPPFLAGS += -DNNB_HAVE_SESSION
PRODUCER_SOURCES += $(KERNEL)/tools/xdev_ext_xsk_redirect.c
LDLIBS += -lbpf -lelf -lz
endif

all: $(BUILD_DIR)/nnb_producer $(BUILD_DIR)/nnb_peer $(BUILD_DIR)/test_wire $(BUILD_DIR)/test_bpf_body \
	$(BUILD_DIR)/test_latency $(URING_TESTS)
$(BUILD_DIR):
	mkdir -p $@
.PHONY: all check clean FORCE hardware-bpf
# Rebuild when the optional backend selection changes, as well as on source changes.
$(BUILD_DIR)/nnb_producer: $(PRODUCER_SOURCES) $(HEADERS) FORCE | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(PRODUCER_SOURCES) -o $@ $(LDFLAGS) $(LDLIBS)
$(BUILD_DIR)/nnb_peer: nnb_peer.c nnb_wire.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
$(BUILD_DIR)/test_wire: test_wire.c nnb_wire.h $(KERNEL)/tools/xdev_ext_mech/xdev_ext_mech_prog.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
$(BUILD_DIR)/test_bpf_body: test_bpf_body.c nnb_bench.bpf.c nnb_wire.h $(KERNEL)/tools/xdev_ext_mech/xdev_ext_mech_prog.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(KERNEL)/tools/testing/selftests/xdev_ext_mech/cref/host -I$(KERNEL) \
		-I$(KERNEL)/tools/xdev_ext_mech $< -o $@ $(LDFLAGS)
# Latency distribution of the producer with synthetic stamps (no measurement).
$(BUILD_DIR)/test_latency: test_latency.c nnb_producer.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
# Submission shape of the reverse uring arm, against a real ring (never submitted).
$(BUILD_DIR)/test_uring_shape: test_uring_shape.c nnb_uring.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -luring
check: all
	$(BUILD_DIR)/test_wire
	$(BUILD_DIR)/test_bpf_body
	$(BUILD_DIR)/test_latency
	$(if $(URING_TESTS),$(BUILD_DIR)/test_uring_shape)
	NNB_BUILD_DIR=$(abspath $(BUILD_DIR)) PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s . -p 'test_*.py'
clean:
	rm -rf $(BUILD_DIR) __pycache__

# The session policy object, built against the running producer kernel's BTF.
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
CLANG ?= clang
BPFTOOL ?= bpftool
BPF_ARCH ?= x86
BPF_DIR = $(BUILD_DIR)/bpf
hardware-bpf: $(BPF_DIR)/nnb_bench.bpf.o
$(BPF_DIR)/vmlinux.h: $(VMLINUX_BTF)
	mkdir -p $(BPF_DIR)
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@.tmp && mv -f $@.tmp $@
$(BPF_DIR)/nnb_bench.bpf.o: nnb_bench.bpf.c $(BPF_DIR)/vmlinux.h $(KERNEL)/tools/xdev_ext_mech/xdev_ext_mech_prog.h $(KERNEL)/tools/xdev_ext_mech/xdev_ext_mech_kfunc.h
	$(CLANG) -O2 -g -Wall -Wextra -Werror -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
		-I$(BPF_DIR) -I$(KERNEL)/tools/xdev_ext_mech -c $< -o $@
