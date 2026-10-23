# SPDX-License-Identifier: GPL-2.0
KERNEL_SRC ?= $(abspath ../../../../..)
CC ?= cc
CLANG ?= /usr/bin/clang-14
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror
BPF_CFLAGS ?= -O2 -g -Wall -Wextra -Werror -target bpf -D__TARGET_ARCH_x86
MULTIARCH ?= $(shell $(CC) -print-multiarch)
.PHONY: runtime check clean
runtime: socket_runtime ce_observe.bpf.o
socket_runtime: socket_runtime.c observations.h
	$(CC) $(CFLAGS) -I$(KERNEL_SRC) $< -o $@ -lbpf -lelf -lz -pthread
ce_observe.bpf.o: ce_observe.bpf.c observations.h
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_SRC) -idirafter /usr/include/$(MULTIARCH) -c $< -o $@
check:
	python3 key_contract_test.py
	python3 independent_adapter_test.py
	python3 independent_class7_admission.py
	python3 nic_fallback_harness_test.py
clean:
	rm -f socket_runtime ce_observe.bpf.o
