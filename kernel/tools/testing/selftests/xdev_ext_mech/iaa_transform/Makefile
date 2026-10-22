# SPDX-License-Identifier: GPL-2.0
KERNEL_SRC ?= $(abspath ../../../../..)
CC ?= cc
CLANG ?= /usr/bin/clang-14
BPF_ARCH ?= x86
MULTIARCH ?= $(shell $(CC) -print-multiarch)
PROVIDER_HEADERS ?= ../provider
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror
.PHONY: runtime check clean
runtime: iaa_runtime iaa_pair.bpf.o
iaa_runtime: iaa_runtime.c campaign.h observations.h $(PROVIDER_HEADERS)/dma_provider_fixture.h
	$(CC) $(CFLAGS) -I$(KERNEL_SRC) -I$(PROVIDER_HEADERS) $< -o $@ -lbpf -lelf -lz
iaa_pair.bpf.o: iaa_pair.bpf.c observations.h
	$(CLANG) -O2 -g -Wall -Wextra -Werror -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -I$(KERNEL_SRC) -idirafter /usr/include/$(MULTIARCH) -c $< -o $@
check:
	./run.sh
clean:
	rm -f iaa_runtime iaa_pair.bpf.o
