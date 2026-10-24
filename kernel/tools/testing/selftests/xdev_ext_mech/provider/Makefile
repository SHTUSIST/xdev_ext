# Independent tests. KERNEL_SRC points at the real production tree.
KERNEL_SRC ?= $(abspath ../../../../..)
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror
.PHONY: all check clean
all: xdev_ext_mech_dma_core_test
xdev_ext_mech_dma_core_test: xdev_ext_mech_dma_core_test.c
	$(CC) $(CFLAGS) -I$(KERNEL_SRC) $< -o $@
check: xdev_ext_mech_dma_core_test dma_campaign_test
	./xdev_ext_mech_dma_core_test
	./dma_campaign_test
	python3 sim_work_test.py
	python3 stats_frames_test.py
	python3 mmap_test.py
	python3 unbind_api_test.py
dma_campaign_test: dma_campaign_test.c dma_campaign.h
	$(CC) $(CFLAGS) $< -o $@
clean:
	rm -f xdev_ext_mech_dma_core_test dma_provider_runtime dma_provider_pair.bpf.o dma_campaign_test

CLANG ?= /usr/bin/clang-14
BPF_ARCH ?= x86
MULTIARCH ?= $(shell $(CC) -print-multiarch)
LIBBPF_INCLUDE ?= /usr/include
BPF_CFLAGS ?= -O2 -g -Wall -Wextra -Werror -target bpf -D__TARGET_ARCH_$(BPF_ARCH)
.PHONY: runtime provider
runtime: dma_provider_runtime dma_provider_pair.bpf.o
dma_provider_runtime: dma_provider_runtime.c dma_provider_fixture.h dma_campaign.h
	$(CC) $(CFLAGS) -I$(KERNEL_SRC) $< -o $@ -lbpf -lelf -lz -pthread
dma_provider_pair.bpf.o: dma_provider_pair.bpf.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_SRC) -I$(LIBBPF_INCLUDE) -idirafter /usr/include/$(MULTIARCH) -c $< -o $@
# KERNEL_BUILD is the configured output directory for the exact guest kernel.
KERNEL_BUILD ?= $(KERNEL_SRC)
provider:
	$(MAKE) -C $(KERNEL_SRC) O=$(KERNEL_BUILD) M=$(CURDIR) modules

# Standalone dynamically registered provider fixture.
obj-m := xdev_ext_dma_provider_sim.o
