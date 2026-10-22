# SPDX-License-Identifier: GPL-2.0
ifneq ($(KERNELRELEASE),)
obj-m := xdev_ext_peer_sw.o
else
KERNEL_SRC ?= $(abspath ../../../../..)
KDIR ?= $(KERNEL_SRC)
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror
all: peer_nvme_e2e modules
peer_nvme_e2e: peer_nvme_e2e.c sw_provider_uapi.h $(KERNEL_SRC)/include/uapi/linux/xdev_ext_peer.h
	$(CC) $(CFLAGS) -iquote $(KERNEL_SRC)/include/uapi $< $(LDFLAGS) -o $@
modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
clean:
	$(RM) peer_nvme_e2e
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
.PHONY: all modules clean
endif
