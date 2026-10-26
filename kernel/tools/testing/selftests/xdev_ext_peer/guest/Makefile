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
# Session test: dynamically linked like the product controller it executes.
EPOCH_HELPER_DIR ?= $(abspath $(KERNEL_SRC)/../tests/eval/xdomain)
EPOCH_HELPER_INPUTS := $(addprefix $(EPOCH_HELPER_DIR)/,epoch_control.c epoch_control.h check_contract.c check_contract.h)
peer_session_e2e: peer_session_e2e.c sw_provider_uapi.h $(KERNEL_SRC)/include/uapi/linux/xdev_ext_peer.h \
		$(KERNEL_SRC)/include/uapi/linux/xdev_ext_mech.h $(KERNEL_SRC)/include/uapi/linux/io_uring.h $(EPOCH_HELPER_INPUTS)
	$(CC) $(CFLAGS) -iquote $(KERNEL_SRC)/include/uapi -I$(EPOCH_HELPER_DIR) $< \
		$(EPOCH_HELPER_DIR)/epoch_control.c $(EPOCH_HELPER_DIR)/check_contract.c \
		$(SESSION_LDFLAGS) -o $@ -pthread -lbpf -lelf -lz
modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
clean:
	$(RM) peer_nvme_e2e peer_session_e2e
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
.PHONY: all modules clean
endif
