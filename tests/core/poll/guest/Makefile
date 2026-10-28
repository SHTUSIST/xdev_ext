# SPDX-License-Identifier: GPL-2.0
# Guest test program of stage polling; poll_kvm.sh builds it against the
# exact product checkout and links it like the product controller.
KERNEL_SRC ?= $(abspath ../../../../../..)
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror
.PHONY: all clean
all: nvme_poll_e2e
nvme_poll_e2e: nvme_poll_e2e.c $(KERNEL_SRC)/include/uapi/linux/xdev_ext_mech.h $(KERNEL_SRC)/include/uapi/linux/io_uring.h
	$(CC) $(CFLAGS) -iquote $(KERNEL_SRC)/include/uapi $< $(LDFLAGS) -o $@ -lbpf -lelf -lz
clean:
	$(RM) nvme_poll_e2e
