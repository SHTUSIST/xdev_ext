# SPDX-License-Identifier: GPL-2.0
#
# Guest programs of the libxdev_ext KVM test (lib_kvm.sh builds them).
#	make KSRC=<kernel/ of the checkout> LIBXDEV_EXT=<dir of libxdev_ext.a> CC=<gcc>

CC ?= gcc
KSRC ?= $(abspath ../../../../..)
LIBXDEV_EXT ?= $(KSRC)/tools/xdev_ext_mech/lib/.xdev_ext-lib-build
OUTPUT ?= $(CURDIR)
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror

all: $(OUTPUT)/xdev_ext_lib_nvme_nic $(OUTPUT)/xdev_ext_lib_iou $(OUTPUT)/xdev_ext_lib_rx

$(OUTPUT)/xdev_ext_lib_nvme_nic: xdev_ext_lib_nvme_nic.c $(LIBXDEV_EXT)/libxdev_ext.a \
		$(KSRC)/tools/xdev_ext_mech/lib/libxdev_ext.h
	$(CC) $(CFLAGS) -I$(KSRC)/tools/xdev_ext_mech/lib $< -o $@ \
		$(LIBXDEV_EXT)/libxdev_ext.a -lbpf -lelf -lz

$(OUTPUT)/xdev_ext_lib_iou: xdev_ext_lib_iou.c $(LIBXDEV_EXT)/libxdev_ext.a \
		$(KSRC)/tools/xdev_ext_mech/lib/libxdev_ext.h
	$(CC) $(CFLAGS) -pthread -I$(KSRC)/tools/xdev_ext_mech/lib $< -o $@ \
		$(LIBXDEV_EXT)/libxdev_ext.a -lbpf -lelf -lz

# Independent of the product: no product header.
$(OUTPUT)/xdev_ext_lib_rx: xdev_ext_lib_rx.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: all
