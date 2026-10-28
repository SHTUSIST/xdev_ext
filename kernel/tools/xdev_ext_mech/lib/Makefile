# SPDX-License-Identifier: GPL-2.0
#
# libxdev_ext, the thin session library (SPEC.md).
#	make -C tools/xdev_ext_mech/lib BUILD_DIR=<dir> CC=<gcc>
# produces BUILD_DIR/libxdev_ext.a.  The class program part needs libbpf
# >= 1.0 headers; programs linking the archive add -lbpf -lelf -lz.

CC ?= gcc
AR ?= ar
BUILD_DIR ?= .xdev_ext-lib-build

CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror -fPIC

SRCS := xdev_ext_session.c xdev_ext_prog.c xdev_ext_run.c xdev_ext_user.c xdev_ext_link.c xdev_ext_peer_message.c
OBJS := $(SRCS:%.c=$(BUILD_DIR)/%.o)
HDRS := libxdev_ext.h libxdev_ext_internal.h libxdev_ext_peer_message.h ../xdev_ext_mech_ctl_core.h \
	../xdev_ext_mech_prog.h ../../../include/uapi/linux/xdev_ext_mech.h \
	../../../include/uapi/linux/io_uring.h

.DEFAULT_GOAL := lib

lib: $(BUILD_DIR)/libxdev_ext.a

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/%.o: %.c $(HDRS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/libxdev_ext.a: $(OBJS)
	rm -f $@
	$(AR) rcs $@ $^

clean:
	rm -rf $(BUILD_DIR)

.PHONY: lib clean
