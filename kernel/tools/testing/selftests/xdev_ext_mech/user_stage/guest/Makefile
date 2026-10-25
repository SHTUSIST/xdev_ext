# SPDX-License-Identifier: GPL-2.0
# Guest test program of the USER stage; user_kvm.sh builds it against the
# exact product checkout, with the libxdev_ext USER helpers compiled in.
KERNEL_SRC ?= $(abspath ../../../../../..)
LIBDIR := $(KERNEL_SRC)/tools/xdev_ext_mech/lib
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror -pthread
.PHONY: all clean
all: user_stage_e2e
user_stage_e2e: user_stage_e2e.c $(LIBDIR)/xdev_ext_user.c $(LIBDIR)/xdev_ext_session.c $(LIBDIR)/libxdev_ext.h \
		$(KERNEL_SRC)/include/uapi/linux/xdev_ext_mech.h $(KERNEL_SRC)/include/uapi/linux/io_uring.h
	$(CC) $(CFLAGS) -iquote $(KERNEL_SRC)/include/uapi -I$(LIBDIR) user_stage_e2e.c \
		$(LIBDIR)/xdev_ext_user.c $(LIBDIR)/xdev_ext_session.c $(LDFLAGS) -o $@ -lbpf -lelf -lz -pthread
clean:
	$(RM) user_stage_e2e
