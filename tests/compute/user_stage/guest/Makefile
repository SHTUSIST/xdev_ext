# SPDX-License-Identifier: GPL-2.0
# Guest test program of the USER stage; user_kvm.sh builds it against the
# exact product checkout, with the libxdev_ext USER helpers compiled in.
KERNEL_SRC ?= $(abspath ../../../../../..)
LIBDIR := $(KERNEL_SRC)/tools/xdev_ext_mech/lib
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror -pthread
.PHONY: all clean
all: user_stage_e2e ordered_frames_guest
user_stage_e2e: user_stage_e2e.c $(LIBDIR)/xdev_ext_user.c $(LIBDIR)/xdev_ext_session.c $(LIBDIR)/libxdev_ext.h \
		$(KERNEL_SRC)/include/uapi/linux/xdev_ext_mech.h $(KERNEL_SRC)/include/uapi/linux/io_uring.h
	$(CC) $(CFLAGS) -iquote $(KERNEL_SRC)/include/uapi -I$(LIBDIR) user_stage_e2e.c \
		$(LIBDIR)/xdev_ext_user.c $(LIBDIR)/xdev_ext_session.c $(LDFLAGS) -o $@ -lbpf -lelf -lz -pthread
ordered_frames_guest: ordered_frames_guest.c $(KERNEL_SRC)/include/uapi/linux/xdev_ext_mech.h \
                $(KERNEL_SRC)/include/uapi/linux/io_uring.h \
                $(KERNEL_SRC)/include/uapi/linux/xdev_ext_peer.h \
                ../../../xdev_ext_peer/guest/sw_provider_uapi.h
	$(CC) $(CFLAGS) -iquote $(KERNEL_SRC)/include/uapi $< $(LDFLAGS) -o $@ -lbpf -lelf -lz -pthread
# Optional test-only address policy; the runner selects this target explicitly.
# Build in its private guest copy and use the actual tested kernel's BTF.
CLANG ?= clang
BPFTOOL ?= bpftool
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
BPF_CFLAGS ?= -O2 -g -Wall -Wextra -Werror -target bpf -D__TARGET_ARCH_x86
vmlinux.h: $(VMLINUX_BTF)
	@set -eu; temporary="$@.tmp"; trap 'rm -f "$$temporary"' EXIT; \
		$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c >"$$temporary"; \
		mv -f "$$temporary" "$@"
ordered_frames_nvme.bpf.o: ordered_frames_nvme.bpf.c vmlinux.h \
		$(KERNEL_SRC)/tools/xdev_ext_mech/xdev_ext_mech_prog.h \
		$(KERNEL_SRC)/tools/xdev_ext_mech/xdev_ext_mech_kfunc.h
	$(CLANG) $(BPF_CFLAGS) -I. -I$(KERNEL_SRC)/tools/xdev_ext_mech -c $< -o $@
clean:
	$(RM) user_stage_e2e ordered_frames_guest ordered_frames_nvme.bpf.o vmlinux.h vmlinux.h.tmp
