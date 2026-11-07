# SPDX-License-Identifier: GPL-2.0
# Guest test program and BPF objects for attacker-brought program isolation.
# attack_kvm.sh builds this against the exact product checkout, with the
# libxdev_ext USER helpers compiled in. KERNEL_SRC is a native source tree
# (canonical or assembled); it supplies the UAPI headers and the library.
KERNEL_SRC ?= $(abspath ../../../..)
LIBDIR := $(KERNEL_SRC)/tools/xdev_ext_mech/lib
MECHDIR := $(KERNEL_SRC)/tools/xdev_ext_mech
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror -pthread
LIBBPF_CFLAGS ?=
LIBBPF_LIBS ?= -lbpf
SHARED_SOURCES := $(KERNEL_SRC)/tools/xdev_ext_xsk_shared.c $(KERNEL_SRC)/tools/xdev_ext_xsk_steer.c \
	$(KERNEL_SRC)/tools/xdev_ext_xsk_redirect.c
CLANG ?= clang
BPFTOOL ?= bpftool
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
BPF_CFLAGS ?= -O2 -g -Wall -Wextra -Werror -target bpf -D__TARGET_ARCH_x86

MODES := correct reserved outside frame verdict
BPF_OBJS := $(addprefix attack_,$(addsuffix .bpf.o,$(MODES))) attack_user.bpf.o

.PHONY: all clean
all: attack_guest $(BPF_OBJS)

attack_guest: attack_guest.c $(LIBDIR)/xdev_ext_user.c $(LIBDIR)/xdev_ext_session.c \
		$(SHARED_SOURCES) $(LIBDIR)/libxdev_ext.h \
		$(KERNEL_SRC)/include/uapi/linux/xdev_ext_mech.h \
		$(KERNEL_SRC)/include/uapi/linux/io_uring.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LIBBPF_CFLAGS) -iquote $(KERNEL_SRC)/include/uapi -I$(LIBDIR) \
		attack_guest.c $(LIBDIR)/xdev_ext_user.c $(LIBDIR)/xdev_ext_session.c $(SHARED_SOURCES) \
		$(LDFLAGS) -o $@ $(LIBBPF_LIBS) -lelf -lz -pthread

vmlinux.h: $(VMLINUX_BTF)
	@set -eu; temporary="$@.tmp"; trap 'rm -f "$$temporary"' EXIT; \
		$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c >"$$temporary"; \
		mv -f "$$temporary" "$@"

# attack_<mode>.bpf.o selects ATK_MODE=<MODE> (uppercased) at compile time.
attack_correct.bpf.o:  ATK := ATK_CORRECT
attack_reserved.bpf.o: ATK := ATK_RESERVED
attack_outside.bpf.o:  ATK := ATK_OUTSIDE
attack_frame.bpf.o:    ATK := ATK_FRAME
attack_verdict.bpf.o:  ATK := ATK_VERDICT

attack_%.bpf.o: attack.bpf.c vmlinux.h $(MECHDIR)/xdev_ext_mech_prog.h $(MECHDIR)/xdev_ext_mech_kfunc.h
	$(CLANG) $(BPF_CFLAGS) -DATK_MODE=$(ATK) -DATK_FIRST_KEY=1 -I. -I$(MECHDIR) -c attack.bpf.c -o $@

attack_user.bpf.o: attack_user.bpf.c vmlinux.h $(MECHDIR)/xdev_ext_mech_prog.h
	$(CLANG) $(BPF_CFLAGS) -I. -I$(MECHDIR) -c attack_user.bpf.c -o $@

clean:
	$(RM) attack_guest $(BPF_OBJS) vmlinux.h vmlinux.h.tmp
