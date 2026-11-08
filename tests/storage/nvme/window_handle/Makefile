# SPDX-License-Identifier: GPL-2.0
# Guest program and BPF object of the NVMe LBA window handle test.
# window_kvm.sh builds this against the assembled native tree of the exact
# product commit (KERNEL_SRC: its UAPI headers and BPF program headers) and
# the tested kernel's BTF.
KERNEL_SRC ?= $(abspath ../../../..)
MECHDIR := $(KERNEL_SRC)/tools/xdev_ext_mech
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror -pthread
LIBBPF_CFLAGS ?=
LIBBPF_LIBS ?= -lbpf
CLANG ?= clang
BPFTOOL ?= bpftool
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
BPF_CFLAGS ?= -O2 -g -Wall -Wextra -Werror -target bpf -D__TARGET_ARCH_x86

.PHONY: all clean
all: window_guest window_nvme.bpf.o

window_guest: window_guest.c window_multi.h window_reuse.h $(KERNEL_SRC)/include/uapi/linux/xdev_ext_mech.h \
		$(KERNEL_SRC)/include/uapi/linux/io_uring.h \
		$(KERNEL_SRC)/include/uapi/linux/nvme_ioctl.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LIBBPF_CFLAGS) -iquote $(KERNEL_SRC)/include/uapi \
		window_guest.c $(LDFLAGS) -o $@ $(LIBBPF_LIBS) -lelf -lz -pthread

vmlinux.h: $(VMLINUX_BTF)
	@set -eu; temporary="$@.tmp"; trap 'rm -f "$$temporary"' EXIT; \
		$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c >"$$temporary"; \
		mv -f "$$temporary" "$@"

window_nvme.bpf.o: window_nvme.bpf.c vmlinux.h $(MECHDIR)/xdev_ext_mech_prog.h $(MECHDIR)/xdev_ext_mech_kfunc.h
	$(CLANG) $(BPF_CFLAGS) -I. -I$(MECHDIR) -c window_nvme.bpf.c -o $@

clean:
	$(RM) window_guest window_nvme.bpf.o vmlinux.h vmlinux.h.tmp
