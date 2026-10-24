# SPDX-License-Identifier: GPL-2.0
#
# Makefile for io_uring

ifdef CONFIG_GCOV_PROFILE_URING
GCOV_PROFILE := y
endif

# XDEV_EXT UMEM zero-copy feature flag (comment out to disable)
ccflags-y += -DXDEV_EXT_UMEM_ZEROCOPY
ccflags-$(CONFIG_IO_URING_XDEV_EXT_IAA) += -DXDEV_EXT_LIFECYCLE_SM=1
ccflags-$(CONFIG_IO_URING_XDEV_EXT_AFXDP_COPY) += -DXDEV_EXT_AFXDP_SEND=1

obj-$(CONFIG_IO_URING)		+= io_uring.o opdef.o kbuf.o rsrc.o notif.o \
					tctx.o filetable.o rw.o poll.o \
					eventfd.o uring_cmd.o openclose.o \
					sqpoll.o xattr.o nop.o fs.o splice.o \
					sync.o msg_ring.o advise.o openclose.o \
					statx.o timeout.o cancel.o \
					waitid.o register.o truncate.o \
					memmap.o alloc_cache.o unified_ops.o \
					sched_hints.o \
					xdev_ext_umem.o
obj-$(CONFIG_IO_URING_ZCRX)	+= zcrx.o
obj-$(CONFIG_IO_URING_XDEV_EXT_BPF_POLICY) += xdev_ext_ops_core.o xdev_ext_binding.o
obj-$(CONFIG_XDEV_EXT_MECH) += xdev_ext_mech.o xdev_ext_mech_ops.o xdev_ext_peer.o xdev_ext_peer_fd.o xdev_ext_peer_net.o xdev_ext_mech_peer_pool.o xdev_ext_mech_net.o
obj-$(CONFIG_XDEV_EXT_MECH_CE) += xdev_ext_mech_ce.o
obj-$(CONFIG_XDEV_EXT_MECH_DMA) += xdev_ext_mech_dma.o
obj-$(CONFIG_IO_WQ)		+= io-wq.o
obj-$(CONFIG_FUTEX)		+= futex.o
obj-$(CONFIG_EPOLL)		+= epoll.o
obj-$(CONFIG_NET_RX_BUSY_POLL)	+= napi.o
obj-$(CONFIG_NET) += net.o cmd_net.o
obj-$(CONFIG_PROC_FS) += fdinfo.o

obj-y += iaa/
obj-$(CONFIG_XDEV_EXT_MECH_SOCKET) += xdev_ext_mech_socket.o

obj-$(CONFIG_XDEV_EXT_MECH_CPU) += xdev_ext_mech_cpu.o
