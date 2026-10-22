# SPDX-License-Identifier: GPL-2.0
# Project-owned IAA operations and mechanism adapter.
ifdef CONFIG_GCOV_PROFILE_URING
GCOV_PROFILE := y
endif

ccflags-y += -DXDEV_EXT_UMEM_ZEROCOPY
ccflags-$(CONFIG_IO_URING_XDEV_EXT_IAA) += -DXDEV_EXT_LIFECYCLE_SM=1
ccflags-$(CONFIG_IO_URING_XDEV_EXT_AFXDP_COPY) += -DXDEV_EXT_AFXDP_SEND=1

obj-$(CONFIG_IO_URING_XDEV_EXT_IAA) += xdev_ext_iaa.o
obj-$(CONFIG_XDEV_EXT_MECH_IAA) += xdev_ext_mech_iaa.o
