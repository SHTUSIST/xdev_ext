# SPDX-License-Identifier: GPL-2.0

# xdev_ext_xsk_redirect_testrun loads programs and runs BPF_PROG_TEST_RUN only; it
# never attaches to an interface and exits 4 (skip) without uid 0.
TEST_GEN_PROGS := xsk_xdev_ext_core_test xsk_xdev_ext_fake_driver_test \
		  xsk_xdev_ext_rx_fake_driver_test xsk_xdev_ext_mech_tx_test xsk_xdev_ext_mech_zc_test \
		  xsk_xdev_ext_mech_zc_fifo_test \
		  xdev_ext_xsk_redirect_test xdev_ext_xsk_redirect_testrun
TEST_PROGS := xsk_xdev_ext_mech_reliable_submit_test.py xsk_xdev_ext_mech_reliable_packet_test.py
TEST_PROGS += xsk_xdev_ext_mech_backlog_test.py
TEST_FILES += xsk_xdev_ext_mech_backlog_fixture.c
TEST_PROGS += xsk_xdev_ext_mech_publication_test.py xsk_xdev_ext_source_test.py xsk_xdev_ext_mech_source_test.py

LOCAL_HDRS += $(abspath ../../../../net/xdp/xsk_xdev_ext_core.h)
LOCAL_HDRS += $(abspath ../../../../net/xdp/xsk_xdev_ext_rx_core.h)
LOCAL_HDRS += $(abspath ../../../../net/xdp/xsk_xdev_ext_mech_core.h)
LOCAL_HDRS += $(abspath ../../../../net/xdp/xsk_xdev_ext_mech_tx_core.h)
LOCAL_HDRS += $(abspath ../../../../net/xdp/xsk_xdev_ext_mech_zc_core.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_core.h)
LOCAL_HDRS += $(abspath ../../../include/xdev_ext_xsk_redirect.h)
LOCAL_HDRS += $(abspath ../../../include/xdev_ext_xsk_redirect_prog.h)
LOCAL_HDRS += $(abspath ../../../xdev_ext_bpf_raw.h)

CFLAGS += -std=gnu11 -O2 -g -Wall -Wextra -Werror $(KHDR_INCLUDES)

include ../lib.mk

$(OUTPUT)/xdev_ext_xsk_redirect_test: xdev_ext_xsk_redirect_test.c \
				       ../../../xdev_ext_xsk_redirect.c $(LOCAL_HDRS)
	$(CC) $(CFLAGS) -I../../.. $< ../../../xdev_ext_xsk_redirect.c \
		-o $@ $(LDFLAGS) -lbpf

.PHONY: run
run: run_tests
