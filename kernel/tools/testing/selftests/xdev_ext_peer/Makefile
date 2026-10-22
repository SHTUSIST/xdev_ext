# SPDX-License-Identifier: GPL-2.0
CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror -fsanitize=undefined -pthread
TEST_GEN_PROGS := xdev_ext_peer_test xdev_ext_peer_nvme_test xdev_ext_peer_net_test xdev_ext_peer_mech_test xdev_ext_peer_net_plan_test
all: $(TEST_GEN_PROGS)
xdev_ext_peer_test: xdev_ext_peer_test.c xdev_ext_peer_test_shim.h ../../../../io_uring/xdev_ext_peer.c ../../../../include/linux/xdev_ext_peer.h
	$(CC) $(CFLAGS) $< -o $@
xdev_ext_peer_nvme_test: xdev_ext_peer_nvme_test.c ../../../../drivers/nvme/host/xdev_ext_peer_nvme_core.h
	$(CC) $(CFLAGS) $< -o $@
xdev_ext_peer_net_test: xdev_ext_peer_net_test.c ../../../../io_uring/xdev_ext_peer_net_core.h
	$(CC) $(CFLAGS) $< -o $@
xdev_ext_peer_mech_test: xdev_ext_peer_mech_test.c ../../../../io_uring/xdev_ext_mech_step.h ../../../../include/uapi/linux/xdev_ext_mech.h
	$(CC) $(CFLAGS) $< -o $@
xdev_ext_peer_net_plan_test: xdev_ext_peer_net_plan_test.c ../../../../io_uring/xdev_ext_mech_net_core.h
	$(CC) $(CFLAGS) $< -o $@
run_tests: all
	./xdev_ext_peer_test
	./xdev_ext_peer_nvme_test
	./xdev_ext_peer_net_test
	./xdev_ext_peer_mech_test
	./xdev_ext_peer_net_plan_test
	python3 xdev_ext_peer_claim_test.py
	python3 xdev_ext_peer_native_test.py
	python3 xdev_ext_peer_mlx5_test.py
	python3 independent_peer_lifetime.py
	python3 independent_peer_ioctl.py
	python3 independent_gpu_peer.py
	python3 independent_peer_net_completion.py
	@for test in ../xdev_ext_mech/peer_graph/*_test.py ../xdev_ext_mech/peer_graph/independent_*.py ../xdev_ext_mech/peer_graph/quality_*.py; do python3 "$$test" || exit $$?; done
clean:
	rm -f $(TEST_GEN_PROGS)
.PHONY: all run_tests clean
