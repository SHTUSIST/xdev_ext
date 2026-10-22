CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Werror -fsanitize=undefined
LDFLAGS += -fsanitize=undefined

TESTS := nv_xdev_ext_gpu_policy_test nv_xdev_ext_gpu_binding_test nv_xdev_ext_gpu_stub_test \
	 nv_xdev_ext_umem_quota_test nv_xdev_ext_handle_lifetime_test \
	 nv_xdev_ext_ce_chunk_test nv_xdev_ext_dma_lifetime_test \
	 nv_xdev_ext_gpu_identity_test nv_xdev_ext_ce_classify_test \
	 nv_xdev_ext_vidmem_offset_test nv_xdev_ext_ce_plan_test nv_xdev_ext_ce_async_test

.PHONY: all run run-async run-host-bookkeeping clean

all: $(TESTS)

nv_xdev_ext_gpu_policy_test: nv_xdev_ext_gpu_policy_test.c ../kernel-open/nvidia/nv-xdev_ext-gpu-policy.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

nv_xdev_ext_gpu_binding_test: nv_xdev_ext_gpu_binding_test.c \
		../kernel-open/nvidia/nv-xdev_ext-gpu.h fake_include/linux/xdev_ext_binding.h
	$(CC) $(CFLAGS) -DCONFIG_IO_URING_XDEV_EXT_BPF_POLICY=1 \
		-Ifake_include $< -o $@ $(LDFLAGS)

nv_xdev_ext_gpu_stub_test: nv_xdev_ext_gpu_stub_test.c \
		../kernel-open/nvidia/nv-xdev_ext-gpu.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

nv_xdev_ext_umem_quota_test: nv_xdev_ext_umem_quota_test.c \
		../kernel-open/nvidia/nv-xdev_ext-umem-quota.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -pthread

nv_xdev_ext_handle_lifetime_test: nv_xdev_ext_handle_lifetime_test.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -pthread

nv_xdev_ext_ce_chunk_test: nv_xdev_ext_ce_chunk_test.c \
		../src/nvidia/inc/kernel/mem_mgr/p2p_umem_chunk.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

nv_xdev_ext_dma_lifetime_test: nv_xdev_ext_dma_lifetime_test.c \
		../kernel-open/nvidia/nv-xdev_ext-dma-lifetime.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

nv_xdev_ext_gpu_identity_test: nv_xdev_ext_gpu_identity_test.c \
		../kernel-open/nvidia/nv-p2p-gpu-identity.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

nv_xdev_ext_ce_classify_test: nv_xdev_ext_ce_classify_test.c \
		../kernel-open/nvidia/nv-xdev_ext-ce-classify.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

nv_xdev_ext_vidmem_offset_test: nv_xdev_ext_vidmem_offset_test.c \
		../src/nvidia/inc/kernel/mem_mgr/p2p_umem_vidmem.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

nv_xdev_ext_ce_plan_test: nv_xdev_ext_ce_plan_test.c \
		../kernel-open/nvidia/nv-xdev_ext-ce-plan.h \
		../kernel-open/nvidia/nv-xdev_ext-gpu-policy.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# wildcard keeps the missing-feature RED executable buildable before the
# production helper exists; the test includes it directly once implemented.
nv_xdev_ext_ce_async_test: nv_xdev_ext_ce_async_test.c nv_xdev_ext_ce_async_contract.h \
		$(wildcard ../kernel-open/nvidia/nv-xdev_ext-ce-async.h)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

run-async: nv_xdev_ext_ce_async_test
	@status=0; ./nv_xdev_ext_ce_async_test || status=1; \
		python3 nv_xdev_ext_ce_async_source_test.py || status=1; exit $$status

run-host-bookkeeping:
	CC=$(CC) python3 nv_xdev_ext_umem_host_contract_test.py -v

run: $(TESTS)
	@for test in $(TESTS); do ./$$test || exit $$?; done
	python3 nv_xdev_ext_gpu_source_test.py
	python3 nv_xdev_ext_ce_async_source_test.py
	python3 nv_xdev_ext_ce_fence_algorithm_test.py
	$(MAKE) run-host-bookkeeping

clean:
	rm -f $(TESTS)
