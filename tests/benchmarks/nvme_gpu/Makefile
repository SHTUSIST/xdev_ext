PYTHON ?= python3
CUDA_ROOT ?= /usr/local/cuda
BUILD_DIR ?= build

.PHONY: all check probe cuda-build clean
# Host build of the session arm; the CUDA arms need an official SDK.
all:
	$(PYTHON) run.py --arms session --sizes 4096 --qd 1 --build-only

check:
	$(PYTHON) test_contract.py -v
	$(PYTHON) -B test_ce_vmm.py -v
	$(PYTHON) -B test_ce_runtime.py -v
	$(PYTHON) -B test_ce_probe.py -v
	$(PYTHON) -B test_ce_submit_diag.py -v
	$(PYTHON) -B test_session_timing.py -v
	$(PYTHON) -B test_delegate_build.py -v
	$(PYTHON) -B test_session_rand.py -v

probe:
	mkdir -p $(BUILD_DIR)
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror ce_vmm_probe.c \
		../../../kernel/tools/xdev_ext_gpu_identity.c -ldl -o $(BUILD_DIR)/ce_vmm_probe
	$(CC) -std=gnu11 -O2 -g -Wall -Wextra -Werror ce_submit_diag.c \
		../../../kernel/tools/xdev_ext_gpu_identity.c -ldl -lpthread -o $(BUILD_DIR)/ce_submit_diag

cuda-build:
	$(PYTHON) run.py --arms uring-cuda,gds-batch,gds-async --sizes 4096 --qd 1 \
		--build-only --cuda-root $(CUDA_ROOT)

clean:
	rm -rf build __pycache__
