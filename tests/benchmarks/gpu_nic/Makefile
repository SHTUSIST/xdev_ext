PYTHON ?= python3
CUDA_ROOT ?= /usr/local/cuda

.PHONY: all check cuda-build clean
# Host builds of the session arm and the NXP peer; the CUDA arms need an SDK.
all:
	$(PYTHON) run.py --arms session --direction nic-gpu --shape ingest --build-only

check:
	$(PYTHON) test_contract.py -v

cuda-build:
	$(PYTHON) run.py --arms afxdp-cuda,udp-pinned-cuda --direction nic-gpu --shape ingest \
		--build-only --cuda-root $(CUDA_ROOT)

clean:
	rm -rf build __pycache__
