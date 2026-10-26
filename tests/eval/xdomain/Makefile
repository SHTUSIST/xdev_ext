# SPDX-License-Identifier: GPL-2.0
PYTHON ?= python3
HOST_CXX ?= g++
CUDA_ARCH ?= sm_80
BUILD ?= build
.PHONY: check test-epoch test-protocol test-retention test-build test-gpu-contract sdk-build
check: test-epoch test-protocol test-retention test-build
test-epoch:
	$(PYTHON) -B test_epoch_control.py
test-protocol:
	$(PYTHON) -B test_contract.py
	$(PYTHON) -B test_oracle.py
	$(PYTHON) -B test_cases.py
test-retention:
	$(PYTHON) -B test_retention.py
test-build:
	$(PYTHON) -B test_build.py
test-gpu-contract:
	$(PYTHON) -B test_gpu_contract.py --cuda-home "$(CUDA_HOME)"
sdk-build:
	$(PYTHON) -B build.py --cuda-home "$(CUDA_HOME)" --host-cxx "$(HOST_CXX)" --arch "$(CUDA_ARCH)" --out "$(BUILD)"
