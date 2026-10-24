PYTHON ?= python3
CUDA_ROOT ?= /usr/local/cuda

.PHONY: all check cuda-build clean
# Host build of the session arm; the CUDA arms need an official SDK.
all:
	$(PYTHON) run.py --arms session --sizes 4096 --qd 1 --build-only

check:
	$(PYTHON) test_contract.py -v
	$(PYTHON) -B test_session_timing.py -v
	$(PYTHON) -B test_delegate_build.py -v

cuda-build:
	$(PYTHON) run.py --arms uring-cuda,gds-batch,gds-async --sizes 4096 --qd 1 \
		--build-only --cuda-root $(CUDA_ROOT)

clean:
	rm -rf build __pycache__
