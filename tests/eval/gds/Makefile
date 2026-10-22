PYTHON ?= python3
CUDA_ROOT ?= /usr/local/cuda

.PHONY: all check clean
all:
	$(PYTHON) run.py --mode cufile-direct --workload llm-load --bytes 4096 --chunk 4096 --iterations 1 --directory . --cuda-root $(CUDA_ROOT) --build-only

check:
	$(PYTHON) test_gds.py -v

clean:
	rm -rf build __pycache__
