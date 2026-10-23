CC ?= cc
CFLAGS ?= -O2 -g
CPPFLAGS += -D_FILE_OFFSET_BITS=64
WARN = -std=c11 -Wall -Wextra -Werror
BUILD ?= build
ENABLE_URING ?= 0

ifeq ($(ENABLE_URING),1)
ifeq ($(shell pkg-config --exists liburing && echo yes),)
$(error ENABLE_URING=1 requires liburing development headers and pkg-config)
endif
URING_CPPFLAGS = -DEVAL_HAVE_LIBURING $(shell pkg-config --cflags liburing)
URING_LIBS = $(shell pkg-config --libs liburing)
endif

.PHONY: all check run clean FORCE gds-check hft hft-check cuda-host-check
.PHONY: chains-check uo-check nvme-nic-check nvme-gpu-check gpu-nic-check bam-check eval-cost-check reviewer-eval-check
all: $(BUILD)/bench_file_pipeline $(BUILD)/bench_cuda_staging

$(BUILD):
	mkdir -p $@

$(BUILD)/config: FORCE | $(BUILD)
	@echo 'ENABLE_URING=$(ENABLE_URING)' | cmp -s - $@ || echo 'ENABLE_URING=$(ENABLE_URING)' > $@

$(BUILD)/bench_file_pipeline: bench_file_pipeline.c eval_common.h Makefile $(BUILD)/config | $(BUILD)
	$(CC) $(CPPFLAGS) $(URING_CPPFLAGS) $(CFLAGS) $(WARN) -o $@ $< -pthread $(URING_LIBS)

$(BUILD)/bench_cuda_staging: bench_cuda_staging.c eval_common.h Makefile | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARN) -o $@ $< -ldl

check: all
	python3 test_eval.py

run: all
	python3 run.py

gds-check:
	$(MAKE) -C gds check

hft:
	$(MAKE) -C hft all

hft-check:
	$(MAKE) -C hft check

cuda-host-check:
	$(MAKE) -C cuda_host_compute test

chains-check:
	$(MAKE) -C chains check

uo-check:
	$(MAKE) -C userspace_orchestrator check

nvme-nic-check:
	$(MAKE) -C nvme_nic check

nvme-gpu-check:
	$(MAKE) -C nvme_gpu check

gpu-nic-check:
	$(MAKE) -C gpu_nic check

bam-check:
	$(MAKE) -C bam check

eval-cost-check:
	$(MAKE) -C common check
	$(MAKE) -C setup_cost check BUILD=$(abspath $(BUILD))/setup_cost
	$(MAKE) -C breakdown check
	$(MAKE) -C providers check

# Host-side contracts of the reviewer-driven harnesses; no timing.
reviewer-eval-check: chains-check uo-check nvme-nic-check nvme-gpu-check gpu-nic-check bam-check eval-cost-check

clean:
	rm -rf $(BUILD) __pycache__
