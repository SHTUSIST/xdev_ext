# SPDX-License-Identifier: GPL-2.0
#
# E8 multi-tenant runner: run from the source view (tests/eval/isolation).
#   make check     host contracts (no device, no timing)
#   make tenant    uring_tenant (raw io_uring system calls; no liburing)
CC ?= cc
PYTHON ?= python3
BUILD ?= build
CFLAGS ?= -O2 -g
WARN = -std=gnu11 -Wall -Wextra -Werror

.PHONY: all tenant check clean
all: tenant
tenant: $(BUILD)/uring_tenant

$(BUILD):
	mkdir -p $@

$(BUILD)/uring_tenant: uring_tenant.c ../chains/uring_min.h ../nvme_gpu/nvme_gpu_core.h | $(BUILD)
	$(CC) $(WARN) $(CFLAGS) $< -o $@

check:
	$(PYTHON) -m unittest discover -s . -p 'test_*.py' -v

clean:
	rm -rf $(BUILD) __pycache__
