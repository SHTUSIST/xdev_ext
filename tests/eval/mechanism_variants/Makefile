# SPDX-License-Identifier: GPL-2.0
CC ?= cc
CLANG ?= clang
BUILD ?= .build
LIBBPF_LIBS ?= -lbpf
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror
.PHONY: all sink ctl check bpf
all: sink ctl bpf
sink: $(BUILD)/mv_sink
ctl: $(BUILD)/mv_ctl
$(BUILD):
	mkdir -p $@
$(BUILD)/mv_sink: mv_sink.c | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@
$(BUILD)/mv_ctl: mv_ctl.c mv_create_capture.h mv_umem_guard.h mv_policy_capture.h ../../../kernel/tools/xdev_ext_mech/xdev_ext_mech_ctl.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) mv_ctl.c ../../../kernel/tools/xdev_ext_xsk_redirect.c ../../../kernel/tools/xdev_ext_gpu_identity.c -o $@ $(LDFLAGS) $(LIBBPF_LIBS) -lelf -lz -ldl
$(BUILD)/test_umem_guard: test_umem_guard.c mv_umem_guard.h mv_create_capture.h | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@
$(BUILD)/test_create_capture: test_create_capture.c mv_create_capture.h | $(BUILD)
	$(CC) $(CFLAGS) -D_GNU_SOURCE $< -o $@
bpf:
	$(MAKE) -C tests bpf CLANG=$(CLANG)
check: $(BUILD)/test_create_capture $(BUILD)/test_umem_guard
	$(MAKE) -C tests check
	python3 -B test_helpers.py -v
	python3 -B test_artifacts.py -v
	python3 -B test_capture_transport.py -v
	python3 -B test_export_old_ticket.py -v
	python3 -B test_kvm_wiring.py -v
	python3 -B test_old_ticket_cache.py -v
	python3 -B test_trace_config.py -v
	python3 -B test_decode.py -v
	python3 -B test_decode_regressions.py -v
	python3 -B test_driver_audit.py -v
	python3 -B test_driver_identity.py -v
	python3 -B test_driver_backing_diagnostics.py -v
	python3 -B test_decode_session_bind.py -v
	python3 -B test_negative_recycle.py -v
	python3 -B test_zero_generation.py -v
	python3 -B test_archive_relocation.py -v
	python3 -B test_guard.py -v
	python3 -B test_inspect_create.py -v
	@temporary=$$(mktemp -d); trap 'rm -rf "$$temporary"' EXIT; $(BUILD)/test_create_capture "$$temporary/create"

	@temporary=$$(mktemp -d); trap 'rm -rf "$$temporary"' EXIT; $(BUILD)/test_umem_guard "$$temporary/good" good && $(BUILD)/test_umem_guard "$$temporary/bad" corrupt
