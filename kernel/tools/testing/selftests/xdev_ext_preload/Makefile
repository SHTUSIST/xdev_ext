# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := xdev_ext_preload_core_test xdev_ext_preload_fd_shard_test \
	xdev_ext_preload_socket_core_test xdev_ext_preload_socket_smoke \
	xdev_ext_preload_socket_mech_test \
	xdev_ext_preload_ce_concurrency_test \
	xdev_ext_preload_config_test xdev_ext_preload_admission_test \
	xdev_ext_preload_reg_test \
	xdev_ext_preload_ring128_test xdev_ext_preload_ring128_model_check \
	xdev_ext_preload_nvme_pt_test \
	xdev_ext_preload_rx_core_test
TEST_PROGS := xdev_ext_preload_vfs_source_test.sh \
	xdev_ext_preload_concurrency_test.py \
	xdev_ext_preload_efault_test.py \
	xdev_ext_preload_positional_efault_test.py \
	xdev_ext_preload_payload_integrity_test.py \
	independent_mech_fork_inherited.py \
	independent_mech_fork_teardown.py \
	independent_ordinary_fork_lifetime.py \
	xdev_ext_preload_socket_source_test.py xdev_ext_preload_db_equivalence.sh
# Run by xdev_ext_preload_db_equivalence.sh.  The KVM harness copies only
# xdev_ext_preload_db_workload into the guest and runs it in phase
# db-workload-preload-ext4; the guest does not run
# xdev_ext_preload_db_equivalence.sh or xdev_ext_preload_cancel_wait.
TEST_GEN_PROGS_EXTENDED := xdev_ext_preload_db_workload xdev_ext_preload_cancel_wait \
	xdev_ext_preload_mech_workload \
	xdev_ext_preload_fortify xdev_ext_preload_buffered_cost
TEST_GEN_FILES := libio_uring_unified.so libxdev_ext_preload_kernel_model.so
TEST_FILES += xdev_ext_preload_payload_fault_fixture.c \
	xdev_ext_preload_mech_workload.c \
	independent_ordinary_fork_lifetime_fixture.c
# The independent fork tests extract production functions and require the
# kernel source tree; copying TEST_PROGS/TEST_FILES alone is not sufficient.

# lib.mk only supplies this default at MAKELEVEL=0.  This test is also run by
# tools/Makefile.unified_ops through a recursive make.
ifeq ($(OUTPUT),)
OUTPUT := $(CURDIR)
endif

CFLAGS += -std=gnu11 -O2 -g -Wall -Wextra -Werror -pthread \
	-I$(CURDIR)/../../../
LDLIBS += -pthread

LOCAL_HDRS += $(abspath ../../../xdev_ext_preload_core.h)
LOCAL_HDRS += $(abspath ../../../xdev_ext_preload_socket_mech.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/xdev_ext_mech_ce_lease.h)
LOCAL_HDRS += $(abspath ../../../../include/uapi/linux/xdev_ext_mech.h)
LOCAL_HDRS += $(abspath ../../../xdev_ext_preload_fd_shard.h)
LOCAL_HDRS += $(abspath ../../../xdev_ext_preload_config.h)
LOCAL_HDRS += $(abspath ../../../xdev_ext_preload_config_backend.h)
LOCAL_HDRS += $(abspath ../../../xdev_ext_preload_admission.h)
LOCAL_HDRS += $(abspath ../../../xdev_ext_preload_reg.h)
LOCAL_HDRS += $(abspath ../../../xdev_ext_preload_privfd.h)
LOCAL_HDRS += $(abspath ../../../../include/uapi/linux/close_range.h)
LOCAL_HDRS += $(abspath ../../../xdev_ext_preload_ring128.h)
LOCAL_HDRS += $(abspath ../../../xdev_ext_preload_sink.h)
LOCAL_HDRS += $(abspath ../../../xdev_ext_preload_sink_nvme_pt.h)
LOCAL_HDRS += $(abspath ../../../../include/uapi/linux/nvme_ioctl.h)
LOCAL_HDRS += $(abspath ../../../xdev_ext_preload_rx_core.h)
LOCAL_HDRS += $(abspath ../../../../include/uapi/linux/io_uring.h)
LOCAL_HDRS += $(abspath ../../../../io_uring/unified_ops_core.h)
LOCAL_HDRS += $(abspath ../../../../xdev_ext_frame_sm.h)

include ../lib.mk

$(OUTPUT)/xdev_ext_preload_cancel_wait: LDLIBS += -ldl
# The config test also covers the knobs only a test build of the front end reads.
$(OUTPUT)/xdev_ext_preload_config_test: CFLAGS += -DXDEV_EXT_PRELOAD_TEST_HOOKS
$(OUTPUT)/xdev_ext_preload_buffered_cost: LDLIBS += -ldl
# Re-executes itself with libxdev_ext_preload_kernel_model.so from its directory.
$(OUTPUT)/xdev_ext_preload_ring128_model_check: LDLIBS += -ldl
# Fortified code reaches __pread_chk/__pread64_chk instead of pread/pread64.
$(OUTPUT)/xdev_ext_preload_fortify: CFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
$(OUTPUT)/xdev_ext_preload_fortify: LDLIBS += -ldl

# A private build of the front end keeps this directory self-contained.
$(OUTPUT)/libio_uring_unified.so: ../../../io_uring_unified_preload.c \
	$(LOCAL_HDRS) ../../../../include/uapi/linux/stat.h \
	../../../include/io_uring/mini_liburing.h
	$(CC) -shared -fPIC $(CFLAGS) -o $@ $< -ldl -pthread

$(OUTPUT)/libxdev_ext_preload_kernel_model.so: xdev_ext_preload_kernel_model.c \
	$(LOCAL_HDRS)
	$(CC) -shared -fPIC $(CFLAGS) -o $@ $< -ldl -pthread

# lib.mk runs TEST_PROGS from this source directory, also when OUTPUT is
# elsewhere; xdev_ext_preload_db_equivalence.sh finds its programs through this.
run_tests: export XDEV_EXT_PRELOAD_TEST_DIR := $(abspath $(OUTPUT))

.PHONY: run sanitize
run: run_tests

sanitize:
	@set -eu; \
	bin="$(OUTPUT)/.xdev_ext_preload_core_test_sanitize"; \
	shard_bin="$(OUTPUT)/.xdev_ext_preload_fd_shard_test_sanitize"; \
	trap 'rm -f "$$bin" "$$shard_bin"' EXIT; \
	$(CC) $(CFLAGS) -O1 \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		xdev_ext_preload_core_test.c $(LDFLAGS) $(LDLIBS) \
		-fsanitize=address,undefined -o "$$bin"; \
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 \
		"$$bin"; \
	$(CC) $(CFLAGS) -O1 \
		-fsanitize=address,undefined -fno-omit-frame-pointer \
		xdev_ext_preload_fd_shard_test.c $(LDFLAGS) $(LDLIBS) \
		-fsanitize=address,undefined -o "$$shard_bin"; \
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
		UBSAN_OPTIONS=halt_on_error=1 \
			"$$shard_bin"; \
		socket_bin="$(OUTPUT)/.xdev_ext_preload_socket_core_test_sanitize"; \
		trap 'rm -f "$$bin" "$$shard_bin" "$$socket_bin"' EXIT; \
		$(CC) $(CFLAGS) -O1 \
			-fsanitize=address,undefined -fno-omit-frame-pointer \
			xdev_ext_preload_socket_core_test.c $(LDFLAGS) $(LDLIBS) \
			-fsanitize=address,undefined -o "$$socket_bin"; \
		ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
			UBSAN_OPTIONS=halt_on_error=1 \
			"$$socket_bin"; \
		config_bin="$(OUTPUT)/.xdev_ext_preload_config_test_sanitize"; \
		trap 'rm -f "$$bin" "$$shard_bin" "$$socket_bin" "$$config_bin"' EXIT; \
		$(CC) $(CFLAGS) -O1 -DXDEV_EXT_PRELOAD_TEST_HOOKS \
			-fsanitize=address,undefined -fno-omit-frame-pointer \
			xdev_ext_preload_config_test.c $(LDFLAGS) $(LDLIBS) \
			-fsanitize=address,undefined -o "$$config_bin"; \
		: "The constructor checks load an uninstrumented front end."; \
		env -u XDEV_EXT_PRELOAD_TEST_DIR \
			ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
			UBSAN_OPTIONS=halt_on_error=1 \
			"$$config_bin"; \
		gate_bin="$(OUTPUT)/.xdev_ext_preload_admission_test_sanitize"; \
		trap 'rm -f "$$bin" "$$shard_bin" "$$socket_bin" "$$config_bin" "$$gate_bin"' EXIT; \
		$(CC) $(CFLAGS) -O1 \
			-fsanitize=address,undefined -fno-omit-frame-pointer \
			xdev_ext_preload_admission_test.c $(LDFLAGS) $(LDLIBS) \
			-fsanitize=address,undefined -o "$$gate_bin"; \
		ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
			UBSAN_OPTIONS=halt_on_error=1 \
			"$$gate_bin"; \
		reg_bin="$(OUTPUT)/.xdev_ext_preload_reg_test_sanitize"; \
		trap 'rm -f "$$bin" "$$shard_bin" "$$socket_bin" "$$config_bin" "$$gate_bin" "$$reg_bin"' EXIT; \
		$(CC) $(CFLAGS) -O1 \
			-fsanitize=address,undefined -fno-omit-frame-pointer \
			xdev_ext_preload_reg_test.c $(LDFLAGS) $(LDLIBS) \
			-fsanitize=address,undefined -o "$$reg_bin"; \
		: "use_sigaltstack=0: the cancellation cases unwind threads"; \
		: "with pthread_cancel (see the db step below)."; \
		ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:use_sigaltstack=0 \
			UBSAN_OPTIONS=halt_on_error=1 \
			"$$reg_bin"; \
		ring128_bin="$(OUTPUT)/.xdev_ext_preload_ring128_test_sanitize"; \
		ring128_dir="$(OUTPUT)/.xdev_ext_preload_ring128_sanitize"; \
		trap 'rm -rf "$$bin" "$$shard_bin" "$$socket_bin" "$$config_bin" "$$gate_bin" "$$reg_bin" "$$ring128_bin" "$$ring128_dir"' EXIT; \
		$(CC) $(CFLAGS) -O1 \
			-fsanitize=address,undefined -fno-omit-frame-pointer \
			xdev_ext_preload_ring128_test.c $(LDFLAGS) $(LDLIBS) \
			-fsanitize=address,undefined -o "$$ring128_bin"; \
		ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
			UBSAN_OPTIONS=halt_on_error=1 \
			"$$ring128_bin"; \
		rm -rf "$$ring128_dir"; \
		mkdir -p "$$ring128_dir"; \
		$(CC) $(CFLAGS) -O1 \
			-fsanitize=address,undefined -fno-omit-frame-pointer \
			xdev_ext_preload_ring128_model_check.c $(LDFLAGS) $(LDLIBS) \
			-ldl -o "$$ring128_dir/xdev_ext_preload_ring128_model_check"; \
		$(CC) -shared -fPIC $(CFLAGS) -O1 \
			-fsanitize=address,undefined -fno-omit-frame-pointer \
			xdev_ext_preload_kernel_model.c -ldl -pthread \
			-o "$$ring128_dir/libxdev_ext_preload_kernel_model.so"; \
		: "The model check preloads the model next to itself."; \
		ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
			UBSAN_OPTIONS=halt_on_error=1 \
			XDEV_EXT_PRELOAD_TEST_LD_PREFIX="$$($(CC) -print-file-name=libasan.so)" \
			"$$ring128_dir/xdev_ext_preload_ring128_model_check"; \
		nvme_pt_bin="$(OUTPUT)/.xdev_ext_preload_nvme_pt_test_sanitize"; \
		trap 'rm -rf "$$bin" "$$shard_bin" "$$socket_bin" "$$config_bin" "$$gate_bin" "$$reg_bin" "$$ring128_bin" "$$ring128_dir" "$$nvme_pt_bin"' EXIT; \
		$(CC) $(CFLAGS) -O1 \
			-fsanitize=address,undefined -fno-omit-frame-pointer \
			xdev_ext_preload_nvme_pt_test.c $(LDFLAGS) $(LDLIBS) \
			-fsanitize=address,undefined -o "$$nvme_pt_bin"; \
		ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
			UBSAN_OPTIONS=halt_on_error=1 \
			"$$nvme_pt_bin"; \
		rx_bin="$(OUTPUT)/.xdev_ext_preload_rx_core_test_sanitize"; \
		trap 'rm -rf "$$bin" "$$shard_bin" "$$socket_bin" "$$config_bin" "$$gate_bin" "$$reg_bin" "$$ring128_bin" "$$ring128_dir" "$$nvme_pt_bin" "$$rx_bin"' EXIT; \
		$(CC) $(CFLAGS) -O1 \
			-fsanitize=address,undefined -fno-omit-frame-pointer \
			xdev_ext_preload_rx_core_test.c $(LDFLAGS) $(LDLIBS) \
			-fsanitize=address,undefined -o "$$rx_bin"; \
		ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
			UBSAN_OPTIONS=halt_on_error=1 \
			"$$rx_bin"; \
		db_dir="$(OUTPUT)/.xdev_ext_preload_db_sanitize"; \
		trap 'rm -rf "$$bin" "$$shard_bin" "$$socket_bin" "$$config_bin" "$$gate_bin" "$$reg_bin" "$$ring128_bin" "$$ring128_dir" "$$nvme_pt_bin" "$$rx_bin" "$$db_dir"' EXIT; \
		rm -rf "$$db_dir"; \
		mkdir -p "$$db_dir"; \
		san="-O1 -fsanitize=address,undefined -fno-omit-frame-pointer"; \
		$(CC) $(CFLAGS) $$san xdev_ext_preload_db_workload.c $(LDFLAGS) \
			$(LDLIBS) -o "$$db_dir/xdev_ext_preload_db_workload"; \
		$(CC) $(CFLAGS) $$san xdev_ext_preload_cancel_wait.c $(LDFLAGS) \
			$(LDLIBS) -ldl -o "$$db_dir/xdev_ext_preload_cancel_wait"; \
		$(CC) $(CFLAGS) $$san xdev_ext_preload_buffered_cost.c $(LDFLAGS) \
			$(LDLIBS) -ldl -o "$$db_dir/xdev_ext_preload_buffered_cost"; \
		$(CC) $(CFLAGS) $$san -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 \
			xdev_ext_preload_fortify.c $(LDFLAGS) $(LDLIBS) -ldl \
			-o "$$db_dir/xdev_ext_preload_fortify"; \
		$(CC) -shared -fPIC $(CFLAGS) $$san \
			../../../io_uring_unified_preload.c -ldl -pthread \
			-o "$$db_dir/libio_uring_unified.so"; \
		$(CC) -shared -fPIC $(CFLAGS) $$san xdev_ext_preload_kernel_model.c \
			-ldl -pthread -o "$$db_dir/libxdev_ext_preload_kernel_model.so"; \
		cp xdev_ext_preload_db_equivalence.sh "$$db_dir/"; \
		: "use_sigaltstack=0: libasan unsets its signal stack before"; \
		: "clearing the shadow of a thread unwound by pthread_cancel."; \
		ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:use_sigaltstack=0 \
			UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
			XDEV_EXT_PRELOAD_TEST_LD_PREFIX="$$($(CC) -print-file-name=libasan.so)" \
			XDEV_EXT_PRELOAD_TEST_DIR="$$db_dir" \
			"$$db_dir/xdev_ext_preload_db_equivalence.sh"
