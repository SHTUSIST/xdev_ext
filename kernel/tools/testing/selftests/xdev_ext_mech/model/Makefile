# SPDX-License-Identifier: GPL-2.0
#
# Bounded model check of io_uring/xdev_ext_mech_lifecycle.h together with the
# session, custody and quarantine rules of io_uring/xdev_ext_mech_core.h; see
# the comment at the top of life_explore.c.  "make model-check" explores the
# live headers in both granularities, then requires every seeded defect in
# mutants.py to be found.  The checker binary goes to $(OUTPUT); the mutant
# trees go to a temporary directory that is removed afterwards.

KERNEL_DIR ?= $(abspath ../../../../..)
OUTPUT ?= $(CURDIR)
XDEV_EXT_MECH_UBSAN ?= 1

MODEL_CFLAGS := -std=gnu11 -O2 -g -Wall -Wextra -Werror
ifeq ($(XDEV_EXT_MECH_UBSAN),1)
MODEL_CFLAGS += -fsanitize=undefined -fno-sanitize-recover=undefined
endif
MODEL_HDRS := $(KERNEL_DIR)/io_uring/xdev_ext_mech_lifecycle.h \
	$(KERNEL_DIR)/io_uring/xdev_ext_mech_core.h \
	$(KERNEL_DIR)/include/linux/xdev_ext_mech.h \
	$(KERNEL_DIR)/include/uapi/linux/xdev_ext_mech.h \
	$(wildcard shim/linux/*.h)

.PHONY: all model-check clean
all: $(OUTPUT)/life_explore

$(OUTPUT):
	mkdir -p $@

$(OUTPUT)/life_explore: life_explore.c $(MODEL_HDRS) | $(OUTPUT)
	$(CC) $(MODEL_CFLAGS) -I shim -I $(KERNEL_DIR) $< -o $@

model-check: $(OUTPUT)/life_explore
	cd $(KERNEL_DIR) && sha256sum io_uring/xdev_ext_mech_lifecycle.h \
		io_uring/xdev_ext_mech_core.h
	$(OUTPUT)/life_explore
	@set -e; tmp=$$(mktemp -d "$${TMPDIR:-/tmp}/xdev-life-mutants.XXXXXX"); \
	trap 'rm -rf "$$tmp"' EXIT; \
	CC="$(CC)" python3 mutants.py $(KERNEL_DIR) "$$tmp"

clean:
	rm -f $(OUTPUT)/life_explore
