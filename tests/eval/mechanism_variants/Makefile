# SPDX-License-Identifier: GPL-2.0
CC ?= cc
CLANG ?= clang
BUILD ?= .build
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror
.PHONY: all sink check bpf
all: sink bpf
sink: $(BUILD)/mv_sink
$(BUILD):
	mkdir -p $@
$(BUILD)/mv_sink: mv_sink.c | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@
bpf:
	$(MAKE) -C tests bpf CLANG=$(CLANG)
check:
	$(MAKE) -C tests check
	python3 -B test_helpers.py -v
