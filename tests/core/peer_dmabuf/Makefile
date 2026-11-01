# SPDX-License-Identifier: GPL-2.0
CC = gcc
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../../..)
OUTPUT ?= $(ROOT)/build/native-tests/dmabuf_import
CFLAGS ?= -O2 -g

.PHONY: all cli-test
all: $(OUTPUT)

$(OUTPUT): $(ROOT)/tests/core/peer_dmabuf/native_import.c $(ROOT)/src/core/include/uapi/linux/xdev_ext_peer.h
	mkdir -p $(dir $(OUTPUT))
	$(CC) $(CFLAGS) -std=gnu11 -Wall -Wextra -Werror -I$(ROOT)/src/core/include/uapi $< -o $@

cli-test: $(OUTPUT)
	python3 -I $(ROOT)/tests/core/peer_dmabuf/native_cli_test.py $(OUTPUT)
