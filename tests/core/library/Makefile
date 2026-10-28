# SPDX-License-Identifier: GPL-2.0
#
# Host unit tests of libxdev_ext (no device, no privilege).
#	make run          session tests and one-call/program validation tests
#	make run-session  session and USER stage tests only (no libbpf needed)
# Output is TAP; a nonzero exit is a failure.

CC ?= gcc
KSRC := $(abspath ../../../..)
LIBDIR := $(KSRC)/tools/xdev_ext_mech/lib
OUTPUT ?= $(CURDIR)/.build

CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror -I$(KSRC) -I$(LIBDIR)
XDEV_EXT_LIB_SANITIZE ?= 1
ifeq ($(XDEV_EXT_LIB_SANITIZE),1)
CFLAGS += -fsanitize=address,undefined -fno-sanitize-recover=undefined
LDFLAGS += -fsanitize=address,undefined
endif

# libbpf >= 1.0; override both for a libbpf outside the system paths.
LIBBPF_CFLAGS ?=
LIBBPF_LIBS ?= -lbpf
CFLAGS += $(LIBBPF_CFLAGS)

LIB_HDRS := $(wildcard $(LIBDIR)/*.h) $(KSRC)/tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h \
	$(KSRC)/include/uapi/linux/xdev_ext_mech.h
SESSION_TEST := $(OUTPUT)/xdev_ext_lib_session_test
RUN_TEST := $(OUTPUT)/xdev_ext_lib_run_test
USER_TEST := $(OUTPUT)/xdev_ext_lib_user_test

all: $(SESSION_TEST) $(RUN_TEST) $(USER_TEST)

$(OUTPUT):
	mkdir -p $@

$(SESSION_TEST): xdev_ext_lib_session_test.c $(LIBDIR)/xdev_ext_session.c $(LIB_HDRS) | $(OUTPUT)
	$(CC) $(CFLAGS) xdev_ext_lib_session_test.c $(LIBDIR)/xdev_ext_session.c -o $@ $(LDFLAGS)

$(RUN_TEST): xdev_ext_lib_run_test.c $(LIBDIR)/xdev_ext_session.c $(LIBDIR)/xdev_ext_prog.c \
		$(LIBDIR)/xdev_ext_run.c $(LIB_HDRS) | $(OUTPUT)
	$(CC) $(CFLAGS) xdev_ext_lib_run_test.c $(LIBDIR)/xdev_ext_session.c \
		$(LIBDIR)/xdev_ext_prog.c $(LIBDIR)/xdev_ext_run.c -o $@ $(LDFLAGS) $(LIBBPF_LIBS) -lelf -lz

$(USER_TEST): xdev_ext_lib_user_test.c $(LIBDIR)/xdev_ext_session.c $(LIBDIR)/xdev_ext_user.c \
		$(LIB_HDRS) | $(OUTPUT)
	$(CC) $(CFLAGS) -pthread xdev_ext_lib_user_test.c $(LIBDIR)/xdev_ext_session.c \
		$(LIBDIR)/xdev_ext_user.c -o $@ $(LDFLAGS) -pthread

run-session: $(SESSION_TEST) $(USER_TEST)
	$(SESSION_TEST)
	$(USER_TEST)

run: $(SESSION_TEST) $(RUN_TEST) $(USER_TEST)
	$(SESSION_TEST)
	$(RUN_TEST)
	$(USER_TEST)

clean:
	rm -rf $(OUTPUT)

.PHONY: all run run-session clean
