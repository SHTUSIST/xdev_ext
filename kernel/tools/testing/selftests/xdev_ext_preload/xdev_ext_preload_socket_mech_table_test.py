#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Opt-in socket mechanism path of the preload front end, per-thread session table.

A thread that alternates between connected UDP sockets must keep one session
per socket instead of stopping and re-creating a session on every call; a
socket whose session could not be stopped keeps working through libc and is
counted, instead of failing every later send with EBUSY.  Each datagram is
received by a real peer and compared byte for byte with independently
generated expected bytes.

The front end is the production library built by the selftest Makefile.  Only
the XDEV_EXT_MECH control API is modelled (xdev_ext_preload_mech_model.c);
this is host API evidence, not evidence of the kernel mechanism, of a device or
of performance.
"""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
OUT = Path(os.environ.get("XDEV_EXT_PRELOAD_TEST_DIR", str(HERE))).resolve()
FIXTURE = r"""
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define MAX_PAIRS 8

static int rx[MAX_PAIRS], tx[MAX_PAIRS];

static void pattern(unsigned char *out, size_t len, unsigned int seed)
{
    for (size_t i = 0; i < len; i++)
        out[i] = (unsigned char)(seed * 131u + i * 7u + 1u);
}

static int pair(int i)
{
    struct sockaddr_in addr = {.sin_family = AF_INET,
                               .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct timeval timeout = {.tv_sec = 3};
    socklen_t len = sizeof(addr);

    rx[i] = socket(AF_INET, SOCK_DGRAM, 0);
    tx[i] = socket(AF_INET, SOCK_DGRAM, 0);
    return rx[i] < 0 || tx[i] < 0 ||
           setsockopt(rx[i], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
           bind(rx[i], (void *)&addr, sizeof(addr)) ||
           getsockname(rx[i], (void *)&addr, &len) ||
           connect(tx[i], (void *)&addr, len);
}

/* Send one datagram on pair i and compare what its peer receives. */
static int one(int i, unsigned int seed, size_t len)
{
    unsigned char payload[2048], expected[2048], received[4096];
    ssize_t sent, got;

    pattern(payload, len, seed);
    pattern(expected, len, seed);
    errno = 0;
    sent = send(tx[i], payload, len, MSG_NOSIGNAL);
    if (sent != (ssize_t)len) {
        printf("XDEV_EXT_TABLE_FIXTURE=FAIL pair=%d seed=%u sent=%zd errno=%d\n",
               i, seed, sent, errno);
        return 1;
    }
    got = recv(rx[i], received, sizeof(received), 0);
    if (got != (ssize_t)len || memcmp(received, expected, len)) {
        printf("XDEV_EXT_TABLE_FIXTURE=FAIL pair=%d seed=%u received=%zd\n",
               i, seed, got);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    unsigned long long bytes = 0, calls = 0;
    int pairs, rounds, alias;

    if (argc != 2)
        return 2;
    if (!strcmp(argv[1], "alternate") || !strcmp(argv[1], "evict")) {
        pairs = argv[1][0] == 'a' ? 2 : 6;
        rounds = argv[1][0] == 'a' ? 32 : 3;
        for (int i = 0; i < pairs; i++)
            if (pair(i))
                return 3;
        for (int r = 0; r < rounds; r++)
            for (int i = 0; i < pairs; i++) {
                size_t len = 1 + ((r * 61u + i * 17u) % 1400u);

                if (one(i, (unsigned int)(r * pairs + i), len))
                    return 1;
                calls++;
                bytes += len;
            }
    } else if (!strcmp(argv[1], "stopfail")) {
        /* The interposed close of the alias STOPs the shared session. */
        if (pair(0) || pair(1) || (alias = dup(tx[0])) < 0)
            return 3;
        if (one(0, 1, 100))
            return 1;
        if (close(alias))
            return 4;
        /* That STOP failed: the socket must keep working. */
        if (one(0, 2, 200) || one(0, 3, 300) || one(1, 4, 400))
            return 1;
        calls = 4;
        bytes = 1000;
    } else {
        return 2;
    }
    printf("XDEV_EXT_TABLE_FIXTURE=PASS calls=%llu bytes=%llu\n", calls, bytes);
    return 0;
}
"""


def records(text, prefix):
    return [dict(re.findall(r"(\w+)=(\S+)", line)) for line in text.splitlines()
            if line.startswith(prefix + " ")]


def total(rows, key):
    return sum(int(row[key]) for row in rows)


class SocketMechTable(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frontend = OUT / "libio_uring_unified.so"
        if not cls.frontend.is_file():
            raise RuntimeError(f"missing build artifact: {cls.frontend}; build the selftests first")
        cls.work = tempfile.TemporaryDirectory(prefix="xdev-mech-table-", dir=OUT)
        cls.addClassCleanup(cls.work.cleanup)
        directory = Path(cls.work.name)
        cls.clean_env = {key: value for key, value in os.environ.items()
                         if not key.startswith("XDEV") and key != "LD_PRELOAD"}
        cc = shlex.split(os.environ.get("CC", "cc"))
        flags = ["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"]
        source = directory / "fixture.c"
        source.write_text(FIXTURE)
        cls.binary = directory / "fixture"
        cls.model = directory / "libxdev_ext_preload_mech_model.so"
        for command in (cc + flags + [str(source), "-o", str(cls.binary)],
                        cc + flags + ["-shared", "-fPIC", "-pthread",
                                      str(HERE / "xdev_ext_preload_mech_model.c"),
                                      "-o", str(cls.model), "-ldl"]):
            subprocess.run(command, env=cls.clean_env, check=True,
                           capture_output=True, text=True, timeout=60)

    def run_fixture(self, mode, **extra):
        env = dict(self.clean_env)
        env.update(LD_PRELOAD=f"{self.frontend}:{self.model}",
                   XDEV_EXT_PRELOAD_SOCKET_ENABLED="1",
                   XDEV_EXT_PRELOAD_SOCKET_MECH="1",
                   XDEV_EXT_PRELOAD_REPORT="1",
                   XDEV_EXT_MECH_MODEL_SUMMARY="1", **extra)
        completed = subprocess.run([str(self.binary), mode], env=env,
                                   capture_output=True, text=True, timeout=30)
        text = completed.stdout + completed.stderr
        print(f"# mode={mode} exit={completed.returncode}")
        for line in text.splitlines():
            print("# " + line)
        self.assertEqual(completed.returncode, 0, text)
        fixture = records(completed.stdout, "XDEV_EXT_TABLE_FIXTURE=PASS")
        self.assertEqual(len(fixture), 1, text)
        reports = records(completed.stderr, "XDEV_EXT_PRELOAD_MECH_REPORT")
        models = records(completed.stderr, "XDEV_EXT_MECH_MODEL_SUMMARY")
        fallbacks = records(completed.stderr, "XDEV_EXT_PRELOAD_FALLBACK_REPORT")
        self.assertEqual(len(reports), 1, text)
        self.assertEqual(len(models), 1, text)
        return fixture[0], reports, models[0], fallbacks, text

    def test_0_alternating_sockets_keep_one_session_each(self):
        fixture, reports, model, fallbacks, text = self.run_fixture("alternate")
        self.assertEqual(int(fixture["calls"]), 64, text)
        self.assertEqual(total(reports, "calls"), 64, text)
        self.assertEqual(total(reports, "bytes"), int(fixture["bytes"]), text)
        self.assertEqual(total(reports, "errors"), 0, text)
        # One CREATE per socket; the sessions are stopped once, at exit.
        self.assertEqual(total(reports, "creates"), 2, text)
        self.assertEqual(int(model["creates"]), 2, text)
        self.assertEqual(int(model["starts"]), 64, text)
        self.assertEqual(int(model["stops"]), 2, text)
        self.assertEqual(total(reports, "stops"), 2, text)
        self.assertEqual(len(fallbacks), 1, text)
        self.assertEqual(int(fallbacks[0]["socket_qualified"]), 64, text)

    def test_1_more_sockets_than_slots_evict_without_loss(self):
        fixture, reports, model, fallbacks, text = self.run_fixture("evict")
        self.assertEqual(total(reports, "calls"), int(fixture["calls"]), text)
        self.assertEqual(total(reports, "bytes"), int(fixture["bytes"]), text)
        self.assertEqual(total(reports, "errors"), 0, text)
        self.assertEqual(total(reports, "stop_errors"), 0, text)
        self.assertGreaterEqual(int(model["creates"]), 6, text)
        self.assertEqual(int(model["stops"]), int(model["creates"]), text)
        self.assertEqual(total(reports, "stops"), total(reports, "creates"), text)
        self.assertEqual(len(fallbacks), 1, text)
        self.assertEqual(int(fallbacks[0]["socket_qualified"]), int(fixture["calls"]), text)

    def test_2_failed_stop_falls_back_to_libc_for_that_socket(self):
        fixture, reports, model, fallbacks, text = self.run_fixture(
            "stopfail", XDEV_EXT_MECH_MODEL_STOP_FAIL="1")
        self.assertEqual(int(model["stop_failures"]), 1, text)
        # The socket with the unknown session sent twice through libc, and the
        # other socket still received a session of its own.
        self.assertEqual(total(reports, "calls"), 2, text)
        self.assertEqual(total(reports, "creates"), 2, text)
        self.assertEqual(total(reports, "stop_errors"), 1, text)
        self.assertEqual(len(fallbacks), 1, text)
        self.assertEqual(int(fallbacks[0]["socket_qualified"]), 2, text)
        self.assertEqual(int(fallbacks[0]["socket_mech_unavailable"]), 2, text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
