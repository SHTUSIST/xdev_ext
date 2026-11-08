#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile actual app functions with GPU/transport/port boundaries; no DPDK path run."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def block(source, signature):
    """Return the exact C definition, balancing braces outside comments/literals."""
    start = source.index(signature)
    pos = source.index('{', start)
    depth, state, escaped = 0, 'code', False
    for i in range(pos, len(source)):
        c = source[i]
        pair = source[i:i + 2]
        if state in ('string', 'char'):
            if escaped:
                escaped = False
            elif c == '\\':
                escaped = True
            elif c == ('"' if state == 'string' else "'"):
                state = 'code'
        elif state == 'line':
            if c == '\n':
                state = 'code'
        elif state == 'comment':
            if source[i - 1:i + 1] == '*/':
                state = 'code'
        elif pair == '//':
            state = 'line'
        elif pair == '/*':
            state = 'comment'
        elif c == '"':
            state = 'string'
        elif c == "'":
            state = 'char'
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
    raise ValueError('unterminated definition: ' + signature)


PREFIX = r'''
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <net/if.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tb_gpu.h"
#include "tb_wire.h"
struct rte_mempool { int unused; };
struct rte_ether_addr { uint8_t addr_bytes[6]; };
struct rte_eth_conf { int untouched; };
struct rte_eth_dev_info { unsigned int if_index; uint16_t max_mtu; };
#define NB_MBUF 16383
#define MBUF_CACHE 250
#define RTE_MBUF_DEFAULT_BUF_SIZE 2176
'''

BOUNDARIES = r'''
static struct tb *sender, *receiver;
static int corrupt_id = -1, readbacks, loads, force_quit;
static uint16_t reported_max_mtu = 3520;
static uint64_t ticks;
static int rte_errno;
static uint64_t now_ns(void) { return ++ticks * 1000000; }
static void __attribute__((noreturn, format(printf, 1, 2))) fatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr); exit(1);
}
static void poll_rx(struct tb *t) { (void)t; }
const char *tb_gpu_error(void) { return "fixture GPU boundary"; }
int tb_gpu_h2d(void *dst, const void *src, size_t n)
{
    memcpy(dst, src, n);
    if (receiver && dst == receiver->gpu_dst && (int)receiver->rx.done_msg_id == corrupt_id)
        ((uint8_t *)dst)[0] ^= 1;
    if (sender && dst == sender->gpu_src) loads++;
    return 0;
}
int tb_gpu_d2h(void *dst, const void *src, size_t n)
{
    if (receiver && src == receiver->gpu_dst) readbacks++;
    memcpy(dst, src, n); return 0;
}
static int rte_eth_dev_is_valid_port(uint16_t p) { (void)p; return 1; }
static int rte_socket_id(void) { return 0; }
static int rte_eth_dev_socket_id(uint16_t p) { (void)p; return 0; }
static struct rte_mempool *rte_pktmbuf_pool_create(const char *n, unsigned m, unsigned c,
                                                uint16_t x, uint16_t size, int socket)
{ static struct rte_mempool pool; (void)n; (void)m; (void)c; (void)x; (void)size; (void)socket; return &pool; }
static const char *rte_strerror(int e) { return strerror(e); }
static int rte_eth_dev_info_get(uint16_t p, struct rte_eth_dev_info *i)
{ (void)p; *i = (struct rte_eth_dev_info){ .max_mtu = reported_max_mtu }; return 0; }
static int rte_eth_dev_configure(uint16_t p, uint16_t r, uint16_t t, const struct rte_eth_conf *c)
{ (void)p; assert(r == 1 && t == 1 && !c->untouched); return 0; }
static int rte_eth_rx_queue_setup(uint16_t p, uint16_t q, uint16_t n, unsigned s,
                                 const void *c, struct rte_mempool *m)
{ (void)p; (void)s; (void)m; assert(q == 0 && n == 0 && !c); return 0; }
static int rte_eth_tx_queue_setup(uint16_t p, uint16_t q, uint16_t n, unsigned s, const void *c)
{ (void)p; (void)s; assert(q == 0 && n == 0 && !c); return 0; }
static int rte_eth_dev_start(uint16_t p) { (void)p; return 0; }
static int rte_eth_macaddr_get(uint16_t p, struct rte_ether_addr *m)
{ (void)p; memset(m, 0, sizeof(*m)); return 0; }
static int rte_eth_dev_get_mtu(uint16_t p, uint16_t *m) { (void)p; *m = 1500; return 0; }
static uint32_t netdev_mtu(const char *s) { (void)s; return 1400; }
static const char *attach_mode_name(int i) { (void)i; return "fixture"; }
static int xsk_zerocopy(void) { return -1; }
static const char *rte_version(void) { return "fixture-port-boundary"; }
static void send_ctrl(struct tb *t, uint8_t type, uint32_t seq, uint32_t len, uint32_t aux, int b)
{
    (void)t; (void)len; (void)b; assert(type == TB_ACK);
    assert(!tb_tx_on_ack(&sender->tx, seq));
    sender->peer_completed = aux; sender->frames_rx++;
}
static void send_message(struct tb *t, const uint8_t *src, uint32_t len, uint8_t flags);
'''

DRIVER = r'''
static void send_message(struct tb *t, const uint8_t *src, uint32_t len, uint8_t flags)
{
    struct tb_hdr h = { .magic = TB_MAGIC, .type = TB_DATA,
        .seq = t->tx.next_seq, .msg_id = t->tx_msg_id, .msg_len = len,
        .payload_len = (uint16_t)len, .flags = (uint8_t)(flags | TB_F_LAST) };
    assert(len == 64); /* One small frame; transport/DPDK rings are outside this fixture. */
    tb_tx_sent(&t->tx); t->frames_tx++;
    assert(tb_rx_data(&receiver->rx, &h, src, receiver->rx_stage) == TB_RX_DONE);
    receiver->frames_rx++;
    message_done(receiver);
    t->tx_msg_id++;
}
static void alloc_buffers(struct tb *t)
{
    t->tx_stage = calloc(1, 64); t->rx_stage = calloc(1, 64); t->check = calloc(1, 64);
    t->gpu_src = calloc(1, 64); t->gpu_dst = calloc(1, 64);
    assert(t->tx_stage && t->rx_stage && t->check && t->gpu_src && t->gpu_dst);
    snprintf(t->gpu_name, sizeof(t->gpu_name), "fixture-no-GPU");
}
static void release_buffers(struct tb *t)
{
    free(t->tx_stage); free(t->rx_stage); free(t->check); free(t->gpu_src); free(t->gpu_dst);
}
int main(int argc, char **argv)
{
    struct tb a = { 0 }, b = { 0 };
    char error[256];
    char *opts[] = { "test", "--role", "client", "--mode", "stream", "--sizes", "64",
        "--warmup", "2", "--iters", "3", "--stream-min-bytes", "64", "--max-size", "64" };
    assert(argc == 2);
    assert(!tb_parse_opts((int)(sizeof(opts) / sizeof(opts[0])), opts, &a.o, error, sizeof(error)));
    if (!strcmp(argv[1], "metadata-unknown")) reported_max_mtu = 0;
    port_init(&a);
    if (!strncmp(argv[1], "metadata", 8)) { printf("{"); print_common(&a); puts("}"); return 0; }
    a.o.verify_all = !strncmp(argv[1], "all", 3);
    b.o = a.o; b.o.role = TB_ROLE_SERVER; b.peer_mode = TB_MODE_STREAM;
    tb_rx_init(&b.rx, 64, 256); tb_tx_init(&a.tx, 1024);
    alloc_buffers(&a); alloc_buffers(&b); sender = &a; receiver = &b;
    if (strstr(argv[1], "corrupt")) corrupt_id = 3; /* A timed, not warmup, message. */
    client_stream(&a, 64);
    printf("{\"receiver_verified\":%" PRIu64 ",\"gpu_readbacks\":%d,\"pattern_loads\":%d}\n",
           b.verified, readbacks, loads);
    assert(!b.msg_ready);
    release_buffers(&a); release_buffers(&b);
    return 0;
}
'''


class ProgramContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build = HERE / 'build'
        build.mkdir(exist_ok=True)
        cls.tmp = tempfile.TemporaryDirectory(prefix='program-', dir=build)
        source = (HERE / 'dpdk_tb.c').read_text()
        definitions = [block(source, 'static void ' + name + '(') for name in (
            'progress', 'check_stall', 'send_ack', 'message_done', 'port_init',
            'print_common', 'load_pattern', 'd2h_stage', 'wait_completed', 'client_stream')]
        unit = PREFIX + block(source, 'struct tb {') + ';\n' + BOUNDARIES + '\n'.join(definitions) + DRIVER
        path = Path(cls.tmp.name) / 'program.c'
        path.write_text(unit)
        cls.binary = path.with_suffix('')
        run = subprocess.run([os.environ.get('CC', 'gcc'), '-std=gnu11', '-O1', '-g',
                              '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                              '-fno-sanitize-recover=all', '-I' + str(HERE), str(path),
                              '-o', str(cls.binary)], capture_output=True, text=True)
        if run.returncode:
            raise RuntimeError(run.stdout + run.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_case(self, case):
        r = subprocess.run([str(self.binary), case], capture_output=True, text=True, timeout=10)
        return r, [json.loads(line) for line in r.stdout.splitlines() if line.startswith('{')]

    def test_verify_all_reads_back_each_gpu_message(self):
        r, rows = self.run_case('all')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(rows[0]['verified_messages'], 5)
        self.assertTrue(rows[0]['timed_includes_verify'])
        self.assertEqual(rows[1], dict(receiver_verified=5, gpu_readbacks=5, pattern_loads=5))

    def test_verify_all_rejects_damaged_timed_gpu_message(self):
        r, rows = self.run_case('all-corrupt')
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn('differs after the GPU copy', r.stderr)
        self.assertEqual(rows, [])

    def test_warmup_reports_only_the_checked_messages(self):
        for case in ('warmup', 'warmup-corrupt'):
            with self.subTest(case=case):
                r, rows = self.run_case(case)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(rows[0]['messages'], 3)
                self.assertEqual(rows[0]['verified_messages'], 2)
                self.assertFalse(rows[0]['timed_includes_verify'])
                self.assertEqual(rows[1], dict(receiver_verified=2, gpu_readbacks=2, pattern_loads=2))

    def test_report_retains_port_max_mtu_without_changing_used_mtu(self):
        r, rows = self.run_case('metadata')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(rows[0]['dpdk_max_mtu'], 3520)
        self.assertEqual(rows[0]['dpdk_mtu'], 1500)
        self.assertEqual(rows[0]['netdev_mtu'], 1400)
        self.assertEqual(rows[0]['mtu'], 1400)

    def test_unspecified_max_mtu_is_recorded_without_inventing_a_limit(self):
        r, rows = self.run_case('metadata-unknown')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(rows[0]['dpdk_max_mtu'], 0)
        self.assertEqual(rows[0]['mtu'], 1400)


if __name__ == '__main__':
    unittest.main(verbosity=2)
