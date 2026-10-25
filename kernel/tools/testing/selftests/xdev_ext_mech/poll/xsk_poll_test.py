#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""AF_XDP polling: NAPI preferred busy polling from the session worker.

xsk_mech_poll_napi_ok(), xsk_mech_poll_bind() and xsk_mech_poll() run
verbatim from net/xdp/xsk_xdev_ext_mech.c. The fixture models a bound socket,
its device queues with their NAPI instances, RTNL as a recorder and
napi_busy_loop() as a recorder. It does not run a driver's NAPI poll.
"""
import unittest

from poll_extract import body, compile_and_run, fields, function, source

XSK = 'net/xdp/xsk_xdev_ext_mech.c'

FIXTURE = r'''
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t u32; typedef uint16_t u16; typedef uint64_t u64;
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#define MIN_NAPI_ID 65U
#define BUSY_POLL_BUDGET 8
static bool napi_id_valid(unsigned int id) { return id >= MIN_NAPI_ID; }
struct napi_struct { unsigned int napi_id; u32 defer_hard_irqs; unsigned long gro_flush_timeout; };
struct netdev_rx_queue { struct napi_struct *napi; };
struct netdev_queue { struct napi_struct *napi; };
struct net_device { unsigned int real_num_rx_queues, real_num_tx_queues;
	struct netdev_rx_queue rxq[4]; struct netdev_queue txq[4]; };
static struct netdev_rx_queue *__netif_get_rx_queue(struct net_device *d, unsigned int q) { return &d->rxq[q]; }
static struct netdev_queue *netdev_get_tx_queue(const struct net_device *d, unsigned int q)
{ return (struct netdev_queue *)&d->txq[q]; }
enum { XSK_READY, XSK_BOUND, XSK_UNBOUND };
struct xdp_sock { int state; struct net_device *dev; u32 queue_id; bool zc; };
struct xsk_xdev_ext_mech_stage { struct xdp_sock *xs; unsigned int poll_napi[2]; u32 nr_poll_napi; };
struct xdev_ext_mech_stage { void *priv; };
static int rtnl_depth, rtnl_takes, rtnl_unbalanced;
static void rtnl_lock(void) { rtnl_depth++; rtnl_takes++; }
static void rtnl_unlock(void) { if (!rtnl_depth--) rtnl_unbalanced++; }
static unsigned busy[8], busy_n, busy_bad_args;
static void napi_busy_loop(unsigned int id, bool (*end)(void *, unsigned long), void *arg, bool prefer, u16 budget)
{
	if (end || arg || !prefer || budget != BUSY_POLL_BUDGET)
		busy_bad_args++;
	if (busy_n < 8)
		busy[busy_n] = id;
	busy_n++;
}

/* PRODUCTION */

int main(int argc, char **argv)
{
	struct napi_struct rx = { .napi_id = 100, .defer_hard_irqs = 2, .gro_flush_timeout = 200000 };
	struct napi_struct tx = { .napi_id = 101, .defer_hard_irqs = 2, .gro_flush_timeout = 200000 };
	struct net_device dev = { .real_num_rx_queues = 2, .real_num_tx_queues = 2 };
	struct xdp_sock xs = { .state = XSK_BOUND, .dev = &dev, .queue_id = 1 };
	struct xsk_xdev_ext_mech_stage xst = { .xs = &xs };
	struct xdev_ext_mech_stage st = { .priv = &xst };
	const char *m;
	bool is_tx = false, reliable = false;
	int ret;

	if (argc != 2)
		return 2;
	m = argv[1];
	dev.rxq[1].napi = &rx;
	if (!strcmp(m, "rx-no-defer")) rx.defer_hard_irqs = 0;
	if (!strcmp(m, "rx-no-timeout")) rx.gro_flush_timeout = 0;
	if (!strcmp(m, "rx-no-napi")) dev.rxq[1].napi = NULL;
	if (!strcmp(m, "rx-bad-id")) rx.napi_id = 3;
	if (!strcmp(m, "unbound")) xs.state = XSK_UNBOUND;
	if (!strcmp(m, "bad-queue")) xs.queue_id = 3;
	if (!strncmp(m, "tx-", 3)) is_tx = true;
	if (!strcmp(m, "tx-copy-reliable")) reliable = true;
	if (!strncmp(m, "tx-zc", 5)) xs.zc = true;
	if (!strcmp(m, "tx-zc-split") || !strcmp(m, "tx-zc-split-no-defer")) dev.txq[1].napi = &tx;
	if (!strcmp(m, "tx-zc-split-no-defer")) tx.defer_hard_irqs = 0;
	if (!strcmp(m, "tx-zc-shared")) dev.txq[1].napi = &rx;
	ret = xsk_mech_poll_bind(&xst, &xs, is_tx, reliable);
	if (!ret)
		xsk_mech_poll(&st);
	printf("ret=%d nr=%u id0=%u id1=%u busy=%u b0=%u b1=%u bad=%u rtnl=%d takes=%d unbalanced=%d\n",
	       ret, xst.nr_poll_napi, xst.poll_napi[0], xst.poll_napi[1], busy_n, busy[0], busy[1],
	       busy_bad_args, rtnl_depth, rtnl_takes, rtnl_unbalanced);
	return 0;
}
'''


def build_fixture():
    text = source(XSK)
    production = '\n'.join(function(text, n) for n in (
        'xsk_mech_poll_napi_ok', 'xsk_mech_poll_bind', 'xsk_mech_poll'))
    return FIXTURE.replace('/* PRODUCTION */', production)


class XskPoll(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = build_fixture()

    def run_case(self, case):
        code, out = compile_and_run(self.fixture, (case,), defines=('CONFIG_NET_RX_BUSY_POLL',))
        self.assertEqual(code, 0, out)
        r = fields(out)
        self.assertEqual((r['rtnl'], r['unbalanced']), (0, 0), 'RTNL balanced: ' + out)
        return r

    def test_receive_queue_napi_is_busy_polled(self):
        r = self.run_case('rx')
        self.assertEqual((r['ret'], r['nr'], r['id0']), (0, 1, 100), r)
        self.assertEqual((r['busy'], r['b0'], r['bad']), (1, 100, 0), 'one preferred pass, budget 8')

    def test_refusals_without_interrupt_deferral_or_napi(self):
        for case in ('rx-no-defer', 'rx-no-timeout', 'rx-no-napi', 'rx-bad-id', 'unbound', 'bad-queue'):
            with self.subTest(case=case):
                r = self.run_case(case)
                self.assertEqual((r['ret'], r['nr'], r['busy']), (-95, 0, 0), r)

    def test_copy_transmit_has_nothing_to_poll(self):
        r = self.run_case('tx-copy')
        self.assertEqual((r['ret'], r['takes']), (-95, 0), r)

    def test_reliable_copy_transmit_polls_for_acknowledgements(self):
        r = self.run_case('tx-copy-reliable')
        self.assertEqual((r['ret'], r['nr'], r['id0'], r['busy']), (0, 1, 100, 1), r)

    def test_zero_copy_transmit_polls_its_own_napi_too(self):
        r = self.run_case('tx-zc-split')
        self.assertEqual((r['ret'], r['nr'], r['id0'], r['id1']), (0, 2, 100, 101), r)
        self.assertEqual((r['busy'], r['b0'], r['b1'], r['bad']), (2, 100, 101, 0), r)

    def test_transmit_napi_needs_deferral_too(self):
        r = self.run_case('tx-zc-split-no-defer')
        self.assertEqual((r['ret'], r['nr']), (-95, 0), r)

    def test_shared_napi_polled_once(self):
        r = self.run_case('tx-zc-shared')
        self.assertEqual((r['ret'], r['nr'], r['busy']), (0, 1, 1), r)


class XskPollStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = source(XSK)

    def test_bind_records_napi_before_socket_mutex(self):
        bind = body(self.text, 'xsk_xdev_ext_mech_bind')
        poll = bind.index('xsk_mech_poll_bind(xst, xs, tx,')
        self.assertLess(poll, bind.index('mutex_lock(&xs->mutex);'), 'RTNL before xs->mutex, as xsk_bind()')
        self.assertIn('if (st->poll)', bind[max(0, poll - 120):poll])

    def test_class_registers_poll(self):
        table = self.text[self.text.index('static const struct xdev_ext_mech_class_ops xsk_xdev_ext_mech_class_ops'):]
        self.assertIn('.poll = xsk_mech_poll,', table[:table.index('};')])


if __name__ == '__main__':
    unittest.main(verbosity=2)
