#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""DMA provider class polling: the generic route for new devices.

xdev_ext_dma_bind() and xdev_ext_dma_poll() run verbatim from
io_uring/xdev_ext_mech_dma.c, with the real geometry rules of
io_uring/xdev_ext_mech_dma_core.h and the real region and provider ABI
structures of include/linux/xdev_ext_mech.h. The fixture stands in for the
provider registry lookup and one provider whose poll support and bind
behaviour each case selects.
"""
import re
import unittest

from poll_extract import compile_and_run, fields, function, source

DMA = 'io_uring/xdev_ext_mech_dma.c'
ABI = 'include/linux/xdev_ext_mech.h'


def structure(text, name):
    match = re.search(r'^struct ' + name + r' \{\n.*?^\};', text, re.M | re.S)
    if not match:
        raise AssertionError('production structure missing: ' + name)
    return match[0]


FIXTURE = r'''
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_dma_core.h"

typedef uint64_t u64; typedef uint32_t u32; typedef uint8_t u8;
typedef struct { int counter; } atomic_t;
#define PAGE_SHIFT 12
#define GFP_KERNEL 0
struct page; struct file { int unused; }; struct module { int refs; }; struct file_operations;
struct xdev_ext_dma_cookie;
struct xdev_ext_mech_session;
struct xdev_ext_mech_batch;
struct xdev_ext_mech_stage { struct xdev_ext_mech_session *s; struct file *file; void *priv;
	u32 direction; bool poll; };
struct xdev_ext_mech_pool { struct page **pages; u32 nr_pages, first_page_off, frame_size, nr_frames; };

/* PRODUCTION_STRUCTS */

static int allocs, frees, mod_puts, mod_gets, bind_regions, unbind_regions, bind_hosts, poll_calls;
static int saw_polled = -1;
static const char *mode;
static struct page *page_array[4];
static struct xdev_ext_mech_pool pool = { .pages = page_array, .nr_pages = 4, .frame_size = 4096, .nr_frames = 4 };
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s)
{ (void)s; return &pool; }
static void *kzalloc(size_t n, int gfp) { (void)gfp; allocs++; return calloc(1, n); }
static void kfree(void *p) { if (p) frees++; free(p); }
static struct module owner;
static void module_put(struct module *m) { (void)m; mod_puts++; }
static int provider_bind_region(struct file *f, u64 off, u64 len, struct xdev_ext_dma_region *out)
{
	(void)f; (void)off;
	bind_regions++;
	saw_polled = out->polled;
	out->priv = &owner; out->len = len; out->segment_size = 4096; out->max_entry_len = 4096;
	out->alignment = 1; out->directions = XDEV_EXT_DMA_DIR_KNOWN_MASK;
	if (!strcmp(mode, "clears"))
		out->polled = false;
	return 0;
}
static void provider_unbind_region(struct xdev_ext_dma_region *r) { (void)r; unbind_regions++; }
static int provider_bind_host(struct xdev_ext_dma_region *r, struct page **p, u32 nr, void **host)
{ (void)r; (void)p; (void)nr; bind_hosts++; *host = &owner; return 0; }
static int provider_unbind_host(void *h) { (void)h; return 0; }
static int provider_submit(struct xdev_ext_dma_region *r, void *h, u32 d, const struct xdev_ext_dma_xfer *x,
			   u32 n, struct xdev_ext_dma_cookie *c, u64 t)
{ (void)r; (void)h; (void)d; (void)x; (void)n; (void)c; (void)t; return 0; }
static struct xdev_ext_dma_region *polled_region;
static int provider_poll(struct xdev_ext_dma_region *r) { poll_calls++; polled_region = r; return 3; }
static const struct xdev_ext_dma_provider_ops with_poll = { .owner = &owner, .bind_region = provider_bind_region,
	.unbind_region = provider_unbind_region, .bind_host = provider_bind_host,
	.unbind_host = provider_unbind_host, .submit = provider_submit, .poll = provider_poll };
static const struct xdev_ext_dma_provider_ops without_poll = { .owner = &owner, .bind_region = provider_bind_region,
	.unbind_region = provider_unbind_region, .bind_host = provider_bind_host,
	.unbind_host = provider_unbind_host, .submit = provider_submit };
static const struct xdev_ext_dma_provider_ops *xdev_ext_dma_provider_get(struct file *file)
{ (void)file; mod_gets++; return strcmp(mode, "no-poll-op") ? &with_poll : &without_poll; }

/* PRODUCTION */

int main(int argc, char **argv)
{
	struct file f;
	struct xdev_ext_mech_stage st = { .file = &f, .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE };
	struct xdev_ext_mech_stage_uapi u = { .class_id = XDEV_EXT_MECH_CLASS_DMA,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .arg0 = 0, .arg1 = 16384 };
	int ret, polled_ret = -999;

	if (argc != 2)
		return 2;
	mode = argv[1];
	st.poll = strcmp(mode, "plain") != 0;
	ret = xdev_ext_dma_bind(&st, &u);
	if (!ret) {
		struct xdev_ext_dma_stage *cs = st.priv;
		if (st.poll)
			polled_ret = xdev_ext_dma_poll(&st);
		printf("# region_polled=%d same_region=%d\n", cs->region.polled, polled_region == &cs->region);
	}
	printf("ret=%d saw_polled=%d bind_regions=%d unbind_regions=%d bind_hosts=%d gets=%d puts=%d "
	       "allocs=%d frees=%d poll_calls=%d poll_ret=%d same=%d\n", ret, saw_polled, bind_regions,
	       unbind_regions, bind_hosts, mod_gets, mod_puts, allocs, frees, poll_calls, polled_ret,
	       st.priv ? polled_region == &((struct xdev_ext_dma_stage *)st.priv)->region : 0);
	return 0;
}
'''


def build_fixture():
    text, abi = source(DMA), source(ABI)
    structs = '\n'.join([structure(abi, 'xdev_ext_dma_region'), structure(abi, 'xdev_ext_dma_xfer'),
                         structure(abi, 'xdev_ext_dma_provider_ops'), structure(text, 'xdev_ext_dma_stage')])
    production = '\n'.join(function(text, n) for n in ('xdev_ext_dma_bind', 'xdev_ext_dma_poll'))
    return FIXTURE.replace('/* PRODUCTION_STRUCTS */', structs).replace('/* PRODUCTION */', production)


class DmaPoll(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = build_fixture()

    def run_case(self, case):
        code, out = compile_and_run(self.fixture, (case,))
        self.assertEqual(code, 0, out)
        return fields(out)

    def test_provider_without_poll_refuses_before_binding(self):
        r = self.run_case('no-poll-op')
        self.assertEqual(r['ret'], -95, r)  # -EOPNOTSUPP
        self.assertEqual((r['bind_regions'], r['bind_hosts']), (0, 0), r)
        self.assertEqual((r['gets'], r['puts']), (1, 1), 'provider module reference released')
        self.assertEqual(r['allocs'], r['frees'], r)

    def test_polled_region_is_marked_before_bind_region(self):
        r = self.run_case('poll')
        self.assertEqual((r['ret'], r['saw_polled'], r['bind_hosts']), (0, 1, 1), r)
        self.assertEqual((r['poll_calls'], r['poll_ret'], r['same']), (1, 3, 1),
                         'class poll forwards the stage region and its count')

    def test_unpolled_region_unchanged(self):
        r = self.run_case('plain')
        self.assertEqual((r['ret'], r['saw_polled'], r['poll_calls']), (0, 0, 0), r)

    def test_provider_clearing_the_poll_mark_is_refused(self):
        r = self.run_case('clears')
        self.assertEqual(r['ret'], -71, r)  # -EPROTO: would silently use its interrupt path
        self.assertEqual((r['bind_regions'], r['unbind_regions'], r['bind_hosts']), (1, 1, 0), r)
        self.assertEqual((r['gets'], r['puts']), (1, 1), r)
        self.assertEqual(r['allocs'], r['frees'], r)

    def test_class_table_registers_poll(self):
        text = source(DMA)
        table = text[text.index('static const struct xdev_ext_mech_class_ops xdev_ext_dma_class'):]
        self.assertIn('.poll\t\t= xdev_ext_dma_poll,', table[:table.index('};')])


if __name__ == '__main__':
    unittest.main(verbosity=2)
