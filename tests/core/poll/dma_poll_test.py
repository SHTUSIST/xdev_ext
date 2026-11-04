#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""DMA provider class polling: the generic route for new devices.

xdev_ext_dma_bind() and xdev_ext_dma_poll() run verbatim from
io_uring/xdev_ext_mech_dma.c, with the real geometry rules of
io_uring/xdev_ext_mech_dma_core.h and the real region and provider ABI
structures of include/linux/xdev_ext_mech.h. The fixture stands in for the
provider registry lookup and one provider whose poll support and bind
behaviour each case selects. The shared copy/lease implementations and DMA
callback table are compiled too; batch submission/completion APIs are unreachable
fail-closed boundaries in this bind/poll/unbind-only fixture.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest

from poll_extract import fields, function

# Keep this fixture independently usable from canonical sources or a native tree.
PRODUCT = next(p for p in Path(__file__).resolve().parents
               if (p / 'tools/layout.py').is_file())
sys.path.insert(0, str(PRODUCT / 'tools'))
import layout


def source(relative):
    return layout.read_native(os.environ.get('KERNEL_SRC', PRODUCT),
                              'linux', relative).decode()


# Exact production headers, installed at their native include paths in a private
# compiler directory. This is an include fixture, not a source-view receipt.
HEADERS = (
    'include/linux/xdev_ext_mech.h', 'include/uapi/linux/xdev_ext_mech.h',
    'include/uapi/linux/xdev_ext_binding.h',
    'include/linux/xdev_ext_family_core.h', 'include/linux/xdev_ext_binding_ctx.h',
    'include/linux/xdev_ext_dma_scope_core.h',
    'include/linux/xdev_ext_compfam_core.h',
    'io_uring/xdev_ext_mech_core.h', 'io_uring/xdev_ext_mech_dma_core.h',
    'io_uring/xdev_ext_mech_window_copy_core.h', 'io_uring/xdev_ext_mech_window.h',
    'io_uring/xdev_ext_mech_native_cookie.h', 'io_uring/xdev_ext_mech_ce_lease.h',
    'io_uring/xdev_ext_compfam_copy_core.h',
    'io_uring/xdev_ext_compfam_copy_runtime.h',
    'io_uring/xdev_ext_compfam_copy_lease.h',
)


def compile_and_run(fixture, args=()):
    with tempfile.TemporaryDirectory(prefix='xdev-ext-dma-poll-') as temporary:
        path = Path(temporary)
        for relative in HEADERS:
            target = path / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source(relative))
        # Same OS include boundary as the published provider/faults fixture.
        for name in ('atomic', 'fs', 'list', 'module', 'mutex', 'xdev_ext_mech', 'slab'):
            target = path / 'linux' / (name + '.h')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('/* OS types and primitives are supplied by fixture.c. */\n')
        (path / 'fixture.c').write_text(fixture)
        command = shlex.split(os.environ.get('CC', 'cc')) + [
            '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
            '-Wno-unused-function', '-Wno-unused-parameter',
            '-fsanitize=undefined', '-fno-sanitize-recover=undefined', '-pthread',
            '-I' + str(path), str(path / 'fixture.c'), '-o', str(path / 'probe')]
        build = subprocess.run(command, text=True, capture_output=True)
        if build.returncode:
            raise AssertionError('fixture compile SETUP failed:\n' + build.stdout + build.stderr)
        run = subprocess.run([str(path / 'probe'), *args], text=True,
                             capture_output=True, timeout=10)
        return run.returncode, run.stdout + run.stderr

DMA = 'io_uring/xdev_ext_mech_dma.c'
ABI = 'include/linux/xdev_ext_mech.h'


def structure(text, name):
    match = re.search(r'^struct ' + name + r' \{\n.*?^\};', text, re.M | re.S)
    if not match:
        raise AssertionError('production structure missing: ' + name)
    return match[0]


FIXTURE = r'''
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_dma_core.h"
#include "io_uring/xdev_ext_mech_window.h"
/* PRODUCTION_INCLUDES */

typedef __u64 u64; typedef uint32_t u32; typedef uint8_t u8;
typedef struct { int counter; } atomic_t;
#define PAGE_SHIFT 12
#define U64_MAX UINT64_MAX
struct list_head { struct list_head *next,*prev; };
#define LIST_HEAD_INIT(n) { &(n), &(n) }
struct mutex { pthread_mutex_t native; };
#define __MUTEX_INITIALIZER(n) { .native = PTHREAD_MUTEX_INITIALIZER }
#define mutex_lock(p) assert(!pthread_mutex_lock(&(p)->native))
#define mutex_unlock(p) assert(!pthread_mutex_unlock(&(p)->native))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_entry(p,t,m) container_of(p,t,m)
#define list_for_each_entry(p,h,m) \
 for ((p)=list_entry((h)->next,typeof(*(p)),m); &(p)->m!=(h); \
      (p)=list_entry((p)->m.next,typeof(*(p)),m))
static void INIT_LIST_HEAD(struct list_head *h) { h->next=h->prev=h; }
static void list_add_tail(struct list_head *n,struct list_head *h) {
 n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;
}
static bool list_empty(const struct list_head *h) { return h->next==h; }
static void list_del(struct list_head *n) { n->prev->next=n->next;n->next->prev=n->prev; }
#define struct_size(p,m,n) (sizeof(*(p))+sizeof((p)->m[0])*(n))
#define WARN_ON_ONCE(c) ({bool bad=!!(c);assert(!bad);bad;})
#define WARN_ONCE(c,...) WARN_ON_ONCE(c)
#define GFP_KERNEL 0
struct page; struct file { int unused; }; struct module { int refs; }; struct file_operations;
struct xdev_ext_dma_cookie;
struct xdev_ext_mech_session;
struct xdev_ext_mech_batch;
struct xdev_ext_mech_stage { struct xdev_ext_mech_session *s; struct file *file; void *priv;
	u32 direction; bool poll; };
struct xdev_ext_mech_pool { struct page **pages; u32 nr_pages, first_page_off, frame_size, nr_frames; };

/* Actual header operations, after the fixture's OS type definitions. */
#include "io_uring/xdev_ext_compfam_copy_runtime.h"
#include "io_uring/xdev_ext_compfam_copy_lease.h"

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
static void *kvzalloc(size_t n, int gfp) { (void)gfp; return calloc(1, n); }
static void kvfree(void *p) { free(p); }
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
static int provider_unbind_region(struct xdev_ext_dma_region *r) { r->priv=NULL; unbind_regions++; return 0; }
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
/* Legacy-only lookup: every selected provider has no scope sidecar. */
static const struct xdev_ext_dma_provider_ops *xdev_ext_dma_provider_get(struct file *file/* SCOPE_LOOKUP_PARAM */)
{ (void)file; /* SCOPE_LOOKUP_INIT */ mod_gets++; return strcmp(mode, "no-poll-op") ? &with_poll : &without_poll; }

static u32 xdev_ext_mech_session_depth(struct xdev_ext_mech_session *s) { (void)s;return 4; }
static const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session *s)
{ static const struct xdev_ext_mech_layout l={.group_bytes=4096};(void)s;return &l; }
/* No batch exists in these CREATE/poll/rollback cases. Never fake a claim. */
static unsigned batch_boundary_calls;
static _Noreturn void batch_boundary_trap(void)
{ batch_boundary_calls++; fprintf(stderr, "SETUP opaque batch API reached\n"); abort(); }
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b)
{ (void)b; batch_boundary_trap(); }
static u64 xdev_ext_mech_batch_id(const struct xdev_ext_mech_batch *b)
{ (void)b; batch_boundary_trap(); }
static u32 xdev_ext_mech_batch_slot(const struct xdev_ext_mech_batch *b)
{ (void)b; batch_boundary_trap(); }
static bool xdev_ext_mech_batch_dma_owners_valid(const struct xdev_ext_mech_batch *b,
 u64 ticket, const struct xdev_ext_dma_xfer *x, u32 n)
{ (void)b; (void)ticket; (void)x; (void)n; batch_boundary_trap(); }
static int atomic_read(const atomic_t *a) { return a->counter; }
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
 if (ret && st.priv) xdev_ext_dma_unbind(&st);
	if (!ret) {
		struct xdev_ext_dma_stage *cs = st.priv;
		if (st.poll)
			polled_ret = xdev_ext_dma_poll(&st);
		printf("# region_polled=%d same_region=%d\n", cs->region.polled, polled_region == &cs->region);
	}
	printf("# opaque_batch_calls=%u\n", batch_boundary_calls);
	printf("ret=%d saw_polled=%d bind_regions=%d unbind_regions=%d bind_hosts=%d gets=%d puts=%d "
	       "allocs=%d frees=%d poll_calls=%d poll_ret=%d same=%d\n", ret, saw_polled, bind_regions,
	       unbind_regions, bind_hosts, mod_gets, mod_puts, allocs, frees, poll_calls, polled_ret,
	       st.priv ? polled_region == &((struct xdev_ext_dma_stage *)st.priv)->region : 0);
	return 0;
}
'''


def build_fixture():
    text, abi = source(DMA), source(ABI)
    bind = function(text, 'xdev_ext_dma_bind')
    scoped = re.search(r'\bxdev_ext_dma_stage_scope\s*\(', bind) is not None
    includes, dependencies = [], []
    structs = [structure(abi, n) for n in
               ('xdev_ext_dma_region', 'xdev_ext_dma_xfer', 'xdev_ext_dma_provider_ops')]
    fixture = FIXTURE
    if scoped:
        includes.append('#include "include/linux/xdev_ext_dma_scope_core.h"')
        structs += [structure(abi, n) for n in
                    ('xdev_ext_dma_scope_info', 'xdev_ext_dma_scope_ops')]
        version = re.search(r'^#define XDEV_EXT_DMA_SCOPE_OPS_VERSION\s+.*', abi, re.M)
        if version is None:
            raise AssertionError('production scope ops version missing')
        structs.append(version[0])
        # This fixture has only legacy providers. Unexpected scope ownership
        # crosses its stated boundary and must fail closed, never be simulated.
        dependencies.append('static void xdev_ext_dma_scope_put(struct xdev_ext_dma_scope *scope)\n'
                            '{ if (scope) abort(); }')
        dependencies.append(function(text, 'xdev_ext_dma_stage_scope'))
    fixture = fixture.replace('/* SCOPE_LOOKUP_PARAM */',
                              ', const struct xdev_ext_dma_scope_ops **scope_ops' if scoped else '')
    fixture = fixture.replace('/* SCOPE_LOOKUP_INIT */', '*scope_ops = NULL;' if scoped else '')
    # Missing shared composition is SETUP, never a fallback to lease success.
    if '#include "xdev_ext_compfam_copy_runtime.h"' not in text or \
            '#include "xdev_ext_compfam_copy_lease.h"' not in text:
        raise AssertionError('SETUP shared copy/lease production composition missing')
    includes.append('#include "io_uring/xdev_ext_compfam_copy_core.h"')
    structs.append(structure(text, 'xdev_ext_dma_stage'))
    structs.append(structure(text, 'xdev_ext_dma_batch'))
    lease = source('io_uring/xdev_ext_compfam_copy_lease.c')
    runtime = source('io_uring/xdev_ext_compfam_copy.c')
    dependencies += [function(lease, n) for n in (
        'xdev_ext_comp_copy_lease_bind', 'xdev_ext_comp_copy_lease_get',
        'xdev_ext_comp_copy_lease_finish', 'xdev_ext_comp_copy_lease_hold',
        'xdev_ext_comp_copy_lease_busy', 'xdev_ext_comp_copy_lease_cleanup_begin',
        'xdev_ext_comp_copy_lease_unbind')]
    dependencies += [function(runtime, n) for n in
                     ('xdev_ext_comp_copy_poll', 'xdev_ext_comp_copy_unbind')]
    # Preserve the actual policy/domain, every callback and its ops table.
    first = text.index('static bool xdev_ext_dma_lease_key_overlap(')
    last = text.index('static int xdev_ext_dma_bind(')
    production = '\n'.join(dependencies + [text[first:last], bind] +
                           [function(text, n) for n in ('xdev_ext_dma_unbind', 'xdev_ext_dma_poll')])
    return (fixture.replace('/* PRODUCTION_INCLUDES */', '\n'.join(includes))
            .replace('/* PRODUCTION_STRUCTS */', '\n'.join(structs))
            .replace('/* PRODUCTION */', production))


class DmaPoll(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = build_fixture()

    def run_case(self, case):
        code, out = compile_and_run(self.fixture, (case,))
        self.assertEqual(code, 0, out)
        self.assertIn("# opaque_batch_calls=0\n", out)
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
