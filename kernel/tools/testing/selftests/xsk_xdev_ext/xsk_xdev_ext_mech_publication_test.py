#!/usr/bin/env python3
"""Execute the production settle/flush functions with observable ring stubs."""
from pathlib import Path
import subprocess
import os
import tempfile

root = Path(os.environ.get('XDEV_EXT_TEST_SRC', Path(__file__).resolve().parents[4]))
scratch = tempfile.TemporaryDirectory(prefix='xdev_ext-regression-')
out = Path(scratch.name)

def function(path, name):
    text = (root / path).read_text()
    start = text.index('\n', text.index(name))
    # Walk backwards to include a split return/signature declaration.
    start = text.rfind('\n', 0, text.index(name)) + 1
    brace = text.index('{', start)
    count = 1
    end = brace + 1
    while count:
        count += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]

settle = function('net/xdp/xsk_xdev_ext_mech.c', 'void __xsk_xdev_ext_mech_rx_settle(')
flush = function('net/xdp/xsk.c', 'static void xsk_flush(')
provider = (root / 'net/xdp/xsk_xdev_ext_mech.c').read_text()
published = function('net/xdp/xsk_xdev_ext_mech.c', 'void xsk_xdev_ext_mech_rx_published(') if 'void xsk_xdev_ext_mech_rx_published(' in provider else ''
prefix = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
typedef uint32_t u32;
typedef uint8_t u8;
struct xdp_ring { u32 producer; };
struct xsk_queue { u32 cached_prod; struct xdp_ring *ring; };
struct xsk_buff_pool { void *fq; };
struct xdev_ext_mech_stage { void *s; };
struct xdp_sock { struct xsk_queue *rx; struct xsk_buff_pool *pool; struct xdev_ext_mech_stage *xdev_ext_mech_rx; int sk; };
struct xdp_buff_xsk { int unused; };
struct xdev_ext_mech_frame { u32 index; };
static struct xdp_sock *observed;
static u32 notified, expected;
static int failures;
#define READ_ONCE(x) (x)
#define smp_load_acquire(p) (*(p))
#define WARN_ON_ONCE(x) (void)(x)
#define XDEV_EXT_MECH_CNT_PUBLISHED 1
static inline bool xsk_xdev_ext_mech_rx_session(const struct xdp_sock *xs) { return xs->xdev_ext_mech_rx != 0; }
static void xsk_xdev_ext_mech_frame(struct xsk_buff_pool *p, struct xdp_buff_xsk *b, struct xdev_ext_mech_frame *f) { (void)p; (void)b; f->index = 0; }
static u32 xdev_ext_mech_frame_state(u8 *s) { return *s; }
static int xsk_xdev_ext_mech_settle_edge(u32 s, bool to_user, u32 *from, u32 *to) { *from=s; *to=to_user; return 1; }
static int xdev_ext_mech_frame_move(u8 *s, u32 from, u32 to) { (void)from; *s=to; return 0; }
static void xdev_ext_mech_count(void *s, int c, u32 n) {
    (void)s; (void)c;
    if (observed->rx->ring->producer != expected) {
        fprintf(stderr, "notification before actual producer publication: producer=%u expected=%u\n", observed->rx->ring->producer, expected);
        failures++;
    }
    notified += n;
}
static void xskq_prod_submit(struct xsk_queue *q) { q->ring->producer = q->cached_prod; }
static void __xskq_cons_release(void *fq) { (void)fq; }
static void sock_def_readable(int *sk) { (void)sk; }
'''
main = r'''
int main(void) {
    struct xdp_ring ring = {0};
    struct xsk_queue q = {.ring=&ring};
    struct xsk_buff_pool pool = {0};
    struct xdev_ext_mech_stage st = {0};
    struct xdp_sock xs = {.rx=&q, .pool=&pool, .xdev_ext_mech_rx=&st};
    struct xdp_buff_xsk skb = {0};
    u8 state = 0;
    observed = &xs;
    expected = 1;
    q.cached_prod = 1;
    __xsk_xdev_ext_mech_rx_settle(&xs, &skb, &state, true);
    if (notified) { fprintf(stderr, "settle notified before flush\n"); failures++; }
    xsk_flush(&xs);
    if (notified != 1 || state != 1) failures++;
    xsk_flush(&xs);
    if (notified != 1) { fprintf(stderr, "empty flush double counted\n"); failures++; }
    ring.producer = UINT32_MAX - 1;
    q.cached_prod = 1;
    expected = 1;
    xsk_flush(&xs);
    if (notified != 4) { fprintf(stderr, "wraparound delta wrong: %u\n", notified); failures++; }
    xs.xdev_ext_mech_rx = 0;
    q.cached_prod++;
    xsk_flush(&xs);
    if (notified != 4) { fprintf(stderr, "unbound socket counted\n"); failures++; }
    printf("rx publication ordering/wrap/empty/unbound: %s\n", failures ? "FAIL" : "PASS");
    return failures != 0;
}
'''
source = out / 'rx-publication-regression.c'
binary = out / 'rx-publication-regression'
source.write_text(prefix + '\n' + settle + '\n' + published + '\n' + flush + '\n' + main)
subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(binary)], check=True)
raise SystemExit(subprocess.run([str(binary)]).returncode)
