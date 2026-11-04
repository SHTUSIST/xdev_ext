#!/usr/bin/env python3
"""Compile production socket adapter functions against a userspace socket shim.

The shim only substitutes allocation, socket and common-core boundaries. The
admission, span validation, submit classification and completion code is real.
"""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent


def production_function(text, name):
    """Extract a complete production definition; missing dependencies fail setup."""
    match = re.search(r"^(?:static )?(?:inline )?[^\n;{}]+\b" + name +
                      r"\s*\([^;{}]*\)\s*\{", text, re.M)
    if not match:
        raise AssertionError("missing production definition: " + name)
    opening = text.index("{", match.start())
    depth, end = 1, opening + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[match.start():end] + "\n"


def socket_family_declarations(root):
    """Actual family types and tracker, with only kernel OS types substituted."""
    mech = (root / 'include/linux/xdev_ext_mech.h').read_text()
    peer = (root / 'include/linux/xdev_ext_peer.h').read_text()
    requester = (root / 'include/linux/xdev_ext_requester.h').read_text()
    rqcore = (root / 'include/linux/xdev_ext_requester_core.h').read_text()
    net = (root / 'include/linux/xdev_ext_netfam.h').read_text()
    declarations = [
        '#include "include/linux/xdev_ext_netfam_core.h"',
        '#include "include/linux/xdev_ext_peer_net_track.h"',
        'typedef __u16 u16; typedef int spinlock_t;',
        'struct module; struct pci_dev;',
        re.search(r'struct xdev_ext_family_hooks_hdr \{.*?\n\};', mech, re.S)[0],
    ]
    for text, names in ((peer, ('xdev_ext_peer_lease', 'xdev_ext_peer_fd_lease')),
                        (rqcore, ('xdev_ext_admission',)),
                        (requester, ('xdev_ext_requester',))):
        declarations.extend(re.search(r'struct ' + name + r' \{.*?\n\};', text, re.S)[0]
                            for name in names)
    declarations.append(re.sub(r'^#include[^\n]*\n', '', net, flags=re.M))
    return '\n'.join(declarations) + '\n'


def socket_family_runtime(root):
    """Compile the real runtime; unused PEER/OS boundaries abort if reached.

    Keep the old class allocation counters scoped to their original allocations;
    family allocations remain real calloc/free and have separate accounting.
    Completion uses the production ticket state machine before the old core
    queue observation boundary records the single batch publication.
    """
    mech = (root / 'io_uring/xdev_ext_mech.c').read_text()
    runtime = (root / 'io_uring/family/xdev_ext_netfam.c').read_text()
    runtime = re.sub(r'^#include[^\n]*\n', '', runtime, flags=re.M)
    return r'''
#define THIS_MODULE NULL
#define EXPORT_SYMBOL_GPL(name)
#define NSEC_PER_MSEC 1000000ULL
#define spin_lock_init(lock) (*(lock)=0)
#define spin_lock_irqsave(lock,flags) do {(flags)=0; if (*(lock)) abort(); *(lock)=1;} while (0)
#define spin_unlock_irqrestore(lock,flags) do {(void)(flags); if (!*(lock)) abort(); *(lock)=0;} while (0)
static u64 ktime_get_boottime_ns(void) { return 1000000ULL; }
static unsigned long msecs_to_jiffies(unsigned int ms) { return ms; }
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st,int err)
{ (void)st; (void)err; abort(); }
static int xdev_ext_requester_bind(struct xdev_ext_requester *r,struct xdev_ext_mech_stage *s,struct pci_dev *p,u32 f)
{ (void)r; (void)s; (void)p; (void)f; abort(); }
static void xdev_ext_requester_unbind(struct xdev_ext_requester *r)
{ (void)r; abort(); }
static void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *l,bool q)
{ (void)l; (void)q; abort(); }
enum dma_data_direction { DMA_BIDIRECTIONAL, DMA_TO_DEVICE, DMA_FROM_DEVICE, DMA_NONE };
static struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *p)
{ (void)p; abort(); }
static u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *p)
{ (void)p; abort(); }
static int xdev_ext_peer_file_acquire(struct file *f,struct pci_dev *p,u64 g,u64 off,u32 n,enum dma_data_direction d,struct xdev_ext_peer_fd_lease *l)
{ (void)f; (void)p; (void)g; (void)off; (void)n; (void)d; (void)l; abort(); }
static unsigned int fixture_family_allocations,fixture_family_frees;
static void *fixture_family_calloc(size_t n,size_t size,int flags)
{ (void)flags; fixture_family_allocations++; return calloc(n,size); }
static void fixture_family_free(const void *ptr)
{ if (ptr) fixture_family_frees++; free((void *)ptr); }
''' + production_function(mech, 'xdev_ext_mech_batch_frame') + production_function(
        mech, 'xdev_ext_mech_batch_completion_claim') + r'''
static void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b,u64 ticket,int err,bool sequester)
{
    if (xdev_ext_mech_completion_publish_begin(&b->completion,ticket)) return;
    if (sequester) abort(); /* No native DMA in this old socket OS boundary. */
    xdev_ext_mech_completion_publish_end(&b->completion,ticket,err);
    xdev_ext_mech_batch_complete(b,ticket,err); /* existing core queue observer */
}
#pragma push_macro("kvcalloc")
#pragma push_macro("kvfree")
#undef kvcalloc
#undef kvfree
#define kvcalloc fixture_family_calloc
#define kvfree fixture_family_free
''' + runtime + r'''
#pragma pop_macro("kvfree")
#pragma pop_macro("kvcalloc")
'''


def socket_submission_setup():
    """Old manual batches now drive the real core prepare/fill boundaries."""
    return r'''
static void fixture_drain_stage(struct xdev_ext_mech_stage *st)
{
    struct xdev_ext_socket_stage *ss=st->priv;
    for (u32 i=0;i<ss->depth;i++)
        xdev_ext_netfam_fill_cqe(&ss->ns,&ss->request[i].tx_slot);
}
static void fixture_prepare_submission(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_batch *b)
{
    int result;
    __u64 ticket;
    fixture_drain_stage(st);
    if ((b->completion.ctrl&7)==XDEV_EXT_MECH_C_LANDED) {
        if (xdev_ext_mech_completion_consume(&b->completion,b->completion.ctrl>>3,&result)) abort();
    } else if ((b->completion.ctrl&7)==XDEV_EXT_MECH_C_SUBMITTED) {
        if (xdev_ext_mech_completion_cancel(&b->completion,b->completion.ctrl>>3)) abort();
    }
    /* Preserve each old explicitly chosen ticket in this hand-driven batch. */
    b->completion.ctrl=(b->ticket-1)<<3;
    if (xdev_ext_mech_completion_begin(&b->completion,&ticket) || ticket!=b->ticket) abort();
}
'''


def socket_family_reference():
    # The host fixtures omit the class table, the production hook's sole user.
    # Keep a typed reference rather than suppress unused-variable diagnostics.
    return ('\nstatic const struct xdev_ext_net_hooks *const fixture_socket_hooks '
            '__attribute__((used)) = &xdev_ext_socket_net_hooks;\n')


class SocketAdapter(unittest.TestCase):
    def test_socket_class_is_admitted_by_production_registry(self):
        text = (ROOT / 'io_uring/xdev_ext_mech_core.h').read_text()
        function = re.search(r'static inline bool xdev_ext_mech_class_known\([^{}]+\)\n\{.*?\n\}', text, re.S)[0]
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'class.c'
            exe = Path(tmp) / 'class'
            source.write_text('#include <stdbool.h>\n#include "include/uapi/linux/xdev_ext_mech.h"\n'
                              '#include "include/linux/xdev_ext_family_core.h"\n' + function + '\nint main(void) {return !xdev_ext_mech_class_known(7);}\n')
            subprocess.run(['cc', '-Wall', '-Werror', '-I'+str(ROOT), str(source), '-o', str(exe)], check=True)
            self.assertEqual(subprocess.run([str(exe)]).returncode, 0,
                             'ordinary socket class 7 must enter the common mechanism registry')

    def test_socket_never_retries_accepted_native_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'retry.c'
            exe = Path(tmp) / 'retry'
            source.write_text('#include <string.h>\n#include "io_uring/xdev_ext_mech_core.h"\n'
                              'int main(void) {int e; for(e=-4095;e<65536;e++) '
                              'if(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_SOCKET,0,e))return 1; return 0;}\n')
            subprocess.run(['cc', '-Wall', '-Werror', '-I'+str(ROOT), str(source), '-o', str(exe)], check=True)
            self.assertEqual(subprocess.run([str(exe)]).returncode, 0)

    def test_production_adapter_with_real_connected_udp(self):
        source = ROOT / 'io_uring/xdev_ext_mech_socket.c'
        self.assertTrue(source.exists(), 'new mechanism ordinary socket adapter is missing')
        text = source.read_text()
        text = re.sub(r'^#include[^\n]*\n', '', text, flags=re.M)
        text = text[:text.index('static const struct xdev_ext_mech_class_ops')]
        with tempfile.TemporaryDirectory() as tmp:
            cfile = Path(tmp) / 'adapter.c'
            exe = Path(tmp) / 'adapter'
            cfile.write_text((HERE/'shim.h').read_text() + '\n' + socket_family_declarations(ROOT) +
                             socket_family_runtime(ROOT) + text + socket_family_reference() + socket_submission_setup() + '\n' + (HERE/'fixture.c').read_text())
            # -Wno-unused-function: this TX fixture does not call the receive-direction entry points.
            subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                            '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                            '-I'+str(ROOT), str(cfile), '-o', str(exe)], check=True)
            run = subprocess.run([str(exe)], text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn('PASS socket sink production adapter', run.stdout)

if __name__ == '__main__':
    unittest.main(verbosity=2)
