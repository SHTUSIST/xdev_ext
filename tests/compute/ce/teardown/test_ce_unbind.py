#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute actual CE cleanup and lease helpers at refusing native boundaries."""
from pathlib import Path
import json
import os
import runpy
import subprocess
import tempfile

def source_owner():
    """Find the canonical owner of this test or its ordinary registered copy."""
    for parent in Path(__file__).resolve().parents:
        marker = parent / 'view.json'
        if marker.is_file():
            receipt = json.loads(marker.read_text())
            if receipt.get('kind') == 'host-source-view':
                return Path(receipt['canonical_root']).resolve()
        if (parent / 'source-layout.json').is_file():
            return parent
    raise RuntimeError('SETUP: no canonical owner or registered source view')


ROOT = source_owner()
# Reuse only host OS/list/allocation primitives and the old extractor. Every
# cleanup/hold/detach decision below is an unchanged production function body.
legacy = runpy.run_path(str(ROOT / 'tests/compute/ce/independent_ce_lease.py'))
function = legacy['function']
text = (ROOT / 'src/compute/io_uring/xdev_ext_mech_ce.c').read_text()
start = text.index('struct xdev_ext_ce_lease_group {')
group = text[start:text.index('\n};', start)+3]
prelude = legacy['SHIM'] + r'''
struct xdev_ext_ce_region { const struct xdev_ext_ce_backend_ops *ops; void *priv; };
struct xdev_ext_ce_backend_ops { void *owner; int (*unbind_host)(void *); int (*unbind_region)(struct xdev_ext_ce_region *); };
struct xdev_ext_ce_stage {
 struct list_head lease_node;
 struct xdev_ext_ce_lease_group *lease_group;
 const struct xdev_ext_ce_backend_ops *ops;
 u64 window_start, window_len;
 bool cleanup_held;
 struct xdev_ext_ce_region region;
 void *host;
 int ambiguous;
};
static int host_error, region_error, host_calls, region_calls, frees, module_puts;
static struct xdev_ext_ce_stage *observed;
static int atomic_read(const int *p) { return *p; }
static void kfree(void *p) { (void)p; frees++; }
static void module_put(void *p) { (void)p; module_puts++; }
'''
helpers = ''.join(function(text, signature) for signature in (
    'static int xdev_ext_ce_lease_bind(',
    'static void xdev_ext_ce_lease_bind_ready(',
    'static int xdev_ext_ce_lease_cleanup_begin(',
    'static bool xdev_ext_ce_lease_unbind(',
    'static int xdev_ext_ce_unbind('))
main = r'''
static void check_native_hold(void) {
 assert(observed->lease_group && observed->cleanup_held);
 assert(observed->lease_group->cleanup_holds==1);
 assert(!list_empty(&observed->lease_group->regions));
 assert(!frees && !module_puts);
}
static int host_unmap(void *p) { (void)p; host_calls++; check_native_hold(); return host_error; }
static int region_unmap(struct xdev_ext_ce_region *r) {
 region_calls++; check_native_hold(); if (!region_error) r->priv=NULL; return region_error;
}
int main(void) {
 pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
 xdev_ext_ce_lease_mutex=&lock;
 const struct xdev_ext_ce_backend_ops ops={ .unbind_host=host_unmap, .unbind_region=region_unmap };
 struct xdev_ext_ce_stage cs={ .ops=&ops,.region={.ops=&ops,.priv=(void*)1}, .host=(void*)2 };
 struct xdev_ext_mech_session session={.depth=1};
 struct xdev_ext_mech_stage st={.s=&session,.priv=&cs};
 observed=&cs;
 assert(!xdev_ext_ce_lease_bind(&st,&cs,4096,4096));
 xdev_ext_ce_lease_bind_ready(&cs);
 assert(!cs.cleanup_held && !cs.lease_group->cleanup_holds);
 host_error=-EBUSY;
 int result=xdev_ext_ce_unbind(&st);
 if (result != -EBUSY || frees || module_puts || region_calls || !cs.host || !st.priv) {
  puts("not ok 1 - failed host unmap must retain region, stage and module"); return 1;
 }
 check_native_hold();
 host_error=0; region_error=-EIO;
 result=xdev_ext_ce_unbind(&st);
 if (result != -EIO || frees || module_puts || cs.host || !cs.region.priv) return 2;
 check_native_hold();
 int before=host_calls;
 region_error=0;
 result=xdev_ext_ce_unbind(&st);
 if (result || host_calls != before || frees != 1 || module_puts != 1 || st.priv) return 3;
 assert(!cs.lease_group && !cs.cleanup_held && list_empty(&xdev_ext_ce_lease_groups));
 assert(!xdev_ext_ce_unbind(&st) && frees==1 && module_puts==1);
 puts("ok 1 - failed host unmap retains every dependency and configured hold\nok 2 - failed region unmap retains residual ownership and configured hold\nok 3 - retry never replays successful host unmap; final detach releases one hold and module pin");
 return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='ce-teardown-', dir=os.environ.get('TMPDIR')) as tmp:
    src=Path(tmp)/'fixture.c'; binary=Path(tmp)/'fixture'
    src.write_text(prelude+'\n#include "'+str(ROOT/'src/compute/io_uring/xdev_ext_mech_ce_lease.h')+'"\n'+group+helpers+main)
    cmd=[os.environ.get('CC','gcc'),'-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-function','-pthread',
         '-fsanitize=undefined','-fno-sanitize-recover=all',str(src),'-o',str(binary)]
    built=subprocess.run(cmd,capture_output=True,text=True)
    if built.returncode:
        print('SETUP: compile failed\n'+built.stdout+built.stderr)
        raise SystemExit(2)
    raise SystemExit(subprocess.run([str(binary)]).returncode)
