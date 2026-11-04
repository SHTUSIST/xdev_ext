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
runtime = (ROOT / 'src/compute/io_uring/xdev_ext_compfam_copy.c').read_text()
header = (ROOT / 'src/compute/io_uring/xdev_ext_compfam_copy_runtime.h').read_text()
import re
lease_header=(ROOT/'src/compute/io_uring/xdev_ext_compfam_copy_lease.h').read_text()
lease_source=(ROOT/'src/compute/io_uring/xdev_ext_compfam_copy_lease.c').read_text()
group=re.sub(r'^#include[^\n]*\n','',lease_header,flags=re.M)
lease_source=re.sub(r'^#include[^\n]*\n','',lease_source,flags=re.M)
prelude = legacy['SHIM'] + '\n#include \"'+str(ROOT/'src/compute/io_uring/xdev_ext_compfam_copy_core.h')+'\"\n'
prelude += 'typedef int atomic_t; typedef uint8_t u8;\nstruct xdev_ext_comp_copy_stage; struct xdev_ext_comp_copy_cookie;\n'
prelude += ''.join(function(header, 'struct '+name+' {')+';\n' for name in (
    'xdev_ext_comp_copy_legacy_ops', 'xdev_ext_comp_copy_stage'))
prelude += '\n#include "'+str(ROOT/'src/compute/io_uring/xdev_ext_mech_ce_lease.h')+'"\n'
prelude += group
prelude += r'''
struct xdev_ext_ce_region { const struct xdev_ext_ce_backend_ops *ops; void *priv; };
struct xdev_ext_ce_backend_ops { void *owner; int (*unbind_host)(void *); int (*unbind_region)(struct xdev_ext_ce_region *); };
struct xdev_ext_ce_stage {
 struct xdev_ext_comp_copy_lease_region lease;
 const struct xdev_ext_ce_backend_ops *ops;
 u64 window_start, window_len;

 struct xdev_ext_ce_region region;
 struct xdev_ext_comp_copy_stage copy;
};
static int host_error, region_error, host_calls, region_calls, frees, module_puts;
static struct xdev_ext_ce_stage *observed;
static int atomic_read(const int *p) { return *p; }
static void kfree(void *p) { (void)p; frees++; }
static void module_put(void *p) { (void)p; module_puts++; }
'''
policy=text[text.index('static bool xdev_ext_ce_lease_key_overlap('):text.index('/* All stages share final batch fate;')]
helpers = lease_source + policy + ''.join(function(text, signature) for signature in (
    'static int xdev_ext_ce_copy_unbind_begin(',
    'static int xdev_ext_ce_copy_unbind_host(',
    'static int xdev_ext_ce_copy_unbind_region(',
    'static int xdev_ext_ce_copy_unbind_end('))
# Select only the actual four cleanup callbacks; no unused policy is simulated.
for name in ('unbind_begin', 'unbind_host', 'unbind_region', 'unbind_end'):
    assert '.'+name+' = xdev_ext_ce_copy_'+name+',' in text
helpers += 'static const struct xdev_ext_comp_copy_legacy_ops cleanup_ops = {\n' + ''.join(
    '.'+name+'=xdev_ext_ce_copy_'+name+',\n' for name in (
        'unbind_begin','unbind_host','unbind_region','unbind_end')) + '};\n'
helpers += function(runtime, 'int xdev_ext_comp_copy_unbind(')
helpers += function(text, 'static int xdev_ext_ce_unbind(')
main = r'''
static void check_native_hold(void) {
 assert(observed->lease.group && observed->lease.cleanup_held);
 assert(observed->lease.group->cleanup_holds==1);
 assert(!list_empty(&observed->lease.group->regions));
 assert(!frees && !module_puts);
}
static int host_unmap(void *p) { (void)p; host_calls++; check_native_hold(); return host_error; }
static int region_unmap(struct xdev_ext_ce_region *r) {
 region_calls++; check_native_hold(); if (!region_error) r->priv=NULL; return region_error;
}
int main(void) {
 pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
 xdev_ext_ce_lease_mutex=&lock;
 xdev_ext_ce_lease_domain.lock.value=&lock;
 const struct xdev_ext_ce_backend_ops ops={ .unbind_host=host_unmap, .unbind_region=region_unmap };
 struct xdev_ext_ce_stage cs={ .ops=&ops,.region={.ops=&ops,.priv=(void*)1}, .copy={.ops=&cleanup_ops,.host=(void*)2} };
 struct xdev_ext_mech_session session={.depth=1};
 struct xdev_ext_mech_stage st={.s=&session,.priv=&cs};
 observed=&cs;
 assert(!xdev_ext_ce_lease_bind(&st,&cs,4096,4096));
 xdev_ext_comp_copy_lease_hold(&cs.lease,false);
 assert(!cs.lease.cleanup_held && !cs.lease.group->cleanup_holds);
 host_error=-EBUSY;
 int result=xdev_ext_ce_unbind(&st);
 if (result != -EBUSY || frees || module_puts || region_calls || !cs.copy.host || !st.priv) {
  puts("not ok 1 - failed host unmap must retain region, stage and module"); return 1;
 }
 check_native_hold();
 host_error=0; region_error=-EIO;
 result=xdev_ext_ce_unbind(&st);
 if (result != -EIO || frees || module_puts || cs.copy.host || !cs.region.priv) return 2;
 check_native_hold();
 int before=host_calls;
 region_error=0;
 result=xdev_ext_ce_unbind(&st);
 if (result || host_calls != before || frees != 1 || module_puts != 1 || st.priv) return 3;
 assert(!cs.lease.group && !cs.lease.cleanup_held && list_empty(&xdev_ext_ce_lease_domain.groups));
 assert(!xdev_ext_ce_unbind(&st) && frees==1 && module_puts==1);
 puts("ok 1 - failed host unmap retains every dependency and configured hold\nok 2 - failed region unmap retains residual ownership and configured hold\nok 3 - retry never replays successful host unmap; final detach releases one hold and module pin");
 return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='ce-teardown-', dir=os.environ.get('TMPDIR')) as tmp:
    src=Path(tmp)/'fixture.c'; binary=Path(tmp)/'fixture'
    src.write_text(prelude+'\n#include "'+str(ROOT/'src/compute/io_uring/xdev_ext_mech_ce_lease.h')+'"\n'+helpers+main)
    cmd=[os.environ.get('CC','gcc'),'-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-function','-pthread',
         '-fsanitize=undefined','-fno-sanitize-recover=all','-I'+str(ROOT/'src/core/include'),'-I'+str(ROOT/'src/core/include/linux'),'-I'+str(ROOT/'src/core/io_uring'),str(src),'-o',str(binary)]
    built=subprocess.run(cmd,capture_output=True,text=True)
    if built.returncode:
        print('SETUP: compile failed\n'+built.stdout+built.stderr)
        raise SystemExit(2)
    raise SystemExit(subprocess.run([str(binary)]).returncode)
