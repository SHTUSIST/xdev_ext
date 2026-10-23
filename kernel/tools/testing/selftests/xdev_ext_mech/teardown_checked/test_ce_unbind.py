#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the real CE teardown at a refusing native unmap boundary."""
from pathlib import Path
import os
import subprocess
import tempfile
import re

KERNEL = Path(__file__).resolve().parents[5]
text = (KERNEL / 'io_uring/xdev_ext_mech_ce.c').read_text()
match = re.search(r'static (void|int) xdev_ext_ce_unbind\([^;]+?\n\{', text)
assert match
start = match.start()
depth = 1
end = match.end()
while depth:
    depth += (text[end] == '{') - (text[end] == '}')
    end += 1
function = text[start:end]
checked = match[1] == 'int'
prelude = r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#define WARN_ON_ONCE(x) (x)
struct xdev_ext_ce_region { const struct xdev_ext_ce_backend_ops *ops; void *priv; };
struct xdev_ext_ce_stage { struct xdev_ext_ce_region region; void *host; int ambiguous; void *lease_group; };
struct xdev_ext_mech_stage { void *priv; };
static int host_error, region_error, host_calls, region_calls, frees, module_puts, lease_calls;
static int atomic_read(const int *p) { return *p; }
static void kfree(void *p) { (void)p; frees++; }
static void module_put(void *p) { (void)p; module_puts++; }
static bool xdev_ext_ce_lease_unbind(struct xdev_ext_ce_stage *cs)
{ lease_calls++; cs->lease_group = NULL; return true; }
'''
if checked:
    prelude += r'''
struct xdev_ext_ce_backend_ops { void *owner; int (*unbind_host)(void *); int (*unbind_region)(struct xdev_ext_ce_region *); };
static int host_unmap(void *p) { (void)p; host_calls++; return host_error; }
static int region_unmap(struct xdev_ext_ce_region *r) { region_calls++; if (!region_error) r->priv=NULL; return region_error; }
'''
else:
    prelude += r'''
struct xdev_ext_ce_backend_ops { void *owner; void (*unbind_host)(void *); void (*unbind_region)(struct xdev_ext_ce_region *); };
static void host_unmap(void *p) { (void)p; host_calls++; }
static void region_unmap(struct xdev_ext_ce_region *r) { region_calls++; if (!region_error) r->priv=NULL; }
'''
call = 'int result = xdev_ext_ce_unbind(&st);' if checked else 'xdev_ext_ce_unbind(&st); int result = 0;'
main = r'''
int main(void) {
 const struct xdev_ext_ce_backend_ops ops={ .unbind_host=host_unmap, .unbind_region=region_unmap };
 struct xdev_ext_ce_stage cs={ .region={.ops=&ops,.priv=(void*)1}, .host=(void*)2, .lease_group=(void*)3 };
 struct xdev_ext_mech_stage st={.priv=&cs};
 host_error=-EBUSY;
 CALL
 if (result != -EBUSY || frees || module_puts || region_calls || !cs.host || !st.priv) {
  puts("not ok 1 - failed host unmap must retain region, stage and module"); return 1;
 }
 host_error=0; region_error=-EIO;
 result=xdev_ext_ce_unbind(&st);
 if (result != -EIO || frees || module_puts || cs.host || !cs.region.priv) return 2;
 int before=host_calls;
 region_error=0;
 result=xdev_ext_ce_unbind(&st);
 if (result || host_calls != before || frees != 1 || module_puts != 1 || st.priv) return 3;
 printf("ok 1 - failed host unmap retains every dependency\nok 2 - failed region unmap retains residual ownership\nok 3 - retry never replays successful host unmap\n");
 return 0;
}
'''.replace('CALL',call).replace('puts(', 'printf(')
# The legacy wrapper supplies a result so old production runs and fails behaviorally.
if not checked:
    main = main.replace('result=xdev_ext_ce_unbind(&st);','xdev_ext_ce_unbind(&st); result=0;')
with tempfile.TemporaryDirectory(prefix='ce-teardown-', dir=os.environ.get('TMPDIR')) as tmp:
    src=Path(tmp)/'fixture.c'; binary=Path(tmp)/'fixture'
    src.write_text(prelude+function+main)
    subprocess.run([os.environ.get('CC','gcc'),'-std=gnu11','-Wall','-Wextra','-Werror',str(src),'-o',str(binary)],check=True)
    raise SystemExit(subprocess.run([str(binary)]).returncode)
