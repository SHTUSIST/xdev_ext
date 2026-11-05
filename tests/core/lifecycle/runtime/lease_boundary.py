# SPDX-License-Identifier: GPL-2.0
"""Build a probe from the IAA lease fixture's OS boundary and production code.

Only the part of iaa_transform/lease_fixture.c before main() is reused: its
pool, page and custody shims.  Every function listed in iaa_transform's
lease_test.FUNCTIONS is the unchanged production text.  BOUNDARY adds the
allocation and reschedule shims a CREATE-time helper may need; nr_frames
resizes the fixture pool and patches replace exact boundary text.
"""
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
for _base in (HERE, *HERE.parents):
    if (_base / 'view.json').is_file() or (_base / 'source-layout.json').is_file():
        _shared = _base / 'tests/compute/transform_source.py'
        if not _shared.is_file():
            raise RuntimeError('missing owned transform source helper')
        sys.path.insert(0, str(_shared.parent))
        break
else:
    raise RuntimeError('missing owned checkout/view')
from transform_source import TransformSource, read_native, select_core, owned_dependency, source_root, verify_entry, compiler_headers  # noqa: E402
verify_entry(__file__, 'tests/core/lifecycle/runtime/lease_boundary.py')
ROOT = source_root(__file__, os.environ.get('KERNEL_SRC'))
LEASE = owned_dependency(__file__, 'tests/compute/iaa/transform/lease_test.py').parent
sys.path.insert(0, str(LEASE))
from lease_test import FUNCTIONS  # noqa: E402
from acquire_red_test import function, session_helpers  # noqa: E402

SHIMS = r'''
#ifndef GFP_KERNEL
#define GFP_KERNEL 0
#endif
static unsigned long test_reschedules __attribute__((unused)), test_live_allocs __attribute__((unused));
static void *test_kvmalloc_array(size_t n, size_t size) { test_live_allocs++; return calloc(n, size); }
static void test_kvfree(void *p) { if (p) test_live_allocs--; free(p); }
#undef cond_resched
#define cond_resched() (test_reschedules++)
#undef kvmalloc_array
#define kvmalloc_array(n,size,gfp) ((void)(gfp),test_kvmalloc_array((n),(size)))
#undef kvfree
#define kvfree(p) test_kvfree(p)
'''


def build(scenario, directory, nr_frames=None, name='probe', patches=()):
    core = select_core(ROOT, os.environ.get('XDEV_EXT_IAA_LEASE_SOURCE'))
    selected = TransformSource(core, lambda path: read_native(ROOT, path), function)
    production = selected.text
    fixture = owned_dependency(__file__, 'tests/compute/iaa/transform/lease_fixture.c').read_text().split('int main(', 1)[0]
    if selected.split:
        fixture = selected.storage(fixture)
        fixture = fixture.replace('struct xdev_ext_mech_batch {',
                                  selected.types + '\nstruct xdev_ext_mech_batch {', 1)
    if nr_frames is not None:
        fixture, n = re.subn(r'^#define N 80$', '#define N ' + str(nr_frames), fixture, flags=re.M)
        if n != 1:
            raise RuntimeError('lease fixture pool size boundary changed')
    # After every fixture shim, before the first production body: these
    # counting shims take precedence over any the fixture itself defines.
    marker = '/* xdev_ext_mech_frames_move */'
    if marker not in fixture:
        raise RuntimeError('lease fixture production boundary changed')
    fixture = fixture.replace(marker, SHIMS + marker, 1)
    for old, new in patches:
        if old not in fixture:
            raise RuntimeError('lease fixture boundary changed: ' + old)
        fixture = fixture.replace(old, new, 1)
    # These legacy scenarios never create an ordered START. Fail loudly if a
    # queue path is reached instead of silently modeling ordered custody.
    fixture = fixture.replace('struct xdev_ext_mech_batch {',
                              'struct xdev_ext_mech_batch { bool ordered_loan;')
    fixture = fixture.replace(marker, 'static int xdev_ext_mech_start_queue_release(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b,bool seq){(void)s;(void)b;(void)seq;abort();}\n' + marker)
    bodies = {}
    for fn in FUNCTIONS:
        body = function(production, fn)
        if fn == 'xdev_ext_mech_transform_reserve' and 'xdev_ext_mech_transform_alias_free' not in FUNCTIONS:
            # CREATE-time alias proof factored out of reserve; absent before.
            try:
                body = function(production, 'xdev_ext_mech_transform_alias_free') + '\n' + body
            except RuntimeError:
                pass
        bodies[fn] = body
    if selected.split:
        bodies['xdev_ext_mech_transform_handoff'] = function(production, 'xdev_ext_mech_transform_handoff')
        fixture = fixture.replace(marker, '\n'.join(selected.helpers(bodies.values())) + '\n' + marker, 1)
        fixture = fixture.replace('/* xdev_ext_mech_batch_handoff */',
            bodies['xdev_ext_mech_transform_handoff'] + '\n/* xdev_ext_mech_batch_handoff */', 1)
    # Match the real compiled closure, including historical source overrides.
    # The shared extractor rejects a called helper absent from that source.
    helpers = session_helpers(production, bodies.values())
    for helper in helpers:
        token = '/* ' + helper + ' */'
        if token not in fixture:
            fixture = fixture.replace(marker, token + '\n' + marker, 1)
        bodies[helper] = function(production, helper)
    if 'xdev_ext_mech_session_start_queue_check' in helpers:
        fixture = fixture.replace('#include "io_uring/xdev_ext_mech_step.h"',
            '#include "io_uring/xdev_ext_mech_step.h"\n#include "io_uring/xdev_ext_mech_start_queue.h"')
    for fn in helpers + list(FUNCTIONS):
        token = '/* ' + fn + ' */'
        if fixture.count(token) != 1:
            raise RuntimeError('lease fixture production marker changed: ' + fn)
        fixture = fixture.replace(token, bodies[fn], 1)
    source = Path(directory) / (name + '.c')
    include_root = compiler_headers(ROOT, Path(directory) / (name + '-qualified-include'), fixture + scenario)
    source.write_text(fixture + scenario)
    binary = Path(directory) / name
    built = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-Wall', '-Wextra', '-Werror',
                            '-Wno-unused-function', '-fsanitize=undefined',
                            '-fno-sanitize-recover=undefined', '-I' + str(include_root), str(source),
                            '-o', str(binary)], capture_output=True, text=True)
    if built.returncode:
        raise RuntimeError(built.stdout + built.stderr)
    return binary
