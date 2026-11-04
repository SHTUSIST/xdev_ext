# SPDX-License-Identifier: GPL-2.0
"""Shared helpers of the stage-polling host tests.

Every test compiles production functions copied verbatim from the kernel tree
(found from this file, or from $KERNEL_SRC) together with a small fixture that
supplies only the surrounding kernel types and calls. No production decision
is reimplemented in a fixture.
"""
import importlib.util
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
# Bootstrap the existing layout API; a nearby manifest may belong to a view.
# The API resolves the script's receipt-backed canonical helper owner.
_layout_path = next(p / 'tools/layout.py' for p in HERE.parents
                    if (p / 'tools/layout.py').is_file())
_layout_spec = importlib.util.spec_from_file_location('_xdev_ext_poll_layout', _layout_path)
_layout = importlib.util.module_from_spec(_layout_spec)
sys.modules[_layout_spec.name] = _layout
_layout_spec.loader.exec_module(_layout)
SCRIPT_ROOT = _layout.canonical_root(HERE)
KERNEL = Path(os.environ.get('KERNEL_SRC', SCRIPT_ROOT)).resolve()
_helpers = runpy.run_path(str(SCRIPT_ROOT / 'tests/integration/peer_graph/nvme_peer_async_test.py'))


def source(relative):
    return _helpers['read_native'](KERNEL, relative)


def function(text, name):
    """The definition of @name: its signature line(s) through the closing brace."""
    match = re.search(r'^[A-Za-z_][^;{}()]*?\b' + re.escape(name) + r'\([^;{}]*\)\s*\{',
                      text, re.M)
    if not match:
        raise AssertionError('production function missing: ' + name)
    depth, i = 1, match.end()
    while depth:
        if i >= len(text):
            raise AssertionError('unterminated function: ' + name)
        depth += (text[i] == '{') - (text[i] == '}')
        i += 1
    return text[match.start():i]


def body(text, name):
    """Only the statements of @name, for structural checks."""
    whole = function(text, name)
    return whole[whole.index('{'):]


def compile_and_run(fixture, args=(), defines=(), timeout=10):
    """Build @fixture (C source text) with -I<kernel>; return (exit code, stdout)."""
    compiler = shutil.which(os.environ.get('CC', 'cc'))
    if not compiler:
        raise AssertionError('C compiler unavailable')
    with tempfile.TemporaryDirectory(prefix='xdev-ext-poll-') as temporary:
        path = Path(temporary)
        (path / 'fixture.c').write_text(fixture)
        include_root = _helpers['host_headers'](KERNEL, path / 'headers')
        if include_root == path / 'headers' and re.search(
                r'^\s*#\s*include\s*["<]tools/xdev_ext_mech/xdev_ext_mech_ctl_core\.h[">]',
                fixture, re.M):
            # The CLI core's quoted sibling and relative portable includes
            # must share this disposable include boundary. Read both through
            # the selected source's native mapping, never a foreign hint.
            for native in ('tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h',
                           'tools/xdev_ext_mech/xdev_ext_mech_prog.h'):
                target = include_root / native
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source(native))
        command = [compiler, '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                   '-Wno-unused-function', '-Wno-unused-parameter',
                   '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                   '-I' + str(include_root), *('-D' + d for d in defines),
                   str(path / 'fixture.c'), '-o', str(path / 'probe')]
        build = subprocess.run(command, text=True, capture_output=True)
        if build.returncode:
            raise AssertionError('fixture compile failed:\n' + build.stdout + build.stderr)
        run = subprocess.run([str(path / 'probe'), *args], text=True,
                             capture_output=True, timeout=timeout)
        return run.returncode, run.stdout + run.stderr


def fields(output):
    """key=value words of the probe's last line."""
    line = [l for l in output.splitlines() if '=' in l][-1]
    return {k: int(v, 0) for k, v in (w.split('=', 1) for w in line.split())}
