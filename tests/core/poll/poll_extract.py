# SPDX-License-Identifier: GPL-2.0
"""Shared helpers of the stage-polling host tests.

Every test compiles production functions copied verbatim from the kernel tree
(found from this file, or from $KERNEL_SRC) together with a small fixture that
supplies only the surrounding kernel types and calls. No production decision
is reimplemented in a fixture.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
KERNEL = Path(os.environ.get('KERNEL_SRC', next(p for p in HERE.parents if (p / 'source-layout.json').is_file()))).resolve()
import runpy
_helpers = runpy.run_path(str(next(p for p in HERE.parents if (p / 'source-layout.json').is_file()) / 'tests/integration/peer_graph/nvme_peer_async_test.py'))


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
        command = [compiler, '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                   '-Wno-unused-function', '-Wno-unused-parameter',
                   '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                   '-I' + str(_helpers['host_headers'](KERNEL, path / 'headers')), *('-D' + d for d in defines),
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
