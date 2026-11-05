# SPDX-License-Identifier: GPL-2.0
"""Shared helpers of the BPF compute callback host tests.

Every test compiles production functions copied verbatim from the kernel tree
(found from this file, or from $KERNEL_SRC) together with a fixture that
supplies only the surrounding kernel types and calls. No production decision
is reimplemented in a fixture. A missing production function is a failure,
never a skip.
"""
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
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
from transform_source import TransformSource, field, read_native, structure, source_root, verify_entry, compiler_headers  # noqa: E402
verify_entry(__file__, 'tests/compute/cpu/compute_extract.py')

KERNEL = source_root(__file__, os.environ.get('KERNEL_SRC'))


def source(relative):
    return read_native(KERNEL, relative)


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


def compile_and_run(fixture, args=(), timeout=20):
    """Build @fixture with qualified native headers; return (exit code, output)."""
    compiler = shlex.split(os.environ.get('CC', 'cc'))
    if not shutil.which(compiler[0]):
        raise AssertionError('C compiler unavailable: ' + compiler[0])
    with tempfile.TemporaryDirectory(prefix='xdev-ext-compute-') as temporary:
        path = Path(temporary)
        include_root = compiler_headers(KERNEL, path / 'qualified-include', fixture)
        (path / 'fixture.c').write_text(fixture)
        command = compiler + ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                              '-Wno-unused-function', '-Wno-unused-parameter',
                              '-fsanitize=undefined,address', '-fno-sanitize-recover=all',
                              '-I' + str(include_root), str(path / 'fixture.c'),
                              '-o', str(path / 'probe')]
        build = subprocess.run(command, text=True, capture_output=True)
        if build.returncode:
            raise AssertionError('fixture compile failed:\n' + build.stdout + build.stderr)
        run = subprocess.run([str(path / 'probe'), *args], text=True,
                             capture_output=True, timeout=timeout)
        return run.returncode, run.stdout + run.stderr
