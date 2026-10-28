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

HERE = Path(__file__).resolve().parent
KERNEL = Path(os.environ.get('KERNEL_SRC', HERE.parents[4])).resolve()


def source(relative):
    return (KERNEL / relative).read_text()


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
    """Build @fixture (C source text) with -I<kernel>; return (exit code, output)."""
    compiler = shlex.split(os.environ.get('CC', 'cc'))
    if not shutil.which(compiler[0]):
        raise AssertionError('C compiler unavailable: ' + compiler[0])
    with tempfile.TemporaryDirectory(prefix='xdev-ext-compute-') as temporary:
        path = Path(temporary)
        (path / 'fixture.c').write_text(fixture)
        command = compiler + ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                              '-Wno-unused-function', '-Wno-unused-parameter',
                              '-fsanitize=undefined,address', '-fno-sanitize-recover=all',
                              '-I' + str(KERNEL), str(path / 'fixture.c'),
                              '-o', str(path / 'probe')]
        build = subprocess.run(command, text=True, capture_output=True)
        if build.returncode:
            raise AssertionError('fixture compile failed:\n' + build.stdout + build.stderr)
        run = subprocess.run([str(path / 'probe'), *args], text=True,
                             capture_output=True, timeout=timeout)
        return run.returncode, run.stdout + run.stderr
