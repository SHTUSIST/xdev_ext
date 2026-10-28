# SPDX-License-Identifier: GPL-2.0
"""Shared helpers of the reliable BPF-glue and policy tests: locate the tree,
select the default (#ifndef XDEV_EXT_REL_C_GLUE) text, extract production
function bodies, compile host fixtures and run them.

KERNEL_DIR selects the kernel tree; RELIABLE_INC, RELIABLE_CORE and
RELIABLE_BPF select other sources (RED runs against older revisions).
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('KERNEL_DIR', str(next(
    p for p in HERE.parents if (p / 'io_uring/xdev_ext_mech.c').is_file()))))
INC = Path(os.environ.get('RELIABLE_INC', str(ROOT / 'net/xdp/xsk_xdev_ext_mech_reliable.inc')))
CORE = Path(os.environ.get('RELIABLE_CORE', str(ROOT / 'include/linux/xdev_ext_mech_reliable_core.h')))
BPF = Path(os.environ.get('RELIABLE_BPF', str(ROOT / 'tools/xdev_ext_mech/nxp_reliable.bpf.c')))
XSK = ROOT / 'net/xdp/xsk_xdev_ext_mech.c'
KFUNC_H = ROOT / 'tools/xdev_ext_mech/xdev_ext_mech_kfunc.h'
PROG_H = ROOT / 'tools/xdev_ext_mech/xdev_ext_mech_prog.h'
CTL = ROOT / 'tools/xdev_ext_mech/xdev_ext_mech_ctl.c'
POLICY_H = ROOT / 'io_uring/xdev_ext_policy.h'
POLICY_C = ROOT / 'io_uring/xdev_ext_policy.c'
POLICY_UAPI = ROOT / 'include/uapi/linux/xdev_ext_policy.h'
CREF_HOST = ROOT / 'tools/testing/selftests/xdev_ext_mech/cref/host'
GLUE = 'XDEV_EXT_REL_C_GLUE'


def unifdef(text, macro=GLUE, defined=False):
    """Resolve #ifdef/#ifndef/#if [!]defined(macro) blocks for one macro only.

    Every other conditional is passed through unchanged (with its own
    #else/#endif tracked so nesting stays correct).
    """
    out = []
    stack = []   # (is_ours, value, parent_keep)
    keep = True
    cond = re.compile(r'^\s*#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)$')
    for line in text.splitlines(keepends=True):
        m = cond.match(line)
        if not m:
            if keep:
                out.append(line)
            continue
        kind, rest = m.group(1), m.group(2).strip()
        ours = False
        value = None
        if kind in ('ifdef', 'ifndef'):
            ours = bool(rest) and rest.split()[0] == macro
            value = (kind == 'ifdef') == defined
        elif kind == 'if':
            mm = re.fullmatch(r'(!\s*)?defined\s*\(?\s*' + re.escape(macro) + r'\s*\)?', rest)
            if mm:
                ours = True
                value = (mm.group(1) is None) == defined
        if kind in ('ifdef', 'ifndef', 'if'):
            stack.append((ours, value if ours else None, keep))
            if ours:
                keep = keep and value
            elif keep:
                out.append(line)
            continue
        if not stack:
            raise RuntimeError('unbalanced #' + kind)
        is_ours, value, parent = stack[-1]
        if kind == 'elif':
            if is_ours:
                raise RuntimeError('#elif inside ' + macro + ' block is not supported')
            if parent:
                out.append(line)
            continue
        if kind == 'else':
            if is_ours:
                keep = parent and not value
            elif parent:
                out.append(line)
            continue
        stack.pop()
        if is_ours:
            keep = parent
        elif parent:
            out.append(line)
    if stack:
        raise RuntimeError('unterminated conditional')
    return ''.join(out)


def default_text(path):
    return unifdef(Path(path).read_text(), GLUE, False)


def glue_text(path):
    return unifdef(Path(path).read_text(), GLUE, True)


def strip_comments(text):
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
    return re.sub(r'//[^\n]*', ' ', text)


def function(text, name):
    """The full definition (signature line through closing brace) of @name."""
    for m in re.finditer(r'^[^\n;#{}]*\b' + re.escape(name) + r'\s*\(', text, re.M):
        start = m.start()
        i = m.end()
        depth = 1
        while i < len(text) and depth:
            if text[i] == '(':
                depth += 1
            elif text[i] == ')':
                depth -= 1
            i += 1
        j = i
        while j < len(text) and text[j] in ' \t\n':
            j += 1
        if j < len(text) and text[j] == '{':
            depth = 0
            k = j
            while k < len(text):
                if text[k] == '{':
                    depth += 1
                elif text[k] == '}':
                    depth -= 1
                    if not depth:
                        return text[start:k + 1]
                k += 1
    return None


def require(text, name, where):
    body = function(text, name)
    if body is None:
        raise AssertionError('missing production definition of %s in %s' % (name, where))
    return body


def closure(text, roots, prefix='xsk_rel_', exclude=()):
    """Definitions of @roots plus every @prefix function they call
    (transitively), preceded by their prototypes."""
    seen = []
    pending = list(roots)
    bodies = {}
    while pending:
        name = pending.pop(0)
        if name in bodies or name in exclude:
            continue
        body = require(text, name, 'default text')
        bodies[name] = body
        seen.append(name)
        for callee in re.findall(r'\b(' + re.escape(prefix) + r'\w+)\s*\(', strip_comments(body)):
            if callee != name and callee not in bodies and callee not in exclude:
                pending.append(callee)
    protos = [bodies[n][:bodies[n].index('{')].strip() + ';' for n in seen]
    return '\n'.join(protos) + '\n' + '\n'.join(bodies[n] for n in reversed(seen))


def cc():
    return shlex.split(os.environ.get('CC', 'cc'))


HOST_FLAGS = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
              '-Wno-unused-function', '-Wno-unused-parameter', '-Wno-unused-variable',
              '-Wno-unused-but-set-variable',
              '-fsanitize=undefined', '-fno-sanitize-recover=undefined']


def build_and_run(test, source, extra=(), name='probe', run=True):
    """Compile @source (text) as one host program; return (build, run) results."""
    with tempfile.TemporaryDirectory(prefix='xdev_ext-rel-glue-') as tmp:
        path = Path(tmp)
        (path / (name + '.c')).write_text(source)
        build = subprocess.run(cc() + HOST_FLAGS + ['-I', str(ROOT)] + list(extra) +
                               [str(path / (name + '.c')), '-o', str(path / name)],
                               capture_output=True, text=True)
        test.assertEqual(build.returncode, 0, 'host build failed:\n' + build.stderr[-6000:])
        if not run:
            return build, None
        result = subprocess.run([str(path / name)], capture_output=True, text=True, timeout=120)
        test.assertEqual(result.returncode, 0, result.stdout[-6000:] + result.stderr[-6000:])
        return build, result
