#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""T-COMP: what each evaluated device chain is built from, counted by item.

    chain_composition.py [--repo DIR] [--revision REV | --worktree]
                         [--upstream-git COMPONENT=GITDIR ...]
                         [--json OUT] [--markdown OUT]

For every chain in CHAINS this reads one source tree and enumerates the items
the chain uses: functions, hooks (function-valued entries of ops tables) and
rows of the core class declaration table.  Every item is classified:

  per-class   written once for one device class, driver, provider or BPF
              program; it names no other device kind;
  per-pair    names a second device kind (in BPF also: shared by the programs
              of two classes), i.e. code written for a device pair;
  shared      core or family code that names no device kind.

Each item records where it runs: "kernel" (trusted C) or "bpf" (verified
program).  Separately, every occurrence under src/core and in family-layer
files of a named class
constant (XDEV_EXT_MECH_CLASS_<NAME>) or of a class-specific identifier is
classified as a registration entry, a per-class dispatch or a per-pair
condition, with the deciding rule and the source line:

  R-SCOPE    outside any function body (enum, table row, type, prototype,
             file-scope macro invocation)                  -> registration
  R-PP       in a preprocessor line (#define, #include)    -> registration
  R-REGCALL  the statement calls a registration function   -> registration
  R-PAIR     one statement compares two different class identities against
             two different operands, or names two device kinds without
             such a comparison                             -> per-pair
  R-SET      several identities compared against one operand
                                                           -> per-class dispatch
  R-ONE      the statement names one device kind           -> per-class dispatch

A core or family function is per-pair when one of its sites is, or when the
function as a whole holds a pair split over several statements:

  F-OPERANDS identities compared against two different operands anywhere in
             the body; a case label compares against its switch subject
  F-KINDS    two device kinds named outside the arms of a single-operand
             switch, or within one arm; identities already counted by
             F-OPERANDS and registration statements are not kinds here

Otherwise it is per-class when it names a device kind, else shared.

Functions are found by kernel C layout: a body is a "{" at file scope after a
header ending in a parameter list.  Comments and string literals never count.
A function in a file that overlays an upstream file (Linux or NVIDIA, pinned
in third_party/sources.lock.json) counts only when it is new or its
comment-free text differs from the pinned upstream; an ops-table entry there
counts only when it is new or changed.  Upstream blobs come from
build/upstream/<component>.git or --upstream-git; a missing cache or commit
is an error, never a guess.

Roots of a chain are the ops tables in its components (or only the tables
a component lists in root_tables), the struct_ops maps of its BPF programs
that the chain names as attached (a map in the same file the chain does not
attach is not counted; a named map missing from the file is an error) and, for components marked root_all_changed (driver hook files stock code
calls through pointers), every changed function.  The closure follows
identifier references inside the chain's components.  A stock function the
product changed that calls reached code, and any product function that
refers to a reached table, is counted as the site where the chain is entered
("caller"), but its other callees are not followed.  When such a stock
function is a dispatcher the product extended with new switch arms, only the
arms whose labels the chain lists in "commands" (with evidence) are judged
as executed; the other added arms are reported as not executed.  Without a
commands list every added arm counts.  Calls through pointers set elsewhere
are not followed.

Output is deterministic (sorted, no time stamps).  Exit status: 0; 1 when a
chain has a per-pair trusted kernel item or its catalog evidence no longer
matches the tree; 2 on input errors.  The count is a static property of one
tree, not a measurement of development effort.
"""
import argparse
import fnmatch
import json
from pathlib import Path
import re
import subprocess
import sys

SCHEMA = 'xdev-ext-chain-composition-v1'

CLASS_NAMES = ('AFXDP', 'NVME', 'CE', 'IAA', 'DMA', 'SOCKET', 'NET', 'CPU',
               'USER', 'XDOMAIN', 'BLOCK')
IDENTITY = re.compile(r'XDEV_EXT_MECH_CLASS_(' + '|'.join(CLASS_NAMES) + r')\Z')
CLASS_KIND = {n: n.lower() for n in CLASS_NAMES}

# Device-kind patterns, applied to single identifiers of comment-free code.
_P = r'^(?:xdev_ext|XDEV_EXT)_(?:mech_|MECH_|decl_)?'
KIND_PATTERNS = (
    ('nvme', re.compile(r'(?i:(?:^|_)nvme)')),
    ('xdomain', re.compile(r'(?i:(?:^|_)(?:xdomain|thunderbolt))|^tb_|^TB_|^nhi(?:_|$)|'
                           r'^NHI_|^xdev_ext_xd_|^xd_')),
    ('nvidia', re.compile(r'(?i:(?:^|_)(?:nvidia|cuda))|^nv_|^NV_|^Nv[A-Z0-9]|^cu[A-Z]')),
    ('afxdp', re.compile(r'(?i:(?:^|_)(?:xsk|afxdp))')),
    ('ice', re.compile(r'^(?:ice|ICE)_')),
    ('mlx5', re.compile(r'(?i:(?:^|_)mlx5)')),
    ('ce', re.compile(_P + r'(?:ce|CE|gpu|GPU)_|^XDEV_EXT_CTX_RULE_GPU$')),
    ('user', re.compile(_P + r'(?:user|USER)_')),
    ('iaa', re.compile(_P + r'(?:iaa|IAA)_')),
    ('cpu', re.compile(_P + r'(?:cpu|CPU)_')),
    ('socket', re.compile(_P + r'(?:socket|SOCKET)_')),
    ('block', re.compile(_P + r'(?:block|BLOCK)_')),
    ('dma', re.compile(r'^(?:xdev_ext|XDEV_EXT)_(?:dma|DMA)_(?:mech|MECH)_')),
    ('net', re.compile(r'^(?:xdev_ext|XDEV_EXT)_(?:net|NET)_(?:mech|MECH)_')),
)
REG_CALL = re.compile(r'register|(?:^|_)reg$|(?:^|_)unreg$|^BTF_TYPE_EMIT$|^static_assert$')
BPF_NAME_MACROS = ('BPF_PROG', 'BPF_PROG2', 'BPF_STRUCT_OPS', 'BPF_STRUCT_OPS_SLEEPABLE')
NOT_NAMES = ('SEC', 'if', 'for', 'while', 'switch', 'return', 'sizeof')
IDENT = re.compile(r'[A-Za-z_]\w*')
KEYWORDS = frozenset('''auto break case char const continue default do double else enum
extern float for goto if inline int long register restrict return short signed sizeof
static struct switch typedef union unsigned void volatile while bool true false NULL'''.split())

# ---------------------------------------------------------------------------
# Catalog.  Paths are canonical source paths ("source" in source-layout.json).
# own: the device kinds a component may name.  role: core and family items
# naming no kind are "shared"; any other role's items are "per-class" unless
# they name a foreign kind.  A file matching two components is an error,
# except that a class file inside src/core belongs to its class.
# ---------------------------------------------------------------------------
NV = 'src/compute/nvidia/kernel-open/nvidia/'
COMPONENTS = {
    'core': dict(role='core', own=[], files=[
        'src/core/io_uring/xdev_ext_*.c', 'src/core/io_uring/xdev_ext_*.h',
        'src/core/io_uring/unified_ops*', 'src/core/io_uring/sched_hints.*',
        'src/core/io_uring/io_uring.c', 'src/core/io_uring/register.c',
        'src/core/io_uring/opdef.c', 'src/core/io_uring/family/*.c',
        'src/core/io_uring/programs/*', 'src/core/include/linux/*.h',
        'src/core/include/uapi/linux/*.h', 'src/core/include/trace/events/*.h',
        'src/core/kernel/dma/*.c']),
    'class:USER': dict(role='class', own=['user'], cls='USER', files=[
        'src/core/io_uring/xdev_ext_mech_user.c', 'src/core/io_uring/xdev_ext_mech_user_core.h']),
    'class:DMA': dict(role='class', own=['dma'], cls='DMA', files=[
        'src/core/io_uring/xdev_ext_mech_dma.c', 'src/core/io_uring/xdev_ext_mech_dma_core.h']),
    'provider:dmabuf': dict(role='provider', own=[], files=[
        'src/core/io_uring/xdev_ext_peer_dmabuf.c', 'src/core/include/linux/xdev_ext_peer_dmabuf.h',
        'src/core/drivers/dma-buf/heaps/system_heap.c']),
    'family:network': dict(role='family', own=[], files=[
        'src/network/io_uring/family/*.c', 'src/network/include/linux/xdev_ext_netfam*.h',
        'src/network/include/linux/xdev_ext_peer_net_track.h']),
    'family:storage': dict(role='family', own=[], files=[
        'src/storage/io_uring/family/*.c', 'src/storage/include/linux/xdev_ext_storfam*.h',
        'src/storage/block/*.c']),
    'family:compute': dict(role='family', own=[], files=[
        'src/compute/io_uring/xdev_ext_compfam*', 'src/compute/include/linux/xdev_ext_compfam*.h']),
    'class:XDOMAIN': dict(role='class', own=['xdomain'], cls='XDOMAIN', files=[
        'src/network/io_uring/xdomain/xdev_ext_xdomain_class.c',
        'src/network/io_uring/xdomain/xdev_ext_xdomain_early.h',
        'src/network/io_uring/xdomain/xdev_ext_xdomain_core.h',
        'src/network/io_uring/xdev_ext_mech_xdomain_kfunc.c']),
    'service:xdomain': dict(role='driver', own=['xdomain'], files=[
        'src/network/io_uring/xdomain/xdev_ext_xdomain_main.c',
        'src/network/io_uring/xdomain/xdev_ext_xdomain_ring.c',
        'src/network/io_uring/xdomain/xdev_ext_xdomain_probe.c',
        'src/network/io_uring/xdomain/xdev_ext_xdomain_probe_core.h',
        'src/network/io_uring/xdomain/xdev_ext_xdomain.h']),
    'driver:thunderbolt': dict(role='driver', own=['xdomain'], root_all_changed=True, files=[
        'src/network/drivers/thunderbolt/nhi.c', 'src/network/drivers/thunderbolt/xdomain.c',
        'src/network/drivers/thunderbolt/tb.c', 'src/network/include/linux/thunderbolt.h']),
    'class:NVME': dict(role='class', own=['nvme'], cls='NVME', files=[
        'src/storage/drivers/nvme/host/xdev_ext_mech_nvme.c',
        'src/storage/drivers/nvme/host/xdev_ext_peer_nvme_core.h',
        'src/storage/drivers/nvme/host/xdev_ext_native_peer_trace.h',
        'src/storage/include/linux/nvme_xdev_ext_passthru.h']),
    'driver:nvme': dict(role='driver', own=['nvme'], files=[
        'src/storage/drivers/nvme/host/pci.c', 'src/storage/drivers/nvme/host/core.c',
        'src/storage/drivers/nvme/host/ioctl.c', 'src/storage/drivers/nvme/host/nvme.h',
        'src/storage/drivers/nvme/host/fabrics.h', 'src/storage/include/uapi/linux/nvme_ioctl.h']),
    'class:AFXDP': dict(role='class', own=['afxdp'], cls='AFXDP', files=[
        'src/network/net/xdp/xsk_xdev_ext_mech*']),
    'driver:afxdp': dict(role='driver', own=['afxdp'], files=[
        'src/network/net/xdp/xsk.c', 'src/network/net/xdp/xsk_buff_pool.c',
        'src/network/include/net/*.h']),
    'driver:ice-xsk': dict(role='driver', own=['ice', 'afxdp'], root_all_changed=True, files=[
        'src/network/drivers/net/ethernet/intel/ice/ice_xsk.c']),
    'class:CE': dict(role='class', own=['ce'], cls='CE', files=[
        'src/compute/io_uring/xdev_ext_mech_ce*']),
    'backend:nvidia-ce': dict(role='backend', own=['nvidia', 'ce'], files=[
        NV + 'nv-xdev_ext-ce-*', NV + 'nv-xdev_ext-dma-lifetime.h', NV + 'nv-xdev_ext-gpu*.h',
        NV + 'nv-xdev_ext-umem-quota.h']),
    'provider:nvidia-vram': dict(role='provider', own=['nvidia'], files=[
        NV + 'nv-xdev_ext-peer.c', NV + 'nv-xdev_ext-peer.h', NV + 'nv-xdev_ext-peer-backing.h',
        NV + 'nv-p2p-gpu-identity.h', NV + 'nv-xdev_ext-dmabuf.h']),
    'driver:nvidia': dict(role='driver', own=['nvidia', 'ce'], root_tables=[], files=[
        NV + 'nv-p2p.c', NV + 'nv-p2p.h', NV + 'nv.c', NV + 'nv-dmabuf.c', NV + 'os-interface.c',
        'src/compute/nvidia/kernel-open/common/inc/*.h', 'src/compute/nvidia/src/nvidia/*']),
}

# A chain lists the classes its sessions use, the components it composes and
# the BPF programs attached, each as (file, [struct_ops maps the chain
# attaches]); other maps in the same file are not used by the chain.  evidence: (path, literal) pairs that must still
# be in the tree; absent: paths that must not be (a piece only on a branch).
CHAINS = (
    dict(id='M-TP', title='VRAM <-> Thunderbolt <-> VRAM (TP=2 exchange)',
         sessions=[dict(side='sender, each rank', pool='PEER (NVIDIA VRAM allocation)',
                        stages=['USER producer', 'XDOMAIN TO_DEVICE', 'USER terminal']),
                   dict(side='receiver, each rank', pool='PEER (NVIDIA VRAM allocation)',
                        stages=['XDOMAIN FROM_DEVICE', 'USER terminal'])],
         classes=['XDOMAIN', 'USER'],
         components=['core', 'family:network', 'family:compute', 'class:XDOMAIN',
                     'service:xdomain', 'driver:thunderbolt', 'class:USER',
                     'provider:nvidia-vram', 'driver:nvidia'],
         bpf=[('examples/network/xdomain_peer.bpf.c', ['xdomain_peer_ops']),
              ('examples/compute/user_plan.bpf.c', ['user_plan_ops'])],
         evidence=[('src/lib/xdev_ext_peer_message.c', 'ret = xdev_ext_session_open_peer(&pool, &e->session);'),
                   ('src/lib/xdev_ext_peer_message.c', 'ret = xdev_ext_stage_xdomain(&create.st[native], control, o->link_token,'),
                   ('src/lib/xdev_ext_peer_message.c', '.class_id = XDEV_EXT_MECH_CLASS_USER,'),
                   ('tests/benchmarks/tp/README.md', 'the XDOMAIN class BPF object, USER class BPF object')],
         absent=[], missing=[]),
    dict(id='E4-direct', title='NVMe -> VRAM, NVMe READ straight into GPU memory',
         sessions=[dict(side='single host', pool='PEER (NVIDIA VRAM allocation)',
                        stages=['NVME FROM_DEVICE', 'second stage of the tool (NVME TO_DEVICE or NET TX)'])],
         classes=['NVME'],
         components=['core', 'family:storage', 'class:NVME', 'driver:nvme',
                     'provider:nvidia-vram', 'driver:nvidia'],
         bpf=[('examples/storage/nvme_s0.bpf.c', ['nvme_s0_ops'])],
         evidence=[('src/cli/xdev_ext_peer_chain.c', '.pool_kind = XDEV_EXT_MECH_POOL_PEER, .pool_fd = allocation,'),
                   ('src/cli/xdev_ext_peer_chain.c', 'create.st[0] = (struct xdev_ext_mech_stage_uapi){.class_id=XDEV_EXT_MECH_CLASS_NVME,'),
                   ('src/cli/xdev_ext_peer_chain.c', 'ret=load_ops(argv[base+7],"nvme_s0",&nvme);')],
         absent=[],
         missing=['performance runner of the direct arm (plan section 2.4 lists it as not written); '
                  'the mechanism path it would drive is in this tree and is counted']),
    dict(id='E4-ce', title='NVMe -> VRAM, host frame then GPU copy engine',
         sessions=[dict(side='single host', pool='IOU_UMEM (host pages)',
                        stages=['NVME FROM_DEVICE', 'CE TO_DEVICE (H2D)'])],
         classes=['NVME', 'CE'],
         components=['core', 'family:storage', 'family:compute', 'class:NVME', 'driver:nvme',
                     'class:CE', 'backend:nvidia-ce', 'driver:nvidia'],
         # nxp_mech.bpf.c also holds nxp_afxdp_ops; the arm attaches only
         # nxp_nvme_ops (guest_correctness.sh, session_nvme_ce.c, README.md).
         bpf=[('examples/pipelines/nxp_mech.bpf.c', ['nxp_nvme_ops']),
              ('examples/compute/ce_plan.bpf.c', ['ce_plan_ops'])],
         evidence=[('tests/benchmarks/nvme_gpu/session_nvme_ce.c', 'c.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM;'),
                   ('tests/benchmarks/nvme_gpu/session_nvme_ce.c', '.class_id = XDEV_EXT_MECH_CLASS_CE,'),
                   ('tests/benchmarks/nvme_gpu/README.md', '`nxp_nvme_ops` (`nxp_mech.bpf.o`'),
                   ('tests/benchmarks/nvme_gpu/guest_correctness.sh', '--obj "$dir/nxp_mech.bpf.o" --map nxp_nvme_ops'),
                   ('tests/benchmarks/nvme_gpu/eval_session.h', 'if (!xdev_ext_nv_ce_attach_memory(fd, &attach))')],
         # Driver commands (switch labels the product added to a stock
         # dispatcher) the chain issues; other added arms are not executed.
         commands=['NV_ESC_XDEV_EXT_CE_ATTACH_MEMORY'],
         absent=[], missing=[]),
    dict(id='E3-a2', title='NVMe -> AF_XDP (value serving, kernel continuation arm)',
         sessions=[dict(side='single host', pool='XSK (AF_XDP UMEM)',
                        stages=['NVME FROM_DEVICE', 'AFXDP TO_DEVICE'])],
         classes=['NVME', 'AFXDP'],
         components=['core', 'family:storage', 'family:network', 'class:NVME', 'driver:nvme',
                     'class:AFXDP', 'driver:afxdp', 'driver:ice-xsk'],
         bpf=[('tests/benchmarks/nvme_nic/nnb_bench.bpf.c', ['nnb_nvme_ops', 'nnb_afxdp_ops'])],
         evidence=[('tests/benchmarks/nvme_nic/nnb_session.c', 'create.pool_kind = XDEV_EXT_MECH_POOL_XSK;'),
                   ('tests/benchmarks/nvme_nic/nnb_session.c', 'create.st[1] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_AFXDP,'),
                   ('tests/benchmarks/nvme_nic/run.py', "default=str(HERE / '.build/bpf/nnb_bench.bpf.o')"),
                   ('tests/benchmarks/nvme_nic/nnb_session.c', 'static const char *const names[2] = { "nnb_nvme_ops", "nnb_afxdp_ops" };')],
         absent=[], missing=[]),
    dict(id='K-KV', title='NVMe -> Thunderbolt -> VRAM (KV restore from the neighbour SSD)',
         sessions=[dict(side='host 1', pool='PEER (dma-buf importer or NVIDIA VRAM allocation)',
                        stages=['NVME FROM_DEVICE', 'XDOMAIN TO_DEVICE']),
                   dict(side='host 2', pool='PEER (NVIDIA VRAM allocation)',
                        stages=['XDOMAIN FROM_DEVICE', 'USER terminal'])],
         classes=['NVME', 'XDOMAIN', 'USER'],
         components=['core', 'family:storage', 'family:network', 'family:compute', 'class:NVME',
                     'driver:nvme', 'class:XDOMAIN', 'service:xdomain', 'driver:thunderbolt',
                     'class:USER', 'provider:dmabuf', 'provider:nvidia-vram', 'driver:nvidia'],
         bpf=[('examples/storage/nvme_s0.bpf.c', ['nvme_s0_ops']),
              ('examples/network/xdomain_peer.bpf.c', ['xdomain_peer_ops']),
              ('examples/compute/user_plan.bpf.c', ['user_plan_ops'])],
         evidence=[('tests/network/xdomain/chain/README.md', '# NVMe READ to XDOMAIN TX in one session worker'),
                   ('tests/network/xdomain/chain/README.md', '`nvme_s0.bpf.c` (NVMe build/complete) and `xdomain_peer.bpf.c`'),
                   ('src/lib/xdev_ext_peer_message.c', 'ret = xdev_ext_session_open_peer(&pool, &e->session);')],
         absent=['tests/benchmarks/kv_restore'],
         missing=['end-to-end KV restore driver: tests/benchmarks/kv_restore is absent from this tree '
                  '(only on a branch); not counted',
                  'host-page frames for XDOMAIN (42-XDOMAIN-HOST) are not in this tree; the counted '
                  'host-1 frame source is the PEER pool (dma-buf importer or NVIDIA VRAM)',
                  'the host-1 half (NVMe READ -> XDOMAIN TX in one session) is exercised only by the '
                  'host fixture of tests/network/xdomain/chain; no hardware run']),
)


class InputError(Exception):
    pass


# ---------------------------------------------------------------------------
# C text handling
# ---------------------------------------------------------------------------
def strip_c(text):
    """Comment- and literal-free code of @text with the same line structure,
    and {line: text} of preprocessor lines (comments removed)."""
    out, i, n = [], 0, len(text)
    while i < n:
        c, two = text[i], text[i:i + 2]
        if two == '/*':
            j = text.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append(''.join('\n' if ch == '\n' else ' ' for ch in text[i:j]))
            i = j
        elif two == '//':
            j = text.find('\n', i)
            j = n if j < 0 else j
            out.append(' ' * (j - i))
            i = j
        elif c in '"\'':
            j = i + 1
            while j < n and text[j] != c and text[j] != '\n':
                j += 2 if text[j] == '\\' else 1
            j = min(j + 1, n)
            out.append(c + ''.join('\n' if ch == '\n' else ' ' for ch in text[i + 1:j - 1])
                       + (c if j - i >= 2 else ''))
            i = j
        else:
            out.append(c)
            i += 1
    lines = ''.join(out).split('\n')
    pp, k = {}, 0
    while k < len(lines):
        if lines[k].lstrip().startswith('#'):
            start = k
            while lines[k].rstrip().endswith('\\') and k + 1 < len(lines):
                k += 1
            for m in range(start, k + 1):
                pp[m + 1] = lines[m]
                lines[m] = ' ' * len(lines[m])
        k += 1
    return '\n'.join(lines), pp


def _line_index(code):
    starts, pos = [0], 0
    while True:
        pos = code.find('\n', pos)
        if pos < 0:
            return starts
        pos += 1
        starts.append(pos)


def _lineno(starts, offset):
    lo, hi = 0, len(starts)
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if starts[mid] <= offset:
            lo = mid
        else:
            hi = mid
    return lo + 1


def _match(code, i):
    depth = 0
    for j in range(i, len(code)):
        if code[j] == '{':
            depth += 1
        elif code[j] == '}':
            depth -= 1
            if depth == 0:
                return j
    return len(code) - 1


def _groups(header):
    """(identifier before, start, end) of every top-level (...) of @header."""
    out, depth, start = [], 0, None
    for i, ch in enumerate(header):
        if ch == '(':
            if depth == 0:
                start = i
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0 and start is not None:
                m = re.search(r'([A-Za-z_]\w*)\s*$', header[:start])
                out.append((m.group(1) if m else None, start, i))
    return out


def function_name(header):
    groups = [g for g in _groups(header) if g[0] and g[0] not in NOT_NAMES
              and not g[0].startswith('__')]
    if not groups:
        return None, None
    name, start, _ = groups[-1]
    if name in BPF_NAME_MACROS:
        m = IDENT.search(header, start + 1)
        return (m.group(0) if m else None), start
    return name, start - len(name)


def _entries(body, base, starts):
    out = []
    for m in re.finditer(r'\.\s*([A-Za-z_]\w*)\s*=\s*([^,;{}]+)', body):
        value = re.sub(r'^\(\s*[A-Za-z_][\w\s\*]*\)\s*', '', m.group(2).strip())
        value = value.lstrip('&').strip()
        out.append(dict(member=m.group(1), value=value,
                        ident=value if re.fullmatch(r'[A-Za-z_]\w*', value) else None,
                        line=_lineno(starts, base + m.start())))
    return out


def _rows(body, base, starts):
    rows, depth, start, index = [], 0, None, 0
    inner = body[1:-1]
    for i, ch in enumerate(inner):
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start is not None:
                text = inner[start:i + 1]
                rows.append(dict(index=index, line=_lineno(starts, base + 1 + start),
                                 entries=_entries(text, base + 1 + start, starts), text=text))
        elif ch == ',' and depth == 0:
            index += 1
    return rows


def parse_c(text):
    """Functions and initialized tables of @text with line numbers."""
    code, pp = strip_c(text)
    starts = _line_index(code)
    funcs, tables = [], []
    i, seg, n = 0, 0, len(code)
    while i < n:
        ch = code[i]
        if ch == '{':
            header = code[seg:i]
            end = _match(code, i)
            h = header.strip()
            if re.search(r'=\s*$', h):
                m = re.search(r'([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*=\s*$', h)
                body = code[i:end + 1]
                nested = body.count('{') > 1
                tables.append(dict(name=m.group(1) if m else None, type=h,
                                   line=_lineno(starts, i), body=body,
                                   entries=[] if nested else _entries(body, i, starts),
                                   rows=_rows(body, i, starts) if nested else []))
                semi = code.find(';', end)
                i = seg = (n if semi < 0 else semi + 1)
                continue
            name, off = function_name(header) if '(' in h else (None, None)
            if name and re.search(r'\)\s*(?:__\w+(?:\([^()]*\))?\s*)*$', h):
                funcs.append(dict(name=name, line=_lineno(starts, seg + off),
                                  end=_lineno(starts, end), header=header,
                                  body=code[i:end + 1], start=i, stop=end,
                                  static=bool(re.search(r'\bstatic\b', header))))
                i = seg = end + 1
                continue
            semi = code.find(';', end)
            i = seg = (n if semi < 0 else semi + 1)
            continue
        if ch == ';':
            seg = i + 1
        i += 1
    return dict(code=code, pp=pp, starts=starts, funcs=funcs, tables=tables)


def tokens(code):
    return [t for t in IDENT.findall(code) if t not in KEYWORDS]


def token_kinds(tok):
    m = IDENTITY.match(tok)
    if m:
        return {CLASS_KIND[m.group(1)]}
    return {k for k, rx in KIND_PATTERNS if rx.search(tok)}


def kinds_of(code):
    found = {}
    for tok in tokens(code):
        for k in token_kinds(tok):
            found.setdefault(k, set()).add(tok)
    return found


def _norm(text):
    return re.sub(r'\s+', '', text)


# ---------------------------------------------------------------------------
# Tree access
# ---------------------------------------------------------------------------
class Tree:
    """files: {path: text}; upstream: {path: pinned upstream text, or None
    when the file is new}."""

    def __init__(self, files, upstream, revision=None):
        self.files, self.upstream, self.revision = files, upstream, revision
        self._parsed = {}

    def parsed(self, path, which='tree'):
        key = (path, which)
        if key not in self._parsed:
            self._parsed[key] = parse_c(self.files[path] if which == 'tree' else self.upstream[path])
        return self._parsed[key]


def _git(repo, *args):
    p = subprocess.run(['git', *args], cwd=str(repo), capture_output=True)
    if p.returncode:
        raise InputError('git %s: %s' % (' '.join(args), p.stderr.decode(errors='replace').strip()))
    return p.stdout.decode(errors='surrogateescape')


def load_tree(repo, revision, worktree, upstream_dirs, wanted):
    repo = Path(repo)

    def read(path):
        return ((repo / path).read_text(errors='surrogateescape') if worktree
                else _git(repo, 'show', revision + ':' + path))

    layout = json.loads(read('source-layout.json'))
    lock = json.loads(read('third_party/sources.lock.json'))
    listed = (_git(repo, 'ls-files', '-z') if worktree
              else _git(repo, 'ls-tree', '-r', '-z', '--name-only', revision)).split('\0')
    natives = {e['source']: (e['component'], e['native_path'])
               for e in layout['files'] if 'component' in e}
    files, upstream = {}, {}
    for path in sorted(p for p in listed if p and wanted(p)):
        files[path] = read(path)
        if path not in natives:
            upstream[path] = None
            continue
        component, native = natives[path]
        cache = Path(upstream_dirs.get(component) or repo / 'build/upstream' / (component + '.git'))
        commit = lock['components'][component]['commit']
        if not cache.is_dir():
            raise InputError('no upstream Git for %s: pass --upstream-git %s=DIR' % (component, component))
        if subprocess.run(['git', '-C', str(cache), 'cat-file', '-e', commit + '^{commit}'],
                          capture_output=True).returncode:
            raise InputError('pinned %s commit %s missing from %s' % (component, commit, cache))
        if subprocess.run(['git', '-C', str(cache), 'cat-file', '-e', commit + ':' + native],
                          capture_output=True).returncode:
            upstream[path] = None      # the overlay adds a file upstream does not have
            continue
        upstream[path] = _git(cache, 'cat-file', '-p', commit + ':' + native)
    head = None if worktree else _git(repo, 'rev-parse', revision + '^{commit}').strip()
    return Tree(files, upstream, head)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
def component_of(path, components):
    hit = [name for name, c in components.items()
           if any(fnmatch.fnmatchcase(path, pat) for pat in c['files'])]
    if len(hit) > 1 and 'core' in hit:
        hit.remove('core')
    if len(hit) > 1:
        raise InputError('%s matches components %s' % (path, ', '.join(sorted(hit))))
    return hit[0] if hit else None


def countable_functions(tree, path):
    """[(func, status)]: every function of a new file; new or changed ones
    of an upstream overlay."""
    p = tree.parsed(path)
    if tree.upstream.get(path) is None:
        return [(f, 'new-file') for f in p['funcs']]
    up = {}
    for f in tree.parsed(path, 'upstream')['funcs']:
        up.setdefault(f['name'], set()).add(_norm(f['header'] + f['body']))
    out = []
    for f in p['funcs']:
        if f['name'] not in up:
            out.append((f, 'added'))
        elif _norm(f['header'] + f['body']) not in up[f['name']]:
            out.append((f, 'changed'))
    return out


def countable_entries(tree, path, table):
    if tree.upstream.get(path) is None:
        return [(e, 'new-file') for e in table['entries']]
    old = {t['name']: t for t in tree.parsed(path, 'upstream')['tables']}.get(table['name'])
    if old is None:
        return [(e, 'added') for e in table['entries']]
    before = {e['member']: _norm(e['value']) for e in old['entries']}
    return [(e, 'added' if e['member'] not in before else 'changed') for e in table['entries']
            if before.get(e['member']) != _norm(e['value'])]


def statement_at(code, offset, lo, hi):
    a = max(code.rfind(';', lo, offset), code.rfind('{', lo, offset), code.rfind('}', lo, offset))
    ends = [x for x in (code.find(';', offset, hi), code.find('{', offset, hi)) if x >= 0]
    return code[a + 1:min(ends) if ends else hi].strip()


_OPERAND = r'([\w\.\[\]]+(?:->[\w\.\[\]]+)*)'


def comparisons(code):
    """[(operand, identity, offset of the identity)] of every == / != of a
    class identity constant in @code."""
    out = [(m.group(1), m.group(3), m.start(3)) for m in
           re.finditer(_OPERAND + r'\s*(==|!=)\s*(XDEV_EXT_MECH_CLASS_\w+)', code)]
    out += [(m.group(3), m.group(1), m.start(1)) for m in
            re.finditer(r'(XDEV_EXT_MECH_CLASS_\w+)\s*(==|!=)\s*' + _OPERAND, code)]
    return [x for x in out if IDENTITY.match(x[1])]


def classify_statement(stmt):
    """(category, rule) of one in-function statement naming a device kind."""
    if any(REG_CALL.search(c) for c in re.findall(r'([A-Za-z_]\w*)\s*\(', stmt)):
        return 'registration', 'R-REGCALL'
    pairs = [(op, c) for op, c, _ in comparisons(stmt)]
    idents, operands = {c for _, c in pairs}, {op for op, _ in pairs}
    if len(idents) >= 2 and len(operands) >= 2:
        return 'per-pair', 'R-PAIR'
    if len(idents) >= 2:
        return 'per-class', 'R-SET'
    kinds = set()
    for tok in tokens(stmt):
        kinds |= token_kinds(tok)
    if len(kinds) >= 2:
        return 'per-pair', 'R-PAIR'
    return 'per-class', 'R-ONE'


def decision_sites(tree, path):
    """Every occurrence in @path of a class identity constant or a
    class-specific identifier, classified."""
    p = tree.parsed(path)
    code, starts = p['code'], p['starts']
    raw = tree.files[path].split('\n')
    spans = [(f['start'], f['stop'], f) for f in p['funcs']]
    sites = []

    def add(line, tok, kinds, ctx, cat, rule, stmt):
        sites.append(dict(file=path, line=line, token=tok, kind=sorted(kinds)[0],
                          identity=bool(IDENTITY.match(tok)), context=ctx, category=cat,
                          rule=rule, text=raw[line - 1].strip(),
                          statement=re.sub(r'\s+', ' ', stmt) if stmt else None))

    for m in IDENT.finditer(code):
        kinds = token_kinds(m.group(0))
        if not kinds:
            continue
        owner = next((f for a, b, f in spans if a <= m.start() <= b), None)
        line = _lineno(starts, m.start())
        if owner is None:
            add(line, m.group(0), kinds, 'file scope', 'registration', 'R-SCOPE', None)
        else:
            stmt = statement_at(code, m.start(), owner['start'], owner['stop'])
            cat, rule = classify_statement(stmt)
            add(line, m.group(0), kinds, owner['name'], cat, rule, stmt)
    for line, directive in sorted(p['pp'].items()):
        for tok in tokens(directive):
            kinds = token_kinds(tok)
            if kinds:
                add(line, tok, kinds, 'preprocessor', 'registration', 'R-PP', None)
    sites.sort(key=lambda s: (s['file'], s['line'], s['token'], s['context']))
    return sites


def _arm_text(body, start):
    """Text of one switch arm from offset @start to the next label at the
    same depth or the end of the switch."""
    depth, i = 0, body.index(':', start) + 1
    while i < len(body):
        ch = body[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and re.match(r'\b(?:case|default)\b', body[i:]) and not \
                re.match(r'\w', body[i - 1]):
            break
        i += 1
    return body[start:i]


def added_arms(tree, path, f, status):
    """[{label, text}] for switch arms the product added to a stock function."""
    if status != 'changed':
        return []
    label = re.compile(r'\bcase\s+([A-Za-z_]\w*)\s*:')
    old = set()
    for g in tree.parsed(path, 'upstream')['funcs']:
        if g['name'] == f['name']:
            old |= set(label.findall(g['body']))
    return [dict(label=m.group(1), text=_arm_text(f['body'], m.start()))
            for m in label.finditer(f['body']) if m.group(1) not in old]


def switch_arms(code):
    """[{subject, label, start, stop}] of every case/default arm of every
    switch in @code (nested switches included); an arm runs from its label
    to the next label of the same switch or the end of the switch."""
    arms = []
    for m in re.finditer(r'\bswitch\s*\(', code):
        depth, j = 1, m.end()
        while j < len(code) and depth:
            depth += {'(': 1, ')': -1}.get(code[j], 0)
            j += 1
        subject, brace = re.sub(r'\s+', '', code[m.end():j - 1]), code.find('{', j)
        if brace < 0:
            continue
        end, depth, labels = _match(code, brace), 0, []
        for i in range(brace, end + 1):
            ch = code[i]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
            elif depth == 1 and re.match(r'(?:case|default)\b', code[i:]) and \
                    not re.match(r'\w', code[i - 1]):
                labels.append(i)
        for k, start in enumerate(labels):
            label = re.match(r'(?:case\s+(.+?)|default)\s*:', code[start:end], re.S)
            arms.append(dict(subject=subject, label=label.group(1).strip() if label and label.group(1)
                             else None, start=start,
                             stop=labels[k + 1] if k + 1 < len(labels) else end))
    return arms


def function_pair(f):
    """The pair evidence of a core or family function judged as a whole, or
    None.  F-OPERANDS: class identities compared against two different
    operands anywhere in the body (case labels compare against the switch
    subject).  F-KINDS: two device kinds named outside the arms of a
    single-operand switch, or within one arm; identities already counted as
    comparisons and registration statements do not name a kind here."""
    code = f['header'] + f['body']
    arms = switch_arms(code)
    comps = [(re.sub(r'\s+', '', op), c, off) for op, c, off in comparisons(code)]
    comps += [(a['subject'], a['label'], code.index(a['label'], a['start'])) for a in arms
              if a['label'] and IDENTITY.match(a['label'])]
    if len({c for _, c, _ in comps}) >= 2 and len({op for op, _, _ in comps}) >= 2:
        names = {}
        for _, c, _ in comps:
            names.setdefault(CLASS_KIND[IDENTITY.match(c).group(1)], set()).add(c)
        return dict({k: sorted(v) for k, v in names.items()}, rule='F-OPERANDS')
    compared = {off for _, _, off in comps}
    groups = {}
    for m in IDENT.finditer(code):
        kinds = token_kinds(m.group(0))
        if not kinds or m.start() in compared:
            continue
        if classify_statement(statement_at(code, m.start(), 0, len(code)))[0] == 'registration':
            continue
        inner = [a for a in arms if a['start'] <= m.start() < a['stop']]
        arm = min(inner, key=lambda a: a['stop'] - a['start'])['start'] if inner else None
        for k in kinds:
            groups.setdefault(arm, {}).setdefault(k, set()).add(m.group(0))
    for found in groups.values():
        if len(found) >= 2:
            return dict({k: sorted(v) for k, v in found.items()}, rule='F-KINDS')
    return None


def foreign_kinds(code, own):
    return {k: sorted(v) for k, v in kinds_of(code).items() if k not in own}


def func_scope(f, path, comp, site_by_func):
    if comp['role'] in ('core', 'family'):
        sites = site_by_func.get((path, f['name']), [])
        pair = [s for s in sites if s['category'] == 'per-pair']
        if pair:
            names = {}
            for s in pair:
                names.setdefault(s['kind'], []).append(s['token'])
            return 'per-pair', {k: sorted(set(v)) for k, v in names.items()}
        pair = function_pair(f)
        if pair:
            return 'per-pair', pair
        found = foreign_kinds(f['header'] + f['body'], ())
        return ('per-class' if found else 'shared'), found
    foreign = foreign_kinds(f['header'] + f['body'], set(comp['own']))
    return ('per-pair' if foreign else 'per-class'), foreign


def bpf_tags(tree, path, maps):
    """({function: kinds of the attached struct_ops maps that reach it},
    [listed maps that are not struct_ops maps of the file]) in a BPF file."""
    p = tree.parsed(path)
    names = {f['name']: f for f in p['funcs']}
    tags, found = {}, set()
    for t in p['tables']:
        m = re.search(r'struct\s+xdev_ext_(\w+?)_mech_ops\b', t['type'] or '')
        if not m or t['name'] not in maps:
            continue
        found.add(t['name'])
        todo = [e['ident'] for e in t['entries'] if e['ident'] in names]
        while todo:
            name = todo.pop()
            if m.group(1) in tags.setdefault(name, set()):
                continue
            tags[name].add(m.group(1))
            todo.extend(tok for tok in tokens(names[name]['body']) if tok in names)
    return tags, sorted(set(maps) - found)


def class_ids(tree):
    """{value: class name} from the UAPI enums (binding backend values first)."""
    values = {}
    for path in ('src/core/include/uapi/linux/xdev_ext_binding.h',
                 'src/core/include/uapi/linux/xdev_ext_mech.h'):
        if path not in tree.files:
            continue
        code, _ = strip_c(tree.files[path])
        for body in re.findall(r'\benum\s+\w*\s*\{([^}]*)\}', code):
            nxt = 0
            for part in body.split(','):
                m = re.match(r'\s*([A-Za-z_]\w*)\s*(?:=\s*(.+?))?\s*$', part, re.S)
                if not m:
                    continue
                if m.group(2):
                    v = m.group(2).strip()
                    if v in values:
                        nxt = values[v]
                    else:
                        try:
                            nxt = int(v, 0)
                        except ValueError:
                            continue
                values[m.group(1)] = nxt
                nxt += 1
    return {values['XDEV_EXT_MECH_CLASS_' + n]: n for n in CLASS_NAMES
            if 'XDEV_EXT_MECH_CLASS_' + n in values}


def class_table(tree):
    path = 'src/core/include/linux/xdev_ext_family_core.h'
    if path not in tree.files:
        return []
    ids, out = class_ids(tree), []
    for t in tree.parsed(path)['tables']:
        if t['name'] != 'xdev_ext_mech_class_decls':
            continue
        for row in t['rows']:
            cls = ids.get(row['index'])
            if not cls or not row['entries']:
                continue
            foreign = foreign_kinds(row['text'], {CLASS_KIND[cls]})
            out.append(dict(cls=cls, line=row['line'], fields=len(row['entries']),
                            scope='per-pair' if foreign else 'per-class', names=foreign))
    return out


RULES = {
    'per-class': "names no device kind other than its own component's",
    'per-pair': 'names a second device kind; in BPF also: shared by the programs of two classes',
    'shared': 'core or family item that names no device kind',
    'R-SCOPE': 'outside any function body -> registration',
    'R-PP': 'in a preprocessor line -> registration',
    'R-REGCALL': 'statement calls a registration function -> registration',
    'R-PAIR': 'two identities against two operands, or two kinds without comparison -> per-pair',
    'R-SET': 'several identities against one operand -> per-class dispatch',
    'R-ONE': 'statement names one device kind -> per-class dispatch',
    'F-OPERANDS': 'core/family function compares identities against two different operands '
                  'anywhere in its body (case labels against the switch subject) -> per-pair',
    'F-KINDS': 'core/family function names two device kinds outside the arms of a single-operand '
               'switch, or within one arm (identities in comparisons and registration statements '
               'excluded) -> per-pair',
}


def analyze(tree, components=None, chains=None):
    components = COMPONENTS if components is None else components
    chains = CHAINS if chains is None else chains
    comp_files = {}
    for path in sorted(tree.files):
        if path.endswith('.bpf.c') or not path.endswith(('.c', '.h', '.inc')):
            continue
        c = component_of(path, components)
        if c:
            comp_files.setdefault(c, []).append(path)
    sites = []
    family = {p for c, paths in comp_files.items() if components[c]['role'] == 'family' for p in paths}
    for path in sorted(tree.files):
        if (path.startswith('src/core/') and path.endswith(('.c', '.h', '.inc'))) or path in family:
            sites.extend(decision_sites(tree, path))
    site_by_func = {}
    for s in sites:
        site_by_func.setdefault((s['file'], s['context']), []).append(s)
    defs, tables = {}, {}
    for comp, paths in comp_files.items():
        for path in paths:
            for f, status in countable_functions(tree, path):
                defs.setdefault(f['name'], []).append((comp, path, f, status))
            for t in tree.parsed(path)['tables']:
                if t['name']:
                    tables.setdefault(t['name'], []).append((comp, path, t))
    rows = class_table(tree)
    results = [chain_items(tree, ch, components, comp_files, defs, tables, site_by_func, rows)
               for ch in chains]
    inventory = {}
    for comp, paths in sorted(comp_files.items()):
        listed = []
        for path in paths:
            for f, _ in countable_functions(tree, path):
                scope, names = func_scope(f, path, components[comp], site_by_func)
                listed.append((scope, f['name'], path, f['line'], names))
        inventory[comp] = dict(functions=len(listed),
                               per_class=sum(1 for r in listed if r[0] == 'per-class'),
                               shared=sum(1 for r in listed if r[0] == 'shared'),
                               per_pair=[dict(name=r[1], file=r[2], line=r[3], names=r[4])
                                         for r in listed if r[0] == 'per-pair'])
    primary = [s for s in sites if s['identity']]
    cats = ('registration', 'per-class', 'per-pair')
    summary = dict(identity_sites=len(primary),
                   identity_by_category={k: sum(1 for s in primary if s['category'] == k) for k in cats},
                   identifier_sites=len(sites) - len(primary),
                   identifier_by_category={k: sum(1 for s in sites if not s['identity']
                                                  and s['category'] == k) for k in cats})
    return dict(schema=SCHEMA, source_commit=tree.revision, rules=RULES, chains=results,
                core_decisions=dict(summary=summary, sites=sites), class_table=rows,
                inventory=inventory)


def chain_items(tree, chain, components, comp_files, defs, tables, site_by_func, class_rows):
    in_chain = set(chain['components'])
    errors = ['unknown component ' + c for c in chain['components'] if c not in components]

    def resolve(name, near):
        cands = [d for d in defs.get(name, ()) if d[0] in in_chain]
        local = [d for d in cands if d[1] == near]
        return local or [d for d in cands if not d[2]['static']] or cands

    reached, hooks, seen_tables, todo = {}, {}, set(), []

    def add_table(comp, path, t, reach):
        if (path, t['name']) in seen_tables:
            return
        seen_tables.add((path, t['name']))
        for e, status in countable_entries(tree, path, t):
            targets = resolve(e['ident'], path) if e['ident'] else []
            if targets:
                hooks[(path, t['name'], e['member'])] = dict(
                    component=comp, table=t['name'], member=e['member'], value=e['ident'],
                    file=path, line=e['line'], status=status, reach=reach)
                todo.extend(d + ('callee',) for d in targets)

    for comp in sorted(in_chain):
        spec = components.get(comp, {})
        for path in comp_files.get(comp, ()):
            for t in tree.parsed(path)['tables']:
                if t['name'] and t['entries'] and (
                        'root_tables' not in spec or t['name'] in spec['root_tables']):
                    add_table(comp, path, t, 'root')
            if spec.get('root_all_changed') and tree.upstream.get(path) is not None:
                todo.extend((comp, path, f, st, 'root') for f, st in countable_functions(tree, path))

    while todo:
        comp, path, f, status, reach = todo.pop()
        key = (path, f['name'], f['line'])
        if key in reached:
            continue
        reached[key] = (comp, f, status, reach)
        for tok in sorted(set(tokens(f['header'] + f['body']))):
            todo.extend(d + ('callee',) for d in resolve(tok, path))
            for tcomp, tpath, t in tables.get(tok, ()):
                if tcomp in in_chain and t['entries']:
                    add_table(tcomp, tpath, t, 'callee')
    # Callers: an upstream function the product changed that calls reached
    # code, or any product function that refers to a reached table, is the
    # site where the chain is entered.  It is counted, but its other callees
    # (other arms of a dispatcher) are not followed.
    funcs = {k[1] for k in reached}
    tabs = {k[1] for k in seen_tables}
    for comp in sorted(in_chain):
        for path in comp_files.get(comp, ()):
            upstream_file = tree.upstream.get(path) is not None
            for f, st in countable_functions(tree, path):
                key = (path, f['name'], f['line'])
                if key in reached:
                    continue
                toks = set(tokens(f['body']))
                if (upstream_file and st == 'changed' and toks & funcs) or toks & tabs:
                    reached[key] = (comp, f, st, 'caller')

    items = []
    commands = chain.get('commands')
    for (path, name, line), (comp, f, status, reach) in sorted(reached.items()):
        spec = components[comp]
        arms = added_arms(tree, path, f, status) if spec['role'] not in ('core', 'family') else []
        extra = {}
        if arms:
            # A stock dispatcher the product extended: judge the arms the chain
            # is shown to execute, plus the rest of the changed function.
            body = f['body']
            for a in arms:
                body = body.replace(a['text'], ' ')
            used = [a for a in arms if commands is None or a['label'] in commands]
            unused = [a for a in arms if a not in used]
            code = f['header'] + body + ' '.join(a['text'] for a in used)
            names = foreign_kinds(code, set(spec['own']))
            scope = 'per-pair' if names else 'per-class'

            def arm(a):
                n = foreign_kinds(a['text'], set(spec['own']))
                return dict(label=a['label'], scope='per-pair' if n else 'per-class', names=n)
            extra = dict(arms_executed=[arm(a) for a in used],
                         arms_not_executed=[arm(a) for a in unused])
        else:
            scope, names = func_scope(f, path, spec, site_by_func)
        items.append(dict(kind='function', component=comp, role=spec['role'],
                          trust='kernel', name=name, file=path, line=line, status=status,
                          reach=reach, scope=scope, names=names, **extra))
    by_key = {(i['file'], i['name']): i for i in items}
    for key in sorted(hooks):
        h = hooks[key]
        c = components[h['component']]
        target = by_key.get((h['file'], h['value'])) or next(
            (i for i in items if i['name'] == h['value']), None)
        names = foreign_kinds('%s %s' % (h['member'], h['value']), set(c['own']))
        scope = ('shared' if not names else 'per-class') if c['role'] in ('core', 'family') else (
            'per-pair' if names else 'per-class')
        if target and target['scope'] == 'per-pair':
            scope, names = 'per-pair', target['names']
        items.append(dict(kind='hook', component=h['component'], role=c['role'], trust='kernel',
                          name='%s.%s = %s' % (h['table'], h['member'], h['value']),
                          file=h['file'], line=h['line'], status=h['status'], reach=h['reach'],
                          scope=scope, names=names))
    for row in class_rows:
        if row['cls'] in chain['classes']:
            items.append(dict(kind='class-table', component='core', role='core', trust='kernel',
                              name='xdev_ext_mech_class_decls[%s] (%d fields)' % (row['cls'], row['fields']),
                              file='src/core/include/linux/xdev_ext_family_core.h', line=row['line'],
                              status='new-file', reach='root', scope=row['scope'],
                              names=row['names']))
    programs = []
    for spec in chain['bpf']:
        if isinstance(spec, str):
            errors.append('BPF program %s names no struct_ops map the chain attaches' % spec)
            continue
        path, maps = spec[0], sorted(spec[1])
        programs.append(dict(file=path, maps=maps))
        if path not in tree.files:
            errors.append('missing BPF program ' + path)
            continue
        p = tree.parsed(path)
        funcs = {f['name']: f for f in p['funcs']}
        entries = {e['ident'] for t in p['tables'] if t['name'] in maps for e in t['entries']}
        tags, unknown = bpf_tags(tree, path, maps)
        errors.extend('%s has no struct_ops map %s' % (path, m) for m in unknown)
        for name, tags in sorted(tags.items()):
            f, classes = funcs[name], sorted(tags)
            names = foreign_kinds(f['header'] + f['body'], set(classes))
            scope = 'per-pair' if names else 'per-class'
            if len(classes) > 1:
                scope, names = 'per-pair', dict(names, shared_by=classes)
            items.append(dict(kind='bpf-callback' if name in entries else 'bpf-helper',
                              component='bpf:' + path, role='bpf', trust='bpf', name=name,
                              file=path, line=f['line'], status='new-file',
                              reach='root' if name in entries else 'callee', scope=scope,
                              names=names, classes=classes))
    evidence = []
    for path, literal in chain['evidence']:
        text = tree.files.get(path)
        idx = -1 if text is None else text.find(literal)
        if idx < 0:
            errors.append('evidence missing in %s: %s' % (path, literal))
        else:
            evidence.append(dict(file=path, line=text.count('\n', 0, idx) + 1, text=literal))
    for path in chain['absent']:
        if any(p == path or p.startswith(path.rstrip('/') + '/') for p in tree.files):
            errors.append('catalog says absent but present: ' + path)
    items.sort(key=lambda i: (i['component'], i['kind'], i['file'], i['line'], i['name']))
    by_comp = {}
    for i in items:
        row = by_comp.setdefault(i['component'], {'role': i['role'], 'trust': i['trust'],
                                                  'functions': 0, 'hooks': 0, 'class_table': 0,
                                                  'bpf': 0, 'per-class': 0, 'per-pair': 0,
                                                  'shared': 0})
        row[{'function': 'functions', 'hook': 'hooks', 'class-table': 'class_table'}.get(i['kind'], 'bpf')] += 1
        row[i['scope']] += 1
    count = lambda pred: sum(1 for i in items if pred(i))  # noqa: E731
    return dict(id=chain['id'], title=chain['title'], sessions=chain['sessions'],
                classes=chain['classes'], components=chain['components'],
                bpf_programs=programs, evidence=evidence, missing=chain['missing'],
                errors=errors,
                totals=dict(items=len(items), trusted=count(lambda i: i['trust'] == 'kernel'),
                            bpf=count(lambda i: i['trust'] == 'bpf'),
                            per_class=count(lambda i: i['scope'] == 'per-class'),
                            shared=count(lambda i: i['scope'] == 'shared'),
                            per_pair_trusted=count(lambda i: i['scope'] == 'per-pair' and i['trust'] == 'kernel'),
                            per_pair_bpf=count(lambda i: i['scope'] == 'per-pair' and i['trust'] == 'bpf'),
                            per_pair_trusted_not_executed=sum(
                                1 for i in items for a in i.get('arms_not_executed', ())
                                if a['scope'] == 'per-pair')),
                by_component=by_comp, items=items)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def markdown(result):
    out = ['# T-COMP chain composition', '',
           'Source commit `%s`. Generated by `tools/analysis/chain_composition.py`; a static '
           'count of one tree, not a measurement.' % result['source_commit'], '',
           '| chain | items | trusted | BPF | per-class | shared | per-pair trusted | per-pair BPF |',
           '|---|---|---|---|---|---|---|---|']
    for c in result['chains']:
        t = c['totals']
        out.append('| %s | %d | %d | %d | %d | %d | %d | %d |' % (
            c['id'], t['items'], t['trusted'], t['bpf'], t['per_class'], t['shared'],
            t['per_pair_trusted'], t['per_pair_bpf']))
    for c in result['chains']:
        out += ['', '## %s: %s' % (c['id'], c['title']), '']
        out += ['- %s, pool %s: %s' % (s['side'], s['pool'], ' -> '.join(s['stages']))
                for s in c['sessions']]
        out += ['', '| component | trust | functions | hooks | class table | BPF | per-class | shared | per-pair |',
                '|---|---|---|---|---|---|---|---|---|']
        for comp, r in sorted(c['by_component'].items()):
            out.append('| %s | %s | %d | %d | %d | %d | %d | %d | %d |' % (
                comp, r['trust'], r['functions'], r['hooks'], r['class_table'], r['bpf'],
                r['per-class'], r['shared'], r['per-pair']))
        pairs = [i for i in c['items'] if i['scope'] == 'per-pair']
        if pairs:
            out += ['', 'Per-pair items:', '']
            out += ['- %s %s `%s` %s:%d names %s' % (i['trust'], i['component'], i['name'], i['file'],
                                                    i['line'], json.dumps(i['names'], sort_keys=True))
                    for i in pairs]
        if c['missing'] or c['errors']:
            out.append('')
        out += ['- not counted: ' + m for m in c['missing']]
        out += ['- ERROR: ' + e for e in c['errors']]
    s = result['core_decisions']['summary']
    out += ['', '## Named class constants under src/core and family code', '',
            'Identity constants `XDEV_EXT_MECH_CLASS_<NAME>`: %d sites, %s.' % (
                s['identity_sites'], json.dumps(s['identity_by_category'], sort_keys=True)),
            'Class-specific identifiers: %d sites, %s.' % (
                s['identifier_sites'], json.dumps(s['identifier_by_category'], sort_keys=True)), '',
            '| file:line | token | context | category | rule |', '|---|---|---|---|---|']
    out += ['| %s:%d | %s | %s | %s | %s |' % (x['file'], x['line'], x['token'], x['context'],
                                               x['category'], x['rule'])
            for x in result['core_decisions']['sites'] if x['identity']]
    return '\n'.join(out) + '\n'


def wanted(path):
    if path.startswith(('src/core/', 'src/network/', 'src/storage/', 'src/compute/')) and \
            path.endswith(('.c', '.h', '.inc')):
        return True
    if path.endswith('.bpf.c'):
        return True
    return any(path == e[0] for c in CHAINS for e in c['evidence']) or any(
        path.startswith(a) for c in CHAINS for a in c['absent'])


def main(argv=None):
    ap = argparse.ArgumentParser(description='T-COMP per-chain composition count')
    ap.add_argument('--repo', default=str(Path(__file__).resolve().parents[2]))
    ap.add_argument('--revision', default='HEAD')
    ap.add_argument('--worktree', action='store_true')
    ap.add_argument('--upstream-git', action='append', default=[], metavar='COMPONENT=GITDIR')
    ap.add_argument('--json', dest='json_out')
    ap.add_argument('--markdown')
    args = ap.parse_args(argv)
    ups = {}
    for spec in args.upstream_git:
        if '=' not in spec:
            ap.error('--upstream-git takes COMPONENT=GITDIR')
        k, v = spec.split('=', 1)
        ups[k] = v
    try:
        result = analyze(load_tree(args.repo, args.revision, args.worktree, ups, wanted))
    except InputError as e:
        print('chain_composition: %s' % e, file=sys.stderr)
        return 2
    text = json.dumps(result, indent=1, sort_keys=True) + '\n'
    if args.json_out:
        Path(args.json_out).write_text(text)
    else:
        sys.stdout.write(text)
    if args.markdown:
        Path(args.markdown).write_text(markdown(result))
    return 1 if any(c['errors'] or c['totals']['per_pair_trusted'] for c in result['chains']) else 0


if __name__ == '__main__':
    sys.exit(main())
