#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile and run cases.c: DMA-stop evidence of retained host-page NVMe slots.

One translation unit of actual sources: the peer region core and requester
epoch records (src/core/io_uring/xdev_ext_peer.c, host-test mode), the
allocation-fd lease releases, the storage-family slot pool and completion
handoff (xdev_ext_storfam.c), the block family's host slots and evidence
(xdev_ext_storfam_block.c), the NVMe mechanism member's posting, end_io and
completion classification (xdev_ext_mech_nvme.c) and the nvme-pci reset proof
and SQ-preparation record (pci.c). The test plays blk-mq and the controller:
blk_execute_rq_nowait() dispatches through the actual SQ-preparation record
unless a case holds the request back, and the case completes each request
with the status and residual it chooses. UBSan and ASan. Exit 0 PASS,
1 FAIL, 2 SETUP (extraction or compile error, never a behavioural verdict).
No device, DMA, IOMMU or timing.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
PEER = 'src/core/io_uring/xdev_ext_peer.c'
PEER_FD = 'src/core/io_uring/xdev_ext_peer_fd.c'
PEER_H = 'src/core/include/linux/xdev_ext_peer.h'
REQUESTER_H = 'src/core/include/linux/xdev_ext_requester.h'
REQUESTER_CORE_H = 'src/core/include/linux/xdev_ext_requester_core.h'
STORFAM = 'src/storage/io_uring/family/xdev_ext_storfam.c'
STORFAM_BLOCK = 'src/storage/io_uring/family/xdev_ext_storfam_block.c'
STORFAM_BLOCK_H = 'src/storage/include/linux/xdev_ext_storfam_block.h'
STORFAM_CORE_H = 'src/storage/include/linux/xdev_ext_storfam_core.h'
STORFAM_RUNTIME_H = 'src/storage/include/linux/xdev_ext_storfam_runtime.h'
MECH_NVME = 'src/storage/drivers/nvme/host/xdev_ext_mech_nvme.c'
PCI = 'src/storage/drivers/nvme/host/pci.c'
NVME_H = 'src/storage/drivers/nvme/host/nvme.h'
TRACE_H = 'src/storage/drivers/nvme/host/xdev_ext_native_peer_trace.h'
PASSTHRU_H = 'src/storage/include/linux/nvme_xdev_ext_passthru.h'
UAPI_MECH = 'src/core/include/uapi/linux/xdev_ext_mech.h'
SHIM = 'tests/network/peer/session/xdev_ext_peer_test_shim.h'
INPUTS = (PEER, PEER_FD, PEER_H, REQUESTER_H, REQUESTER_CORE_H, STORFAM, STORFAM_BLOCK,
          STORFAM_BLOCK_H, STORFAM_CORE_H, STORFAM_RUNTIME_H, MECH_NVME, PCI, NVME_H, TRACE_H,
          PASSTHRU_H, UAPI_MECH, SHIM)
PROFILES = (
    ('ubsan', ['-O2', '-fsanitize=undefined', '-fno-sanitize-recover=undefined']),
    ('asan', ['-O1', '-g', '-fsanitize=address', '-fno-omit-frame-pointer']),
)


class Setup(Exception):
    pass


def braced_from(text, start):
    """text[start:] through the brace that closes the first '{' after start."""
    i = text.index('{', start) + 1
    depth = 1
    while depth and i < len(text):
        depth += (text[i] == '{') - (text[i] == '}')
        i += 1
    if depth:
        raise Setup('unbalanced actual source block at %d' % start)
    return text[start:i]


def function(text, name, optional=False):
    """The definition of NAME at a line start, with a return type line above it."""
    match = re.search(r'^(?:[A-Za-z_][^\n;{}()]*[\s*])?' + re.escape(name) + r'\(([^;{}]|\n)*?\)\s*\{',
                      text, re.M)
    if not match:
        if optional:
            return ''
        raise Setup('missing actual definition: ' + name)
    start = match.start()
    if match.group(0).startswith(name):
        above = text.rfind('\n', 0, start - 1) + 1
        line = text[above:start - 1]
        if line and not line.rstrip().endswith((';', '}', '{', '*/')) and not line.startswith('#'):
            start = above
    return braced_from(text, start) + '\n'


def structure(text, name):
    match = re.search(r'^struct ' + re.escape(name) + r' \{', text, re.M)
    if not match:
        raise Setup('missing actual structure: ' + name)
    body = braced_from(text, match.start())
    return body + ';\n'


def enum(text, name):
    match = re.search(r'^enum ' + re.escape(name) + r' \{', text, re.M)
    if not match:
        raise Setup('missing actual enum: ' + name)
    return braced_from(text, match.start()) + ';\n'


def flag(text, name, optional=False):
    match = re.search(r'\b' + re.escape(name) + r'\s*=\s*([^,]+),', text)
    if not match:
        if optional:
            return None
        raise Setup('missing actual flag: ' + name)
    return match.group(1).strip()


def initializer_field(text, ops, field):
    """The expression the actual OPS initializer gives FIELD, or None."""
    match = re.search(r'^static const struct xdev_ext_stor_dev_ops ' + re.escape(ops) + r' = \{', text, re.M)
    if not match:
        raise Setup('missing actual initializer: ' + ops)
    body = braced_from(text, match.start())
    found = re.search(r'\.' + re.escape(field) + r'\s*=\s*', body)
    if not found:
        return None
    i, depth = found.end(), 0
    while depth or body[i] not in ',}':
        depth += (body[i] == '(') - (body[i] == ')')
        i += 1
    return ' '.join(body[found.end():i].split())


def mech_ifdef_body(text, needle):
    """The #ifdef CONFIG_XDEV_EXT_MECH branch of TEXT holding NEEDLE, up to its #else."""
    pos = text.index(needle)
    begin = text.rindex('#ifdef CONFIG_XDEV_EXT_MECH\n', 0, pos) + len('#ifdef CONFIG_XDEV_EXT_MECH\n')
    end = text.index('\n#else', pos)
    return text[begin:end] + '\n'


def assemble(root):
    root = Path(root)
    read = lambda rel: (root / rel).read_text()
    peer, fd, block, nvme, pci = read(PEER), read(PEER_FD), read(STORFAM_BLOCK), read(MECH_NVME), read(PCI)
    storfam, block_h, nvme_h = read(STORFAM), read(STORFAM_BLOCK_H), read(NVME_H)
    shim = read(SHIM)
    plain_file = 'struct file { const struct file_operations *f_op; int refs; };'
    if shim.count(plain_file) != 1:
        raise Setup('shim struct file anchor')
    shim = shim.replace(plain_file, 'struct file { const struct file_operations *f_op; int refs; '
                        'void *private_data; };')
    # Kernel u64 is the same type as __u64; the storage headers mix both.
    if shim.count('typedef uint64_t u64;') != 1:
        raise Setup('shim u64 anchor')
    shim = shim.replace('typedef uint64_t u64;', 'typedef unsigned long long u64;')
    relative = '#include "../include/linux/xdev_ext_peer.h"'
    if peer.count(relative) != 1:
        raise Setup('peer core host-test include anchor')
    peer = peer.replace(relative, '#include "' + str(root / PEER_H) + '"')
    flags = {n: flag(nvme_h, n) for n in ('NVME_REQ_CANCELLED', 'NVME_REQ_USERCMD',
                                          'NVME_REQ_XDEV_EXT_ZC', 'NVME_REQ_XDEV_EXT_PEER')}
    epoch_flag = flag(nvme_h, 'NVME_REQ_XDEV_EXT_EPOCH', optional=True)
    if epoch_flag:
        flags['NVME_REQ_XDEV_EXT_EPOCH'] = epoch_flag
    trace = re.sub(r'^#include[^\n]*\n', '', read(TRACE_H), flags=re.M)
    requester = read(REQUESTER_H)
    ops_fields = {f: initializer_field(nvme, 'nvme_xdev_ext_member_ops', f)
                  for f in ('peer_evidence', 'peer_slot_bytes', 'peer_native_offset', 'host_native_bytes')}
    if not ops_fields['peer_evidence']:
        raise Setup('the NVMe member reports no peer_evidence')
    ops = ''.join('\t.%s = %s,\n' % (f, e) for f, e in ops_fields.items() if e)
    pieces = [
        '#include <assert.h>\n#include <stdio.h>\n#include <string.h>\n',
        shim,
        (HERE / 'shim.h').read_text(),
        ''.join('#define %s %s\n' % kv for kv in flags.items()),
        '#define XDEV_EXT_PEER_HOST_TEST\n', peer, '\n',
        'struct xdev_ext_peer_authority;\n',
        structure(fd, 'xdev_ext_peer_fd'),
        function(fd, 'xdev_ext_peer_fd_release'),
        function(fd, 'xdev_ext_peer_fd_release_unknown'),
        '#include "' + str(root / STORFAM_CORE_H) + '"\n',
        '#include "' + str(root / STORFAM_RUNTIME_H) + '"\n',
        '#include "' + str(root / REQUESTER_CORE_H) + '"\n',
        structure(requester, 'xdev_ext_requester'),
        ''.join(function(storfam, n) for n in (
            'xdev_ext_stor_leases_retire', 'xdev_ext_stor_leases_retire_unknown',
            'xdev_ext_stor_slot_add', 'xdev_ext_stor_slot_get', 'xdev_ext_stor_slot_put',
            'xdev_ext_stor_done')),
        enum(block_h, 'xdev_ext_stor_host_path'),
        ''.join(structure(block_h, n) for n in (
            'xdev_ext_stor_command', 'xdev_ext_stor_geometry', 'xdev_ext_stor_poll_view',
            'xdev_ext_stor_dev_ops', 'xdev_ext_stor_io', 'xdev_ext_stor_peer_io',
            'xdev_ext_stor_stage', 'xdev_ext_stor_batch')),
        structure(block, 'xdev_ext_stor_peer_resources'),
        ''.join(function(block, n) for n in (
            'xdev_ext_storfam_host_resources_free', 'xdev_ext_storfam_host_resources_init',
            'xdev_ext_storfam_host_get', 'xdev_ext_storfam_host_put', 'xdev_ext_storfam_peer_io',
            'xdev_ext_storfam_peer_evidence', 'xdev_ext_storfam_evidence',
            'xdev_ext_storfam_evidence_release', 'xdev_ext_storfam_host_ready')),
        trace,
        function(read(PASSTHRU_H), 'nvme_xdev_ext_mech_cqe'),
        ''.join(structure(nvme, n) for n in (
            'nvme_xdev_ext_mech_stage', 'nvme_xdev_ext_mech_batch', 'nvme_xdev_ext_peer_slot')),
        mech_ifdef_body(pci, 'static u64 nvme_pci_peer_quiesce_begin('),
        ''.join(function(nvme, n) for n in (
            'nvme_xdev_ext_class_complete', 'nvme_xdev_ext_class_end_io',
            'nvme_xdev_ext_peer_complete', 'nvme_xdev_ext_peer_end_io',
            'nvme_xdev_ext_member_post', 'nvme_xdev_ext_member_peer_evidence')),
        'static const struct xdev_ext_stor_dev_ops actual_member_ops = {\n' + ops + '};\n',
        (HERE / 'cases.c').read_text(),
    ]
    return ''.join(pieces)


def run_unit(source, directory, name='evidence'):
    """Returns (verdict, log, checks) over every sanitizer profile."""
    path = Path(directory) / (name + '.c')
    path.write_text(source)
    log, checks = [], None
    for profile, profile_flags in PROFILES:
        binary = Path(directory) / (name + '-' + profile)
        command = ['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                   '-Wno-unused-parameter', '-Wno-sign-compare', '-Wno-missing-field-initializers',
                   '-pthread', *profile_flags, str(path), '-o', str(binary)]
        built = subprocess.run(command, capture_output=True, text=True)
        log.append('$ ' + ' '.join(command) + '\n' + built.stdout + built.stderr)
        if built.returncode:
            return 'SETUP', '\n'.join(log), checks
        env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:abort_on_error=0',
                   UBSAN_OPTIONS='print_stacktrace=1:halt_on_error=1')
        try:
            result = subprocess.run([str(binary)], capture_output=True, text=True, env=env, timeout=60)
        except subprocess.TimeoutExpired as expired:
            log.append('# profile %s timed out after 60 s\n%s' % (profile, expired.stdout or ''))
            return 'FAIL', '\n'.join(log), checks
        log.append('# profile ' + profile + ' exit ' + str(result.returncode) + '\n' +
                   result.stdout + result.stderr)
        plan = re.findall(r'^1\.\.(\d+)$', result.stdout, re.M)
        oks = len(re.findall(r'^ok \d+ ', result.stdout, re.M))
        if result.returncode or 'not ok' in result.stdout or len(plan) != 1 or int(plan[0]) != oks:
            return 'FAIL', '\n'.join(log), checks
        checks = oks
    return 'PASS', '\n'.join(log), checks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', type=Path, default=HERE.parents[2])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    root = args.source_root.resolve()
    record = {'scope': 'host software state machine only; no device, DMA, IOMMU or timing'}
    try:
        record['inputs'] = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in INPUTS}
        for local in ('cases.c', 'shim.h'):
            record['inputs']['tests/storage/family_block_evidence/' + local] = hashlib.sha256(
                (HERE / local).read_bytes()).hexdigest()
        source = assemble(root)
    except (Setup, OSError, ValueError) as error:
        print('SETUP family-block-evidence ' + str(error))
        return 2
    with tempfile.TemporaryDirectory(prefix='family-block-evidence-') as directory:
        verdict, log, checks = run_unit(source, directory)
    print(log)
    record.update(verdict=verdict, checks=checks, profiles=[p for p, _ in PROFILES])
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / 'output.log').write_text(log)
        (args.output / 'unit.c').write_text(source)
        (args.output / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')
    print('%s family-block-evidence checks=%s profiles=%d' % (verdict, checks, len(PROFILES)))
    return {'PASS': 0, 'FAIL': 1}.get(verdict, 2)


if __name__ == '__main__':
    sys.exit(main())
