#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Lines of code per device provider class.

    loc_report.py [--repo DIR] [--upstream-git COMPONENT=GITDIR ...]
                  [--worktree] [--json]

Counts the files Git tracks, at HEAD unless --worktree.  A class has its own
files, counted whole (code, comment, blank lines), and hook files: upstream
files the class modifies, of which only the lines differing from the pinned
upstream commit in sources.lock.json count.  The upstream base is read from
build/upstream/<component>.git (the source-preparation cache) or from
--upstream-git; when that commit is not present the hook is listed with
added=None rather than estimated.  Own files and hooks that no class names
are listed as unclassified, and catalog entries that match no tracked file
as missing, so the catalog cannot silently drift from the tree.

The catalog below is maintained by hand.  "core" is the shared session
contract every provider uses, not a provider; "shared_hooks" are upstream
changes not specific to one device; NOT_PROVIDER files are excluded.  Exit status: 0, or 1 when a catalog
entry is missing.
"""
import argparse
import difflib
import fnmatch
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
K = 'kernel/'
IO = K + 'io_uring/'
NV = 'gpu/kernel-open/nvidia/'
RM = 'gpu/src/nvidia/'

CATALOG = {
    'core': dict(own=[IO + 'xdev_ext_mech.c', IO + 'xdev_ext_mech_core.h',
                      IO + 'xdev_ext_mech_internal.h', IO + 'xdev_ext_mech_lifecycle.h',
                      IO + 'xdev_ext_mech_step.h', IO + 'xdev_ext_mech_window.h',
                      IO + 'xdev_ext_mech_notify.h', IO + 'xdev_ext_mech_native_cookie.h',
                      IO + 'xdev_ext_mech_ops.c', IO + 'xdev_ext_mech_peer_pool.c',
                      IO + 'xdev_ext_binding.c', IO + 'xdev_ext_ops_core.[ch]',
                      IO + 'xdev_ext_umem.[ch]', IO + 'xdev_ext_config.h',
                      IO + 'xdev_ext_peer.c', IO + 'xdev_ext_peer_fd.c',
                      K + 'include/linux/xdev_ext_mech.h', K + 'include/linux/xdev_ext_binding.h',
                      K + 'include/linux/xdev_ext_peer.h',
                      K + 'include/uapi/linux/xdev_ext_mech.h',
                      K + 'include/uapi/linux/xdev_ext_binding.h',
                      K + 'include/uapi/linux/xdev_ext_peer.h', K + 'xdev_ext_frame_sm.h'],
                 hooks=[]),
    'nvme': dict(own=[K + 'drivers/nvme/host/xdev_ext_mech_nvme.c',
                      K + 'drivers/nvme/host/xdev_ext_peer_nvme_core.h',
                      K + 'include/linux/nvme_xdev_ext_passthru.h'],
                 hooks=[K + 'drivers/nvme/host/' + f for f in (
                     'pci.c', 'core.c', 'ioctl.c', 'nvme.h', 'Makefile', 'apple.c', 'fc.c',
                     'rdma.c', 'tcp.c', 'fabrics.h')] +
                 [K + 'drivers/nvme/target/loop.c', K + 'include/uapi/linux/nvme_ioctl.h']),
    'afxdp': dict(own=[K + 'net/xdp/xsk_xdev_ext_mech*',
                       K + 'include/linux/xdev_ext_mech_reliable_core.h'],
                  hooks=[K + 'net/xdp/xsk.c', K + 'net/xdp/xsk_buff_pool.c',
                         K + 'net/xdp/Kconfig', K + 'net/xdp/Makefile',
                         K + 'include/net/xdp_sock.h', K + 'include/net/xdp_sock_drv.h',
                         K + 'include/net/xsk_buff_pool.h', K + 'include/uapi/linux/if_xdp.h',
                         K + 'include/linux/netdevice.h']),
    'afxdp_policy': dict(own=[K + 'net/xdp/xsk_xdev_ext.[ch]',
                              K + 'net/xdp/xsk_xdev_ext_core.h',
                              K + 'net/xdp/xsk_xdev_ext_rx_core.h'], hooks=[]),
    'nic_mlx5': dict(own=[], hooks=[K + 'drivers/net/ethernet/mellanox/mlx5/core/' + f for f in (
        'en.h', 'en_main.c', 'en_tx.c', 'en/txrx.h', 'en/xsk/tx.c')]),
    'nic_other_drivers': dict(own=[], hooks=[
        K + 'drivers/net/ethernet/freescale/dpaa2/dpaa2-eth.c',
        K + 'drivers/net/ethernet/freescale/dpaa2/dpaa2-xsk.c',
        K + 'drivers/net/ethernet/google/gve/gve_tx.c',
        K + 'drivers/net/ethernet/netronome/nfp/nfd3/rings.c',
        K + 'drivers/net/ethernet/stmicro/stmmac/stmmac_main.c',
        K + 'drivers/net/virtio_net.c']),
    'ce': dict(own=[IO + 'xdev_ext_mech_ce.c', IO + 'xdev_ext_mech_ce_core.h',
                    IO + 'xdev_ext_mech_ce_lease.h', NV + 'nv-xdev_ext-ce-*',
                    NV + 'nv-xdev_ext-dma-lifetime.h', NV + 'nv-xdev_ext-gpu*.h',
                    NV + 'nv-xdev_ext-umem-quota.h'],
               hooks=[NV + 'nv.c', NV + 'nvidia.Kbuild', NV + 'nv-reg.h',
                      'gpu/kernel-open/common/inc/nv-linux.h',
                      'gpu/kernel-open/common/inc/nv.h',
                      'gpu/kernel-open/common/inc/nv-ioctl.h',
                      'gpu/kernel-open/common/inc/nv-ioctl-numbers.h',
                      'gpu/kernel-open/common/inc/nvstatuscodes.h',
                      RM + 'arch/nvalloc/unix/src/osapi.c', RM + 'exports_link_command.txt',
                      RM + 'srcs.mk', RM + 'generated/g_ce_utils_nvoc.h',
                      RM + 'generated/g_mem_mgr_nvoc.h',
                      RM + 'src/kernel/gpu/ce/kernel_ce_shared.c', RM + 'src/kernel/gpu/gpu.c',
                      RM + 'src/kernel/gpu/mem_mgr/ce_utils.c',
                      RM + 'src/kernel/gpu/mem_mgr/channel_utils.c',
                      RM + 'src/kernel/gpu/mem_mgr/mem_utils.c']),
    'gpu_peer': dict(own=[NV + 'nv-xdev_ext-peer.[ch]', NV + 'nv-p2p-gpu-identity.h',
                          RM + 'inc/kernel/mem_mgr/p2p_umem_*.h',
                          RM + 'src/kernel/mem_mgr/p2p_umem.c'],
                     hooks=[NV + 'nv-p2p.c', NV + 'nv-p2p.h', RM + 'inc/kernel/mem_mgr/p2p.h',
                            RM + 'src/kernel/gpu/bus/p2p.c']),
    'dma': dict(own=[IO + 'xdev_ext_mech_dma.c', IO + 'xdev_ext_mech_dma_core.h'], hooks=[]),
    'net_peer': dict(own=[IO + 'xdev_ext_mech_net.c', IO + 'xdev_ext_mech_net_core.h',
                          IO + 'xdev_ext_peer_net.c', IO + 'xdev_ext_peer_net_core.h'],
                     hooks=[]),
    'socket': dict(own=[IO + 'xdev_ext_mech_socket.c', IO + 'xdev_ext_send_hook.h'], hooks=[]),
    'iaa': dict(own=[IO + 'iaa/*.[ch]', IO + 'iaa/Makefile'], hooks=[]),
    'shared_hooks': dict(own=[], hooks=[
        IO + 'io_uring.c', IO + 'register.c', IO + 'opdef.c', IO + 'Kconfig', IO + 'Makefile',
        IO + 'unified_ops*', IO + 'sched_hints.[ch]', K + 'include/linux/io_uring_types.h',
        K + 'include/uapi/linux/io_uring.h', K + 'include/uapi/linux/stat.h',
        K + 'arch/x86/entry/syscalls/syscall_64.tbl', K + 'block/*.c',
        K + 'include/linux/bio.h', K + 'include/linux/blk-mq.h',
        K + 'include/linux/blk_types.h', K + 'include/linux/dma-mapping.h',
        K + 'kernel/dma/mapping.c']),
}

# Tracked kernel-tree files outside the session/provider design: the frame
# state-machine benchmarks and the earlier NVMe-XDP pipeline module.
NOT_PROVIDER = ('kernel/Makefile.pipeline', 'kernel/nvme_xdp_pipeline*',
                'kernel/xdev_ext_sm_*', 'kernel/xdev_ext_sm_fence_bench/*',
                'kernel/xdp_sock_kern.c')
# Tracked files that are neither provider nor hook code.
EXCLUDE = NOT_PROVIDER + ('*/tools/*', 'kernel/tools/*', 'gpu/tests/*', '*/Documentation/*', '*.md',
           '*.rst', '*/.gitignore', 'kernel/drivers/gpu/nvidia-p2p/samples/*')
C_KINDS = ('.c', '.h', '.inc', '.cc', '.cu')
MAKE_KINDS = ('Makefile', 'Kbuild', 'Kconfig')


def git(repo, *args, check=True):
    p = subprocess.run(['git', *args], cwd=str(repo), capture_output=True, text=True)
    if check and p.returncode:
        raise RuntimeError('git %s: %s' % (' '.join(args), p.stderr.strip()))
    return p


def kind(path):
    name = Path(path).name
    if name.endswith(C_KINDS):
        return 'c'
    if name.split('.')[0] in MAKE_KINDS or name.endswith(('.mk', '.Kbuild')):
        return 'make'
    return 'text'


def _strip_c(line, in_block):
    """Code characters of @line outside comments and whether a comment was seen."""
    code, seen, i, quote = [], False, 0, None
    while i < len(line):
        two = line[i:i + 2]
        if in_block:
            seen = True
            if two == '*/':
                in_block, i = False, i + 2
            else:
                i += 1
            continue
        c = line[i]
        if quote:
            code.append(c)
            if c == '\\':
                code.append(line[i + 1:i + 2])
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if two == '//':
            seen = True
            break
        if two == '/*':
            seen, in_block, i = True, True, i + 2
            continue
        if c in '"\'':
            quote = c
        code.append(c)
        i += 1
    return ''.join(code), seen, in_block


def count_lines(text, file_kind):
    total = blank = comment = 0
    in_block = False
    for line in text.splitlines():
        total += 1
        if file_kind == 'c':
            code, seen, in_block_after = _strip_c(line, in_block)
            was_block = in_block
            in_block = in_block_after
            if code.strip():
                continue
            if seen or was_block:
                comment += 1
            else:
                blank += 1
        elif not line.strip():
            blank += 1
        elif file_kind == 'make' and line.lstrip().startswith('#'):
            comment += 1
    return dict(total=total, blank=blank, comment=comment, code=total - blank - comment)


def hunk_lines(base, overlay):
    added = removed = 0
    for line in difflib.unified_diff(base.splitlines(), overlay.splitlines(), n=0,
                                     lineterm=''):
        if line.startswith(('+++', '---', '@@')):
            continue
        if line.startswith('+'):
            added += 1
        elif line.startswith('-'):
            removed += 1
    return dict(added=added, removed=removed)


def matches(path, patterns):
    return any(fnmatch.fnmatchcase(path, p) for p in patterns)


def bases(repo, upstream):
    """component -> (path prefix, commit, git dir or None)."""
    lock = json.loads((Path(repo) / 'sources.lock.json').read_text())
    out = {}
    for name, spec in lock['components'].items():
        gitdir = Path(upstream.get(name, Path(repo) / 'build/upstream' / (name + '.git')))
        ok = gitdir.exists() and not git(repo, '--git-dir', str(gitdir), 'cat-file', '-e',
                                         spec['commit'] + '^{commit}', check=False).returncode
        out[name] = (spec['path'].rstrip('/') + '/', spec['commit'], gitdir if ok else None)
    return out


def hook_entry(repo, path, text, components):
    for prefix, commit, gitdir in components.values():
        if not path.startswith(prefix):
            continue
        if gitdir is None:
            return dict(path=path, base=None, added=None, removed=None,
                        reason='pinned upstream commit %s not available locally' % commit)
        p = git(repo, '--git-dir', str(gitdir), 'show', '%s:%s' % (commit, path[len(prefix):]),
                check=False)
        entry = dict(path=path, base=commit, **hunk_lines(p.stdout if not p.returncode else '',
                                                          text))
        if p.returncode:
            entry['reason'] = 'absent upstream; counted whole'
        return entry
    return dict(path=path, base=None, added=None, removed=None,
                reason='no sources.lock.json component')


def report(repo, catalog, upstream, worktree=False):
    repo = Path(repo)
    tracked = git(repo, 'ls-files', '-z').stdout.split('\0')
    tracked = sorted(p for p in tracked if p)
    revision = git(repo, 'rev-parse', 'HEAD').stdout.strip()
    components = bases(repo, upstream)

    def read(path):
        if worktree:
            return (repo / path).read_text(errors='replace')
        return git(repo, 'show', 'HEAD:' + path).stdout

    classes, claimed, missing = {}, set(), []
    for name, entry in catalog.items():
        own = [p for p in tracked if matches(p, entry['own'])]
        hooks = [p for p in tracked if matches(p, entry['hooks'])]
        missing += [pat for pat in entry['own'] + entry['hooks']
                    if not any(fnmatch.fnmatchcase(p, pat) for p in tracked)]
        claimed.update(own, hooks)
        own_rows = [dict(path=p, **count_lines(read(p), kind(p))) for p in own]
        hook_rows = [hook_entry(repo, p, read(p), components) for p in hooks]
        classes[name] = dict(
            own=own_rows, hooks=hook_rows,
            own_code_lines=sum(r['code'] for r in own_rows),
            own_total_lines=sum(r['total'] for r in own_rows),
            hook_added_lines=sum(r['added'] for r in hook_rows if r['added'] is not None),
            hooks_without_base=sum(r['added'] is None for r in hook_rows))
    prefixes = [v[0] for v in components.values()]
    unclassified = [p for p in tracked if p not in claimed and
                    any(p.startswith(x) for x in prefixes) and not matches(p, EXCLUDE)]
    return dict(schema='xdev-eval-provider-loc-v1', revision=revision,
                source='worktree' if worktree else 'HEAD',
                upstream={n: (c[1] if c[2] else None) for n, c in components.items()},
                classes=classes, unclassified=unclassified, missing=missing)


def main(argv=None, catalog=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--repo', default=str(HERE.parents[2]))
    parser.add_argument('--upstream-git', action='append', default=[],
                        metavar='COMPONENT=GITDIR')
    parser.add_argument('--worktree', action='store_true')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    upstream = {}
    for item in args.upstream_git:
        name, sep, path = item.partition('=')
        if not sep or not name or not path:
            parser.error('--upstream-git takes COMPONENT=GITDIR')
        upstream[name] = Path(path)
    r = report(args.repo, CATALOG if catalog is None else catalog, upstream, args.worktree)
    if args.json:
        print(json.dumps(r, indent=1))
    else:
        print('revision %s (%s); upstream %s' % (r['revision'][:12], r['source'], ', '.join(
            '%s=%s' % (n, (c or 'unavailable')[:12]) for n, c in r['upstream'].items())))
        print('%-18s %6s %6s %6s %8s' % ('class', 'files', 'code', 'hooks', 'hook+'))
        for name, c in r['classes'].items():
            added = str(c['hook_added_lines']) + ('?' if c['hooks_without_base'] else '')
            print('%-18s %6d %6d %6d %8s' % (name, len(c['own']), c['own_code_lines'],
                                              len(c['hooks']), added))
        print('? = %s' % 'some hooks lack the pinned upstream base; their lines are not counted')
        for p in r['unclassified']:
            print('unclassified ' + p)
        for p in r['missing']:
            print('missing ' + p)
    return 1 if r['missing'] else 0


if __name__ == '__main__':
    sys.exit(main())
