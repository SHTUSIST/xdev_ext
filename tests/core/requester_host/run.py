#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host-page (IOU_UMEM) requester mapping of io_uring/family/xdev_ext_requester.c.

Compiles the production requester unit unchanged with a recording DMA API
(shim.h, boundary.c) and runs the independent cases of cases.c, one process per
case. Exit 0 PASS, 1 behaviour FAIL, 2 SETUP_ERROR. Host software only: no
kernel, no device, no DMA.

--mutation NAME applies one documented change to a private copy of the unit and
runs the case that must detect it; KILLED requires exit 1 and a named
REQUESTER_HOST_ASSERT.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
UNIT = 'io_uring/family/xdev_ext_requester.c'
CASES = ('host_bind_maps_every_page', 'host_bind_rx_maps_from_device',
         'host_bind_refuses_misaligned_pool', 'host_bind_refuses_partial_page',
         'host_bind_map_error_unwinds', 'host_lease_page_address', 'host_lease_refuses_spans',
         'host_noncoherent_sync', 'host_coherent_no_sync', 'host_unknown_retains_mapping',
         'host_outstanding_lease_retains_mapping', 'host_unknown_then_quiesced',
         'host_release_during_settled_check', 'host_quiesced_unbind_unmaps_once',
         'peer_bind_unchanged', 'host_create_report')
# name: (case that must catch it, [(old, new)] in UNIT); each makes one requirement false.
MUTATIONS = {
    'accept-misaligned-pool': ('host_bind_refuses_misaligned_pool', [
        ('(pool->frame_size & (pool->frame_size - 1)) || pool->first_page_off ||',
         '(pool->frame_size & (pool->frame_size - 1)) ||')]),
    'accept-partial-page': ('host_bind_refuses_partial_page', [
        ('    pool->size != (u64)pool->nr_pages << PAGE_SHIFT)\n\t\treturn -EINVAL;',
         '    0)\n\t\treturn -EINVAL;')]),
    'map-error-keeps-pages': ('host_bind_map_error_unwinds', [
        ('\t\t\txdev_ext_requester_host_unmap(h, i);\n', '')]),
    'lease-first-page': ('host_lease_page_address', [
        ('addr = h->dma[off >> PAGE_SHIFT] + page_off;', 'addr = h->dma[0] + page_off;')]),
    'lease-crosses-page': ('host_lease_refuses_spans', [
        (' || len > PAGE_SIZE - page_off ||', ' ||')]),
    'lease-crosses-frame': ('host_lease_refuses_spans', [
        (' ||\n\t    (off & frame_mask) != ((off + len - 1) & frame_mask))', ')')]),
    'no-sync-for-device': ('host_noncoherent_sync', [
        ('\t\tdma_sync_single_for_device(&h->pdev->dev, addr, len, h->dir);\n', '\t\t;\n')]),
    'no-sync-for-cpu': ('host_noncoherent_sync', [
        ('\t\tdma_sync_single_for_cpu(&h->pdev->dev, dma, len, DMA_FROM_DEVICE);\n', '\t\t;\n')]),
    'sync-coherent-too': ('host_coherent_no_sync', [
        ('\tif (h->need_sync)\n\t\tdma_sync_single_for_device', '\tif (1)\n\t\tdma_sync_single_for_device')]),
    'lease-after-unknown': ('host_unknown_retains_mapping', [
        ('\tif (READ_ONCE(h->unknown))\n\t\treturn -ESTALE;\n', '')]),
    'unmap-after-unknown': ('host_unknown_retains_mapping', [
        ('\treturn atomic_read_acquire(&h->active) || READ_ONCE(h->unknown);',
         '\treturn atomic_read_acquire(&h->active);')]),
    'unmap-outstanding-lease': ('host_outstanding_lease_retains_mapping', [
        ('\treturn atomic_read_acquire(&h->active) || READ_ONCE(h->unknown);', '\treturn READ_ONCE(h->unknown);')]),
    # Unbinding a busy mapping no longer warns.
    'busy-unbind-silent': ('host_unknown_retains_mapping', [
        ('\tif (h && WARN_ON_ONCE(xdev_ext_requester_host_busy(h))) {\n',
         '\tif (h && xdev_ext_requester_host_busy(h)) {\n')]),
    # The settled check reads the unknown mark before the lease count, as at d3dced6.
    'settled-reads-unknown-first': ('host_release_during_settled_check', [
        ('\treturn atomic_read_acquire(&h->active) || READ_ONCE(h->unknown);',
         '\treturn READ_ONCE(h->unknown) || atomic_read(&h->active);')]),
    'peer-bind-takes-host-pool': ('host_bind_maps_every_page', [
        ('\tif (pool->kind != XDEV_EXT_MECH_POOL_PEER || !pdev || rq->pdev)\n',
         '\tif (pool->kind == XDEV_EXT_MECH_POOL_IOU_UMEM)\n\t\treturn xdev_ext_requester_bind_host(rq, st, pdev);\n'
         '\tif (pool->kind != XDEV_EXT_MECH_POOL_PEER || !pdev || rq->pdev)\n')]),
    'host-bind-takes-peer-pool': ('host_lease_refuses_spans', [
        ('pool->kind != XDEV_EXT_MECH_POOL_IOU_UMEM || !pdev || rq->pdev', '!pdev || rq->pdev')]),
    # A later quiesced end clears the unknown mark (review of d3dced6).
    'review-latch-not-sticky': ('host_unknown_then_quiesced', [
        ('\tif (!quiesced)\n\t\tWRITE_ONCE(h->unknown, true);\n'
         '\telse if (h->need_sync && h->dir == DMA_FROM_DEVICE)\n',
         '\tWRITE_ONCE(h->unknown, !quiesced);\n'
         '\tif (quiesced && h->need_sync && h->dir == DMA_FROM_DEVICE)\n')]),
}


class Setup(Exception):
    pass


def assemble(root, out):
    """Native include/ and io_uring/ paths of the canonical sources."""
    sys.path.insert(0, str(root / 'tools'))
    import layout  # noqa: E402
    lay = layout.load_layout(root)
    kernel = out / 'source/kernel'
    if kernel.exists():
        shutil.rmtree(kernel)
    hashes = {}
    for (component, native), source in lay.by_native.items():
        if component != 'linux' or not native.startswith(('include/', 'io_uring/')):
            continue
        destination = kernel / native
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / source, destination)
        hashes[native] = hashlib.sha256((root / source).read_bytes()).hexdigest()
    if not (kernel / UNIT).is_file():
        raise Setup('missing production unit ' + UNIT)
    return kernel, hashes


def mutate(kernel, name):
    for old, new in MUTATIONS[name][1]:
        path = kernel / UNIT
        text = path.read_text()
        if text.count(old) != 1:
            raise Setup('mutation anchor count %d for %s' % (text.count(old), name))
        path.write_text(text.replace(old, new, 1))


def facade(kernel, directory, units):
    """Empty Linux headers for every non-project include reached from the units."""
    pending, seen, names = list(units), set(), set()
    pattern = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]', re.M)
    while pending:
        path = pending.pop()
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        for kind, name in pattern.findall(path.read_text(errors='replace')):
            local = path.parent / name if kind == '"' else None
            if local is not None and local.is_file():
                pending.append(local)
                continue
            project = kernel / 'include' / name
            if ('xdev_ext' in name or name.startswith('uapi/')) and project.is_file():
                pending.append(project)
            elif kind == '<' and name.split('/')[0] in ('linux', 'asm', 'uapi', 'generated'):
                names.add(name)
    for name in names:
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('/* kernel boundary supplied by shim.h */\n')
    # Host <errno.h> reaches <linux/errno.h>: keep the real numeric constants.
    (directory / 'linux').mkdir(parents=True, exist_ok=True)
    (directory / 'linux/errno.h').write_text('#include <asm-generic/errno.h>\n')
    return sorted(names)


def build(root, out, sanitize, mutation):
    kernel, hashes = assemble(root, out)
    if mutation:
        mutate(kernel, mutation)
    work = out / 'build'
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    env = work / 'facade'
    units = [kernel / UNIT, HERE / 'boundary.c', HERE / 'cases.c']
    facade(kernel, env, units)
    cc = os.environ.get('CC', 'gcc')
    flags = ['-std=gnu11', '-O0', '-g', '-Wall', '-Wextra', '-Wno-unused-parameter',
             '-Wno-missing-field-initializers', '-Werror=implicit-function-declaration',
             '-include', str(HERE / 'shim.h'), '-I', str(env), '-I', str(kernel / 'include'),
             '-I', str(HERE)]
    if sanitize:
        flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
    log, objects = [], []
    for number, unit in enumerate(units):
        obj = work / ('unit-%d.o' % number)
        result = subprocess.run([cc] + flags + ['-MD', '-MF', str(obj) + '.d', '-c', str(unit), '-o', str(obj)],
                                capture_output=True, text=True, timeout=300)
        log.append('$ %s -c %s\n%s%s' % (cc, unit, result.stdout, result.stderr))
        if result.returncode:
            (out / 'compile.log').write_text('\n'.join(log))
            raise Setup('compile failed: %s\n%s' % (unit, result.stderr[-4000:]))
        objects.append(obj)
    binary = work / 'requester-host-cases'
    result = subprocess.run([cc] + (['-fsanitize=address,undefined'] if sanitize else []) +
                            [str(o) for o in objects] + ['-o', str(binary)],
                            capture_output=True, text=True, timeout=300)
    log.append('$ link\n' + result.stdout + result.stderr)
    (out / 'compile.log').write_text('\n'.join(log))
    if result.returncode:
        raise Setup('link failed\n' + result.stderr[-4000:])
    return kernel, hashes, binary


def inputs(root, out, kernel, hashes):
    """Kernel-tree files the compiler opened (gcc -MD), hashed in the source tree before
    any mutation, and the test files this runner read."""
    production, tests = {}, {}
    for dep in sorted((out / 'build').glob('*.d')):
        for item in dep.read_text().replace('\\\n', ' ').split(':', 1)[-1].split():
            path = Path(item).resolve()
            try:
                key = str(path.relative_to(kernel))
            except ValueError:
                continue
            production[key] = hashes.get(key) or hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted(HERE.iterdir()):
        if path.is_file():
            tests[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return dict(sorted(production.items())), tests


def run_cases(binary, out, cases):
    results = []
    for name in cases:
        try:
            run = subprocess.run([str(binary), name], capture_output=True, text=True, timeout=60)
            output, code = run.stdout + run.stderr, run.returncode
        except subprocess.TimeoutExpired as error:
            output, code = str(error.stdout or '') + '\nTIMEOUT\n', 124
        (out / (name + '.log')).write_text(output + '\nexit=%d\n' % code)
        marker = 'REQUESTER_HOST_CASE ' + name + ' assertions='
        counted = [int(line[len(marker):]) for line in output.splitlines() if line.startswith(marker)]
        failed = next((line for line in output.splitlines() if line.startswith('REQUESTER_HOST_ASSERT')), None)
        results.append(dict(case=name, exit=code, assertions=counted[-1] if counted else 0,
                            passed=code == 0 and bool(counted) and counted[-1] > 0,
                            failed_assertion=failed))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', choices=CASES)
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--mutation', choices=sorted(MUTATIONS))
    args = parser.parse_args()
    root, out = args.source_root.resolve(), args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    record = dict(scope='host compilation of the production requester unit with a recording DMA API; '
                  'no kernel, device or DMA', sanitize=args.sanitize, mutation=args.mutation)
    try:
        record['head'] = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'],
                                        capture_output=True, text=True).stdout.strip()
        kernel, hashes, binary = build(root, out, args.sanitize, args.mutation)
        record['inputs_sha256'], record['test_inputs_sha256'] = inputs(root, out, kernel, hashes)
        cases = [MUTATIONS[args.mutation][0]] if args.mutation else ([args.case] if args.case else list(CASES))
        record['cases'] = run_cases(binary, out, cases)
        if args.mutation:
            killed = all(c['exit'] == 1 and c['failed_assertion'] for c in record['cases'])
            record['verdict'] = 'KILLED' if killed else 'SURVIVED'
            code = 0 if killed else 1
        else:
            record['verdict'] = 'PASS' if all(c['passed'] for c in record['cases']) else 'FAIL'
            code = 0 if record['verdict'] == 'PASS' else 1
    except (Setup, OSError, subprocess.SubprocessError) as error:
        record.update(verdict='SETUP_ERROR', error=str(error))
        code = 2
    (out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    for case in record.get('cases', []):
        print(('ok' if case['passed'] else 'not ok') + ' - %s assertions=%d exit=%d' %
              (case['case'], case['assertions'], case['exit']) +
              ('' if case['passed'] else ' ' + str(case['failed_assertion'])))
    print('REQUESTER_HOST_VERDICT ' + record['verdict'] + ('\n' + record.get('error', '') if code == 2 else ''))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
