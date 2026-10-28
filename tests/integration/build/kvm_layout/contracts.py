#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Fail-closed host contracts for canonical KVM input and console records."""
import json
from pathlib import Path
import re
import sys


def read_json(path):
    return json.loads(Path(path).read_text())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checked_file(root, relative):
    relative = Path(relative)
    require(not relative.is_absolute() and '..' not in relative.parts, 'unsafe receipt path')
    path = root / relative
    require(not path.is_symlink() and path.resolve().is_relative_to(root), 'nonlocal receipt input: ' + str(path))
    require(path.is_file(), 'missing input: ' + str(path))
    return path


def check_roots(source, sha, build, baseline=False):
    source, build = Path(source).resolve(), Path(build).resolve()
    require(bool(re.fullmatch('[0-9a-f]{40}', sha)), 'invalid source commit')
    view, assembled = source / 'build/source-view', source / 'build/assembled/linux'
    manifest = read_json(source / 'source-layout.json')
    lock = read_json(source / manifest.get('dependency_lock', 'third_party/sources.lock.json'))
    v = read_json(view / 'view.json')
    a = read_json(assembled / '.xdev-ext-source.json')
    require(v.get('schema') == 1 and v.get('kind') == 'host-source-view' and
            v.get('canonical_root') == str(source) and v.get('revision') == sha and
            v.get('dirty') is False and v.get('manifest') == manifest, 'stale or foreign source view')
    require(a.get('schema') == 2 and a.get('kind') == 'full-assembly' and
            a.get('component') == 'linux' and a.get('canonical_root') == str(source) and
            a.get('output') == str(assembled), 'foreign full assembly')
    require(lock.get('schema') == 2 and all(a.get(k) == lock['components']['linux'][k]
            for k in ('commit', 'url', 'ref')), 'assembly differs from pinned Linux')
    origins, overlay = {}, {}
    for entry in manifest['files']:
        if 'component' in entry:
            prefix = {'linux': 'kernel', 'nvidia': 'gpu'}[entry['component']]
            logical = prefix + '/' + entry['native_path']
            if entry['component'] == 'linux':
                overlay[entry['native_path']] = entry['source']
        else:
            logical = entry['logical_path']
        origins[logical] = entry['source']
    require(v.get('source_origins') == origins and a.get('source_origins') == overlay,
            'receipt input membership differs from canonical mapping')
    for mapping, destination in ((origins, view), (overlay, assembled)):
        for relative, original in mapping.items():
            require(checked_file(destination, relative).read_bytes() ==
                    checked_file(source, original).read_bytes(), 'input differs: ' + relative)
    for path in ('Makefile', 'scripts/Makefile.build', 'include/linux/kernel.h'):
        checked_file(assembled, path)
    if not baseline:
        require((build / 'source').is_symlink() and (build / 'source').resolve() == assembled,
                'Kbuild source does not identify assembled Linux')
    return dict(source=str(source), source_commit=sha, native=str(view / 'kernel'),
                assembled=str(assembled), view_receipt=v, assembly_receipt=a,
                build_identity='old-baseline-not-enforced' if baseline else 'matching-assembled-source')


def kunit_names(source):
    text = Path(source).read_text()
    block = text.split('static struct kunit_case tb_test_cases[] = {', 1)[1].split('\n};', 1)[0]
    names = re.findall(r'KUNIT_CASE\((tb_test_[a-z0-9_]+)\)', block)
    require(len(names) == len(set(names)) == 45, 'canonical KUnit membership must be exactly 45')
    return names


def check_kunit(names, text):
    text = text.replace('\r', '')
    require(len(names) == len(set(names)) == 45, 'expected KUnit membership must be exactly 45')
    require(text.splitlines().count('XDOMAIN_DMESG_BEGIN') == 1 and
            text.splitlines().count('XDOMAIN_DMESG_END') == 1, 'missing or duplicate final dmesg')
    require(text.index('XDOMAIN_DMESG_BEGIN\n') < text.index('XDOMAIN_DMESG_END'),
            'final dmesg markers out of sequence')
    require(not re.search(r'(?im)\bnot ok\b|#\s*SKIP\b', text), 'failed or skipped KTAP')
    body = text.split('XDOMAIN_DMESG_BEGIN\n', 1)[1].split('\nXDOMAIN_DMESG_END', 1)[0]
    seen = re.findall(r'(?m)^[ \t]*(?:\[[^\]\n]+\][ \t]*)?ok[ \t]+\d+[ \t]+(tb_test_[a-z0-9_]+)(?:[ \t].*)?$', body)
    require(len(seen) == 45 and set(seen) == set(names), 'missing, duplicate or unknown KUnit cases')
    require(text.splitlines().count('XDEV_EXT_XDOMAIN_GUEST_EXIT=0') == 1,
            'missing or duplicate successful guest exit')
    return dict(status='PASS', cases=45, names=names, section='final-dmesg')


ORDERED_PASS = ('XDEV_EXT_ORDERED_FRAMES_GUEST=PASS messages=6 selected=7,3,9,1 '
                'raw_user=1 poll_without_kick=1 whole_disk=1 stop_late=1 timing=none')


def check_ordered(text):
    text = text.replace('\r', '')
    records = ['XDEV_EXT_ORDERED_PROVIDER_LOAD=0', ORDERED_PASS,
               'XDEV_EXT_ORDERED_C_EXIT=0', 'XDEV_EXT_ORDERED_PROVIDER_UNLOAD=0',
               'XDEV_EXT_ORDERED_DMESG_BEGIN', 'XDEV_EXT_ORDERED_DMESG_END',
               'XDEV_EXT_ORDERED_GUEST_EXIT=0']
    lines = text.splitlines()
    positions = []
    for record in records:
        require(lines.count(record) == 1, 'missing or duplicate ordered record: ' + record)
        prefix = record.split('=', 1)[0]
        require(sum(line.startswith(prefix) for line in lines) == 1,
                'conflicting ordered record: ' + prefix)
        positions.append(lines.index(record))
    require(positions == sorted(positions), 'ordered terminal records out of sequence')
    require(not re.search(r'(?im)\bnot ok\b|\bFAIL\b|#\s*SKIP\b|^\s*SKIP(?:PED)?\b|'
                          r'\.{3}\s+skipped\b|^OK\s*\(skipped=|quarantin|'
                          r'drain bound passed|deferred[ _-]*drain|WARNING:|BUG:|Oops:|Kernel panic', text),
            'ordered failure, skip, quarantine, deferred drain or kernel diagnostic')
    return dict(status='PASS', messages=6, selected=[7, 3, 9, 1], timing='none')


def check_artifacts(manifest, required):
    entries = {}
    for line in Path(manifest).read_text().splitlines():
        match = re.fullmatch(r'([a-f0-9]{64}) [ *](.+)', line)
        require(match is not None, 'malformed build checksum record')
        path = str(Path(match[2]).resolve())
        require(path not in entries, 'duplicate build checksum path: ' + path)
        entries[path] = match[1]
    missing = sorted({str(Path(path).resolve()) for path in required} - entries.keys())
    require(not missing, 'build checksum manifest omits required artifacts: ' + ', '.join(missing))
    return dict(status='PASS', required=[str(Path(path).resolve()) for path in required])


def main():
    action, *args = sys.argv[1:]
    if action in ('roots', 'red-roots'):
        source, sha, build, output = args
        result = check_roots(source, sha, build, baseline=action == 'red-roots')
    elif action == 'freeze-kunit':
        source, output = args
        result = kunit_names(source)
    elif action == 'kunit':
        expected, log, output = args
        result = check_kunit(read_json(expected), Path(log).read_text(errors='replace'))
    elif action == 'artifacts':
        manifest, output, *required = args
        require(bool(required), 'empty required artifact list')
        result = check_artifacts(manifest, required)
    elif action == 'ordered-log':
        log, output = args
        result = check_ordered(Path(log).read_text(errors='replace'))
    else:
        raise ValueError('unknown contract action: ' + action)
    Path(output).write_text(json.dumps(result, sort_keys=True) + '\n')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, IndexError) as error:
        print('KVM_CONTRACT=FAIL ' + str(error), file=sys.stderr)
        sys.exit(1)
