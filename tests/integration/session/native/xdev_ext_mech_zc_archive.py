#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze one command's original inputs and outputs before scratch reuse.

This is an archive boundary, not an oracle or an acceptance decision.  Manifest
paths retain their original spelling; archived-artifacts.json locates the frozen
bytes independently of the mutable original directories.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time


SERVER_CACHE_BASE = Path('/root/xdev_ext/build-cache')
IMAGE_NAMES = ('source-before.raw', 'source.raw', 'destination-before.raw',
               'destination.raw', 'expected.raw', 'initramfs.cpio.gz',
               'compat.raw', 'peer.raw')
BUILD_NAMES = ('.config', 'xdev-ext-source.commit', 'xdev-ext-debug-profile.json',
               'include/config/kernel.release', 'Module.symvers',
               'xdev-ext-e2-mode.txt',
               'xdev-ext-artifacts.sha256', 'xdev-ext-e2-sources.sha256',
               'xdev-ext-eval-session-source.sha256', 'xdev-ext-fence-sources.sha256')
MANIFEST_BASES = {'xdev-ext-artifacts.sha256': 'scratch',
                  'artifacts.sha256': 'scratch',
                  'source-files.sha256': 'native',
                  'xdev-ext-e2-sources.sha256': 'source',
                  'xdev-ext-eval-session-source.sha256': 'source',
                  'xdev-ext-fence-sources.sha256': 'source'}
JSON_LIMIT = 16 * 1024 * 1024
MANIFEST_LIMIT = 128 * 1024 * 1024
RECORD_LIMIT = 1000000
BLOCK = 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def real_path(value):
    path = Path(value)
    require(path.is_absolute() and '..' not in path.parts,
            'path must be absolute without traversal: ' + str(path))
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), 'symlink path is not allowed: ' + str(parent))
    require(path.resolve() == path, 'path must name its real location: ' + str(path))
    return path


def regular(path):
    path = real_path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode), 'archive needs regular file: ' + str(path))
    return path


def owned_directory(path, mode=None):
    path = real_path(path)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid()),
            'directory must be real and owned: ' + str(path))
    if mode is not None:
        require(stat.S_IMODE(info.st_mode) == mode,
                'directory has wrong mode: ' + str(path))
    return path


def digest(path):
    path = regular(path)
    result = hashlib.sha256()
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'nonregular hash input')
        for block in iter(lambda: stream.read(BLOCK), b''):
            result.update(block)
    return result.hexdigest()


def read_json(path):
    path = regular(path)
    require(path.stat().st_size <= JSON_LIMIT, 'JSON input exceeds bound: ' + str(path))
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        data = stream.read(JSON_LIMIT + 1)
    require(len(data) <= JSON_LIMIT, 'JSON input exceeds bound: ' + str(path))
    return json.loads(data, object_pairs_hook=unique)


def write_json(path, value):
    path = real_path(path)
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def git(repo, *args):
    result = subprocess.run(['git', '-C', str(repo), *args], capture_output=True)
    require(result.returncode == 0,
            result.stderr.decode(errors='replace').strip() or 'source Git check failed')
    return result.stdout


def source_authority(source_root, native_root):
    """Inspect existing source receipts; never prepare or repair any input."""
    repo = owned_directory(source_root)
    native = owned_directory(native_root)
    require(Path(git(repo, 'rev-parse', '--show-toplevel').decode().strip()) == repo,
            'canonical source must be its own Git root')
    require(not git(repo, 'status', '--porcelain', '--untracked-files=all'),
            'canonical source contains dirty or untracked files')
    revision = git(repo, 'rev-parse', '--verify', 'HEAD^{commit}').decode().strip()
    require(re.fullmatch(r'[a-f0-9]{40}', revision), 'source commit must be complete')
    metadata = ('source-layout.json', 'tools/layout.py', 'tools/build/prepare_sources.py')
    git(repo, 'ls-files', '--error-unmatch', '--', *metadata)
    for name in metadata:
        regular(repo / name)
    # Import only the tracked tooling from the already checked canonical root.
    spec = importlib.util.spec_from_file_location('_xdev_archive_layout', repo / 'tools/layout.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        layout = module.load_layout(repo)
    finally:
        sys.modules.pop(spec.name, None)
    lock_name = layout.manifest.get('dependency_lock', 'third_party/sources.lock.json')
    git(repo, 'ls-files', '--error-unmatch', '--', lock_name, *layout.by_source)
    canonical = {regular(repo / name) for name in layout.by_source}
    canonical.update(regular(repo / name) for name in (*metadata, lock_name))
    lock = read_json(repo / lock_name)
    require(lock.get('schema') == 2, 'unsupported dependency lock')
    marker = regular(native / '.xdev-ext-source.json')
    require(marker.stat().st_nlink == 1, 'native receipt must be an isolated copy')
    receipt = read_json(marker)
    origins = {name: source for (component, name), source in layout.by_native.items()
               if component == 'linux'}
    upstream = lock['components']['linux']
    expected = dict(schema=2, kind='full-assembly', component='linux',
                    canonical_root=str(repo), output=str(native), source_origins=origins,
                    url=upstream['url'], ref=upstream['ref'], commit=upstream['commit'])
    require(all(receipt.get(key) == value for key, value in expected.items()),
            'native assembly receipt does not match canonical authority')
    checked = subprocess.run([sys.executable, '-B', str(repo / metadata[2]),
                              '--component', 'linux', '--output', str(native), '--check'],
                             capture_output=True, text=True)
    require(checked.returncode == 0,
            'native assembly check failed: ' + checked.stdout + checked.stderr)
    native_files = {marker}
    for name, source in origins.items():
        actual, original = regular(native / name), regular(repo / source)
        require(digest(actual) == digest(original), 'native source copy differs: ' + name)
        native_files.add(actual)
    view_files = set()
    view = repo / 'build/source-view'
    if view.exists() or view.is_symlink():
        owned_directory(view)
        view_marker = regular(view / 'view.json')
        view_receipt = read_json(view_marker)
        require(view_marker.stat().st_nlink == 1, 'view receipt must be an isolated copy')
        require(view_receipt.get('schema') == 1 and
                view_receipt.get('kind') == 'host-source-view' and
                view_receipt.get('canonical_root') == str(repo) and
                view_receipt.get('revision') == revision and
                view_receipt.get('source_origins') == layout.by_logical and
                view_receipt.get('manifest') == layout.manifest,
                'support view receipt does not match canonical authority')
        view_files.add(view_marker)
        for logical, source in layout.by_logical.items():
            actual, original = regular(view / logical), regular(repo / source)
            require(actual.stat().st_nlink == 1 and digest(actual) == digest(original),
                    'support view copy differs: ' + logical)
            view_files.add(actual)
        for name in ('source-layout.json', 'sources.lock.json'):
            actual = regular(view / name)
            require(actual.stat().st_nlink == 1, 'view metadata must be an isolated copy')
            view_files.add(actual)
        require(digest(view / 'source-layout.json') == digest(repo / 'source-layout.json'),
                'support view layout differs')
        legacy = json.loads(json.dumps(lock))
        legacy['schema'] = 1
        for component, component_lock in legacy['components'].items():
            component_lock['path'] = module.PREFIXES[component]
        require(read_json(view / 'sources.lock.json') == legacy, 'support view lock differs')
    identity_inputs = set()
    for logical in ('tests/eval/dmabuf_lifecycle/run.py',
                    'kernel/io_uring/xdev_ext_mech_lifecycle.h'):
        if logical in layout.by_logical:
            identity_inputs.add(repo / layout.by_logical[logical])
            if view_files:
                identity_inputs.add(view / logical)
            if logical.startswith('kernel/'):
                identity_inputs.add(native / logical[len('kernel/'):])
    generated_artifacts = set()
    fence_directory = Path('tests/eval/dmabuf_lifecycle')
    fence_inputs = (fence_directory / 'Kbuild', fence_directory / 'run.py')
    if all(str(name) in layout.by_logical and view / name in view_files
           for name in fence_inputs):
        # This exact generated module is an artifact, never a mapped source.
        # Its bytes are admitted only when a build/evidence manifest lists it.
        generated_artifacts.add(view / fence_directory / 'lifecycle_bench.ko')
    return dict(revision=revision, canonical=canonical, native=native_files,
                view=view_files, source_roots=(repo, native, view),
                generated_artifacts=generated_artifacts,
                metadata={repo / name for name in (*metadata, lock_name)} |
                {marker} | identity_inputs)


def approved_cache_roots(scratch):
    """Authorize exactly the two existing roots in the private root receipt."""
    receipt = scratch / 'cache-location.json'
    names = ('build', 'tools')
    if not receipt.exists() and not receipt.is_symlink():
        require(not any((scratch / name).is_symlink() for name in names),
                'cache aliases require a root-approved location receipt')
        return {}
    regular(receipt)
    info = receipt.stat()
    require(info.st_uid in (0, os.getuid()) and stat.S_IMODE(info.st_mode) == 0o600,
            'cache receipt must be owned regular mode 0600')
    decision = read_json(receipt)
    require(isinstance(decision, dict), 'invalid cache location receipt')
    base = real_path(SERVER_CACHE_BASE)
    run = base / 'runs' / scratch.name
    roots = {name: run / name for name in names}
    require(type(decision.get('schema')) is int and decision['schema'] == 1 and
            decision.get('decision') == 'ALLOW_BUILD_TOOLS_CACHE_LOCATION' and
            decision.get('approved_by') == 'root' and decision.get('root_approved') is True and
            decision.get('verifiedcmp') is True, 'cache location lacks root approval')
    require(decision.get('source_scratch') == str(scratch) and
            decision.get('cache_base') == str(base) and decision.get('cache_root') == str(run),
            'cache location is bound to another scratch/base/run')
    require(decision.get('roots') == {name: str(path) for name, path in roots.items()},
            'cache approval must name exactly build and tools')
    require(isinstance(decision.get('method'), str) and decision['method'].strip(),
            'cache migration method missing')
    for path in (base, base / 'runs', run, *roots.values()):
        owned_directory(path, 0o700)
    for name, path in roots.items():
        alias = scratch / name
        require(alias.is_symlink() and alias.resolve(strict=True) == path,
                'cache alias does not match approved root: ' + str(alias))
    return roots


def archive_relative(path, scratch, cache_roots):
    for name, root in cache_roots.items():
        if path.is_relative_to(root):
            return Path(name) / path.relative_to(root)
    return path.relative_to(scratch) if path.is_relative_to(scratch) else None


def store_file(source, target, blobs, expected=None):
    """Copy into a checked blob; only immutable archive names share its inode."""
    source = regular(source)
    sha = digest(source)
    require(expected is None or sha == expected, 'archive manifest hash mismatch: ' + str(source))
    real_path(blobs)
    blobs.mkdir(mode=0o700, parents=True, exist_ok=True)
    owned_directory(blobs, 0o700)
    blob = blobs / sha
    if blob.exists() or blob.is_symlink():
        require(digest(blob) == sha, 'existing archive blob corrupted')
        require(stat.S_IMODE(blob.stat().st_mode) == 0o444,
                'existing archive blob must be read-only')
    else:
        fd, temporary = tempfile.mkstemp(prefix='.copy-', dir=blobs)
        temporary = Path(temporary)
        try:
            with os.fdopen(fd, 'wb') as output:
                with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
                    require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'nonregular copy input')
                    shutil.copyfileobj(stream, output, BLOCK)
                output.flush()
                os.fsync(output.fileno())
            require(digest(temporary) == sha and digest(source) == sha, 'archive copy changed')
            temporary.chmod(0o444)
            try:
                os.link(temporary, blob)
            except FileExistsError:
                require(digest(blob) == sha, 'existing archive blob corrupted')
        finally:
            temporary.unlink(missing_ok=True)
    target = real_path(target)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target.exists():
        require(digest(target) == sha, 'frozen aliases disagree: ' + str(target))
    else:
        os.link(blob, target)
    require(digest(target) == sha, 'frozen target differs: ' + str(target))
    return sha


def frozen_alias(source, target):
    source, target = regular(source), real_path(target)
    if target.exists():
        require(digest(target) == digest(source), 'frozen aliases disagree')
    else:
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.link(source, target)


def case_location(scratch, case_dir):
    scratch = owned_directory(scratch, 0o700)
    case_dir = real_path(case_dir)
    require(case_dir != scratch and case_dir.is_relative_to(scratch),
            'case archive must stay within owned scratch')
    require(case_dir.relative_to(scratch).parts[0] not in ('evidence', 'build', 'tools'),
            'case archive overlaps mutable command outputs')
    for parent in case_dir.parents:
        if parent == scratch:
            break
        if parent.exists():
            owned_directory(parent)
    return scratch, case_dir


def input_path(path, scratch, cache_roots, authority, artifact_manifest=False):
    """Resolve only the approved build/tools aliases, never arbitrary links."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts,
            'manifest target must be absolute without traversal')
    for name, root in cache_roots.items():
        alias = scratch / name
        if path.is_relative_to(alias):
            path = root / path.relative_to(alias)
            break
    real_path(path)
    inside_scratch = path.is_relative_to(scratch)
    require(not inside_scratch or not path.is_relative_to(scratch / 'acceptance'),
            'manifest target cannot reference case archives')
    mapped = (path in authority['canonical'] or path in authority['native'] or
              path in authority['view'])
    generated = artifact_manifest and path in authority['generated_artifacts']
    if any(path.is_relative_to(root) for root in authority['source_roots']):
        require(mapped or generated, 'source target lacks mapped authority: ' + str(path))
    require(inside_scratch or any(path.is_relative_to(root) for root in cache_roots.values()) or
            mapped or generated,
            'archive manifest outside owned or mapped paths: ' + str(path))
    return regular(path)


def tree_files(root):
    owned_directory(root)
    count = 0
    for directory, names, files in os.walk(root, followlinks=False):
        for name in sorted(names + files):
            path = Path(directory) / name
            real_path(path)
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
                    'nonregular evidence entry: ' + str(path))
            if stat.S_ISREG(info.st_mode):
                count += 1
                require(count <= RECORD_LIMIT, 'too many evidence files')
                yield path


def manifest_records(manifest, cwd, scratch, cache_roots, authority, artifact_manifest=False):
    require(manifest.stat().st_size <= MANIFEST_LIMIT, 'manifest exceeds size bound')
    seen = {}
    total = 0
    with os.fdopen(os.open(regular(manifest), os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        for index in range(RECORD_LIMIT + 1):
            line = stream.readline(8193)
            if not line:
                break
            total += len(line)
            require(index < RECORD_LIMIT and len(line) <= 8192 and total <= MANIFEST_LIMIT,
                    'manifest exceeds record/line bound')
            match = re.fullmatch(rb'([a-f0-9]{64}) [ *]([^\x00-\x1f\x7f]+)\n?', line)
            require(match is not None, 'malformed archive manifest: ' + str(manifest))
            expected, name = match.groups()
            name = os.fsdecode(name)
            named = Path(name)
            require('..' not in named.parts, 'manifest path traversal')
            path = input_path(named if named.is_absolute() else cwd / named,
                              scratch, cache_roots, authority, artifact_manifest)
            require(path not in seen or seen[path] == expected,
                    'conflicting hashes within manifest: ' + str(path))
            seen[path] = expected
            yield path, expected.decode('ascii')


def freeze_e2_manifest(case_dir, scratch, cache_roots, archived, authority, source_root):
    """Preserve raw manifests and derive replay copies from checked frozen bytes."""
    build = cache_roots.get('build', scratch / 'build')
    specifications = (
        ('xdev-ext-artifacts.sha256', scratch, 'frozen-e2-manifest.json', True),
        ('xdev-ext-e2-sources.sha256', source_root, 'frozen-e2-sources-manifest.json', False),
    )
    pending = []
    # Preserve every raw manifest first: another raw manifest may hash it.
    # Renaming a frozen alias keeps its immutable blob untouched; the replay
    # file is then created exclusively with a new inode.
    for name, cwd, map_name, artifact_manifest in specifications:
        manifest = case_dir / 'build' / name
        if not manifest.exists() and not manifest.is_symlink():
            continue  # A failed command may not have produced this input.
        regular(manifest)
        key = str(build / name)
        require(key in archived and digest(manifest) == archived[key]['sha256'],
                'E2 original manifest was not frozen correctly: ' + name)
        original = manifest.with_name(manifest.stem + '.original' + manifest.suffix)
        require(not original.exists() and not original.is_symlink(),
                'E2 original manifest already exists: ' + name)
        manifest.rename(original)
        archived[key]['file'] = str(original.relative_to(case_dir))
        pending.append((manifest, original, cwd, map_name, artifact_manifest))
    for manifest, original, cwd, map_name, artifact_manifest in pending:
        rewritten = []
        mapping = {}
        for path, expected in manifest_records(original, cwd, scratch, cache_roots,
                                               authority, artifact_manifest):
            require(str(path) in archived, 'E2 target was not archived: ' + str(path))
            record = archived[str(path)]
            relative = Path(record['file'])
            require(not relative.is_absolute() and '..' not in relative.parts,
                    'E2 frozen target escapes archive')
            target = regular(case_dir / relative)
            require(record['sha256'] == expected and digest(target) == expected,
                    'E2 frozen manifest target missing/corrupt: ' + str(path))
            rewritten.append(expected + '  ' + str(target) + '\n')
            mapping[str(path)] = str(target)
        with manifest.open('x') as stream:
            stream.write(''.join(rewritten))
        manifest.chmod(0o444)
        write_json(case_dir / map_name,
                   dict(original=str(original.relative_to(case_dir)),
                        original_sha256=digest(original),
                        frozen=str(manifest.relative_to(case_dir)),
                        frozen_sha256=digest(manifest), targets=mapping))


def archive_case(scratch: Path, case_dir: Path,
                 source_root: Path, native_root: Path) -> None:
    scratch, case_dir = case_location(scratch, case_dir)
    require(not any((case_dir / name).exists() or (case_dir / name).is_symlink()
                    for name in ('archive-files.json', 'archived-artifacts.json')),
            'case archive already exists')
    case_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    owned_directory(case_dir, 0o700)
    authority = source_authority(source_root, native_root)
    cache_roots = approved_cache_roots(scratch)
    blobs = case_dir.parent / 'blobs'
    archived = {}
    queue = []
    visited = set()
    roots = dict(scratch=scratch, source=Path(source_root), native=Path(native_root))
    artifact_manifests = {scratch / 'evidence/artifacts.sha256',
                          cache_roots.get('build', scratch / 'build') /
                          'xdev-ext-artifacts.sha256'}

    def freeze(source, target, expected=None, artifact_manifest=False):
        source = input_path(source, scratch, cache_roots, authority,
                            artifact_manifest and expected is not None)
        key = str(source)
        if key in archived:
            require(expected is None or archived[key]['sha256'] == expected,
                    'archive manifests disagree: ' + key)
            # A repeated manifest reference consumes no new numbered slot.
            if target.parent != case_dir / 'artifacts':
                frozen_alias(case_dir / archived[key]['file'], target)
        else:
            actual = store_file(source, target, blobs, expected)
            archived[key] = dict(file=str(target.relative_to(case_dir)), sha256=actual,
                                 expected_sha256=expected or actual)
        if source.name in MANIFEST_BASES and source not in visited:
            queue.append(source)
        return source

    def optional(path, target):
        # Only the two root-approved cache aliases are resolved here.
        candidate = path
        for name, root in cache_roots.items():
            if path.is_relative_to(scratch / name):
                candidate = root / path.relative_to(scratch / name)
                break
        real_path(candidate)
        if candidate.exists():
            freeze(path, target)

    try:
        evidence = scratch / 'evidence'
        if evidence.exists() or evidence.is_symlink():
            for path in tree_files(evidence):
                freeze(path, case_dir / 'evidence' / path.relative_to(evidence))
        for name in ('cache-location.json', 'debug-build-cache.json'):
            optional(scratch / name, case_dir / name)
        for name in IMAGE_NAMES:
            optional(scratch / name, case_dir / 'images' / name)
        for name in BUILD_NAMES:
            optional(scratch / 'build' / name, case_dir / 'build' / name)
        # Include the identities checked above, even when no mode source manifest
        # explicitly listed them. Source records retain their original names.
        metadata = authority['metadata'] | {p for p in authority['view']
                                          if p.name in ('view.json', 'sources.lock.json',
                                                        'source-layout.json')}
        for path in sorted(metadata):
            freeze(path, case_dir / 'artifacts' / str(len(archived)))
        while queue:
            manifest = queue.pop(0)
            if manifest in visited:
                continue
            visited.add(manifest)
            frozen = case_dir / archived[str(manifest)]['file']
            cwd = roots[MANIFEST_BASES[manifest.name]]
            artifact_manifest = manifest in artifact_manifests
            for path, expected in manifest_records(frozen, cwd, scratch, cache_roots, authority,
                                                   artifact_manifest):
                freeze(path, case_dir / 'artifacts' / str(len(archived)), expected,
                       artifact_manifest)
                relative = archive_relative(path, scratch, cache_roots)
                if relative is not None:
                    frozen_alias(case_dir / archived[str(path)]['file'], case_dir / relative)
        if (scratch / 'build/xdev-ext-e2-mode.txt').exists():
            for name in IMAGE_NAMES:
                if (case_dir / 'images' / name).exists():
                    frozen_alias(case_dir / 'images' / name, case_dir / name)
            freeze_e2_manifest(case_dir, scratch, cache_roots, archived,
                               authority, Path(source_root))
    finally:
        # Partial failure archives are useful evidence, never a success verdict.
        write_json(case_dir / 'archived-artifacts.json', archived)
        hashes = {str(path.relative_to(case_dir)): digest(path)
                  for path in sorted(tree_files(case_dir))}
        write_json(case_dir / 'archive-files.json', hashes)


def command_paths(command, scratch, native_root):
    require(isinstance(command, list) and command and
            all(isinstance(arg, str) and '\x00' not in arg for arg in command),
            'command must be a nonempty argv list')
    for flag, expected in (('--scratch', scratch), ('--source', native_root)):
        values = []
        for index, argument in enumerate(command):
            if argument == flag:
                require(index + 1 < len(command), 'missing command path: ' + flag)
                values.append(command[index + 1])
            elif argument.startswith(flag + '='):
                values.append(argument[len(flag) + 1:])
        require(len(values) == 1 and values[0] == str(expected),
                'command must bind exactly one ' + flag + ' to the explicit root')


def run_command(command: list[str], scratch: Path, case_dir: Path,
                source_root: Path, native_root: Path) -> dict:
    scratch, case_dir = case_location(scratch, case_dir)
    source_root, native_root = real_path(source_root), real_path(native_root)
    require(not case_dir.exists(), 'case archive already exists')
    command_paths(command, scratch, native_root)
    authority = source_authority(source_root, native_root)
    approved_cache_roots(scratch)
    case_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    evidence = scratch / 'evidence'
    if evidence.exists() or evidence.is_symlink():
        list(tree_files(evidence))
        shutil.rmtree(evidence)
    started = time.time()
    receipt = dict(command=command, source_root=str(source_root), native_root=str(native_root),
                   source_commit=authority['revision'],
                   started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                   scope='KVM software correctness only; no physical DMA/performance claim')
    if (scratch / 'debug-build-cache.json').exists():
        receipt['build_cache'] = read_json(scratch / 'debug-build-cache.json')
        require(receipt['build_cache'].get('status') == 'CACHE_ONLY_NOT_PASS',
                'invalid cache receipt status')
    try:
        write_json(case_dir / 'command-started.json',
                   dict(command=command, started_utc=receipt['started_utc']))
        with (case_dir / 'command.log').open('xb') as log:
            try:
                receipt['command_exit'] = subprocess.run(command, stdout=log,
                                                        stderr=subprocess.STDOUT,
                                                        check=False).returncode
            except OSError as error:
                receipt.update(command_exit=127, launch_error=str(error))
    finally:
        receipt['duration_seconds'] = time.time() - started
        if 'command_exit' in receipt:
            (case_dir / 'command.exit').write_text(str(receipt['command_exit']) + '\n')
        write_json(case_dir / 'receipt.json', receipt)
        archive_case(scratch, case_dir, source_root, native_root)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    run = sub.add_parser('run')
    for option in ('scratch', 'case-dir', 'source-root', 'native-root'):
        run.add_argument('--' + option, required=True, type=Path)
    run.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    try:
        receipt = run_command(command, args.scratch, args.case_dir,
                              args.source_root, args.native_root)
    except (ValueError, OSError, KeyError, TypeError) as error:
        print('archive error: ' + str(error), file=sys.stderr)
        return 1
    result = receipt['command_exit']
    return result if result >= 0 else 128 - result


if __name__ == '__main__':
    sys.exit(main())
