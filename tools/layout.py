#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Canonical sources, native overlay paths and isolated logical workspaces.

Only this module interprets source-layout.json. Generated views are ordinary
copies, never Git checkouts; revision reads always address the canonical Git.
"""
import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile

PREFIXES = {'linux': 'kernel', 'nvidia': 'gpu'}


class LayoutError(ValueError):
    pass


def relative(value):
    if not isinstance(value, str) or not value or '\\' in value or any(ord(c) < 32 for c in value):
        raise LayoutError(f'Invalid relative path: {value!r}')
    path = PurePosixPath(value)
    if path.is_absolute() or any(x in ('', '.', '..', '.git') for x in value.split('/')):
        raise LayoutError(f'Unsafe relative path: {value!r}')
    return path


def safe_file(root, name, required=True):
    current = Path(root)
    if current.exists() and not current.is_dir():
        raise LayoutError(f'Non-directory root: {current}')
    parts = relative(name).parts
    for index, part in enumerate(parts):
        current /= part
        if current.is_symlink():
            raise LayoutError(f'Symlink path is not allowed: {current}')
        if index < len(parts) - 1 and current.exists() and not current.is_dir():
            raise LayoutError(f'Non-directory parent: {current}')
    if required and not current.is_file():
        raise LayoutError(f'Missing regular source: {current}')
    return current


def git(repo, *args):
    p = subprocess.run(['git', '-C', str(repo), *args], capture_output=True)
    if p.returncode:
        raise LayoutError(p.stderr.decode(errors='replace').strip())
    return p.stdout


def canonical_root(path=None):
    path = Path(path or __file__).absolute()
    if path.is_file():
        path = path.parent
    for parent in (path, *path.parents):
        marker = parent / 'view.json'
        if marker.is_file():
            receipt = json.loads(marker.read_text())
            if receipt.get('kind') == 'host-source-view':
                return Path(receipt['canonical_root']).resolve()
        if (parent / 'source-layout.json').is_file():
            return parent.resolve()
    raise LayoutError(f'No canonical layout root for {path}')


@dataclass
class Layout:
    repo: Path
    manifest: dict
    revision: str | None = None

    def __post_init__(self):
        if self.manifest.get('schema') != 1 or not isinstance(self.manifest.get('files'), list):
            raise LayoutError('Unsupported source-layout.json schema')
        self.by_source, self.by_native, self.by_logical = {}, {}, {}
        for entry in self.manifest['files']:
            source = str(relative(entry['source']))
            # Authored directory names are lowercase identifiers. The two
            # established metadata/license directory names are fixed exceptions;
            # vendor-native names are checked separately below the vendor root.
            parts = PurePosixPath(source).parts[:-1]
            if any((part not in ('LICENSES', 'ISSUE_TEMPLATE') and
                    not re.fullmatch(r'[a-z0-9_.+-]+', part)) or
                   re.search(r'20[0-9]{2}[-_]?[01][0-9][-_]?[0-3][0-9]', part)
                   for part in parts):
                raise LayoutError(f'Unstable canonical directory: {source}')
            if source in self.by_source:
                raise LayoutError(f'Duplicate canonical source: {source}')
            if 'component' in entry:
                component = entry['component']
                if component not in PREFIXES or 'logical_path' in entry:
                    raise LayoutError(f'Invalid component mapping: {entry}')
                native = str(relative(entry['native_path']))
                key = (component, native)
                if key in self.by_native:
                    raise LayoutError(f'Duplicate native destination: {key}')
                self.by_native[key] = source
                logical = PREFIXES[component] + '/' + native
            else:
                logical = str(relative(entry['logical_path']))
            if logical in self.by_logical:
                raise LayoutError(f'Duplicate logical destination: {logical}')
            self.by_source[source] = logical
            self.by_logical[logical] = source
        # Detect file/parent collisions before any destination is written.
        names = set(self.by_logical)
        for name in names:
            if any(str(p) in names for p in PurePosixPath(name).parents):
                raise LayoutError(f'Logical file/directory collision: {name}')
        relative(self.manifest.get('dependency_lock', 'third_party/sources.lock.json'))

    def validate_sources(self):
        for source in self.by_source:
            safe_file(self.repo, source)

    def source(self, component, native):
        key = (component, str(relative(native)))
        if key not in self.by_native:
            raise LayoutError(f'No canonical source for {key}')
        return self.repo / self.by_native[key]

    def destination(self, source):
        source = str(relative(source))
        for (component, native), candidate in self.by_native.items():
            if candidate == source:
                return component, native
        raise LayoutError(f'Not an upstream overlay source: {source}')

    def logical(self, source):
        return self.by_source[str(relative(source))]

    def read_source(self, component, native, revision=None):
        revision = revision if revision is not None else self.revision
        return read_source(self.repo, component, native, revision)


def load_layout(repo, revision=None):
    repo = canonical_root(repo)
    data = git(repo, 'show', f'{revision}:source-layout.json') if revision else (repo / 'source-layout.json').read_bytes()
    return Layout(repo, json.loads(data), revision)


def read_source(repo, component, native, revision=None):
    """Read this revision's mapping, including pre-layout schema1 history."""
    repo = canonical_root(repo)
    native = str(relative(native))
    if component not in PREFIXES:
        raise LayoutError(f'Unknown component: {component}')
    if revision is None:
        layout = load_layout(repo)
        source = layout.source(component, native)
        if not source.exists():
            return read_source(repo, component, native, 'HEAD')
        return safe_file(repo, source.relative_to(repo).as_posix()).read_bytes()
    # Resolve revision first: invalid revisions must never fall back to worktree.
    commit = git(repo, 'rev-parse', '--verify', revision + '^{commit}').decode().strip()
    has_manifest = subprocess.run(['git', '-C', str(repo), 'cat-file', '-e',
                                   commit + ':source-layout.json'], capture_output=True).returncode == 0
    if has_manifest:
        layout = load_layout(repo, commit)
        source = layout.source(component, native).relative_to(repo).as_posix()
    else:
        lock = json.loads(git(repo, 'show', commit + ':sources.lock.json'))
        if lock.get('schema') != 1:
            raise LayoutError('Historical revision has no supported source layout')
        source = str(relative(lock['components'][component]['path'])) + '/' + native
    return git(repo, 'show', commit + ':' + source)


def read_native(root, component, native, revision=None):
    """Explicit native fixture or canonical/view root, with sparse HEAD fallback."""
    root = Path(root).resolve()
    try:
        repo = canonical_root(root)
    except LayoutError:
        if revision:
            prefix = git(root, 'rev-parse', '--show-prefix').decode().strip()
            top = git(root, 'rev-parse', '--show-toplevel').decode().strip()
            return git(top, 'show', revision + ':' + prefix + str(relative(native)))
        path = safe_file(root, native, required=False)
        if path.is_file():
            return path.read_bytes()
        prefix = git(root, 'rev-parse', '--show-prefix').decode().strip()
        top = git(root, 'rev-parse', '--show-toplevel').decode().strip()
        return git(top, 'show', 'HEAD:' + prefix + str(relative(native)))
    return read_source(repo, component, native, revision)


def provenance(root, revision=None, native=False):
    """Require a real canonical checkout, or an explicitly selected native tree.

    An archive's manifest is a layout contract, not evidence that the archive
    belongs to an enclosing Git repository. Views must point to a real checkout.
    """
    try:
        repo = canonical_root(root)
    except LayoutError:
        if not native:
            raise
        repo = Path(git(root, 'rev-parse', '--show-toplevel').decode().strip()).resolve()
    actual = Path(git(repo, 'rev-parse', '--show-toplevel').decode().strip()).resolve()
    if actual != repo:
        raise LayoutError('Canonical source directory is not its own Git checkout')
    commit = git(repo, 'rev-parse', '--verify', (revision or 'HEAD') + '^{commit}').decode().strip()
    return {'canonical_root': str(repo), 'revision': commit,
            'dirty': bool(git(repo, 'status', '--porcelain')) if revision is None else False,
            'source_unit_namespace': 'logical-native-view' if not native else 'explicit-native-tree'}


@dataclass
class View:
    root: Path
    source_origins: dict

    @property
    def kernel(self):
        return self.root / 'kernel'

    @property
    def nvidia(self):
        return self.root / 'gpu'


def output_path(repo, output, default):
    output = Path(output) if output is not None else repo / default
    output = output.absolute()
    # No symlink parents, canonical trees, Git metadata or upstream cache.
    for parent in (output, *output.parents):
        if parent.is_symlink():
            raise LayoutError(f'Symlink output path: {parent}')
    resolved = output.resolve()
    forbidden = [repo / p for p in ('src', 'tools', 'tests', 'examples', 'docs', '.git', 'third_party', 'build/upstream')]
    if resolved == repo or any(resolved == p or p in resolved.parents for p in forbidden):
        raise LayoutError(f'Output overlaps canonical sources/cache: {output}')
    return resolved


@contextmanager
def view_lock(output):
    output.parent.mkdir(parents=True, exist_ok=True)
    lock = output.parent / ('.' + output.name + '.lock')
    if lock.is_symlink():
        raise LayoutError(f'Symlink lock: {lock}')
    with lock.open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def _atomic_copy(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.layout-', dir=destination.parent)
    os.close(fd)
    try:
        shutil.copy2(source, temp)
        os.replace(temp, destination)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def isolated_file(root, name, required=False):
    target = safe_file(root, name, required)
    if target.exists() and target.stat().st_nlink != 1:
        raise LayoutError(f'Hardlinked output is not an isolated copy: {target}')
    return target


def atomic_json(destination, value):
    fd, temporary = tempfile.mkstemp(prefix='.layout-', dir=destination.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def upstream_entries(layout, component, cache, commit):
    """Qualified non-overlay members of one immutable pinned Git tree."""
    cache = Path(cache).absolute()
    for parent in (cache, *cache.parents):
        if parent.is_symlink():
            raise LayoutError(f'Symlink upstream Git cache: {parent}')
    if git(cache, 'rev-parse', '--verify', commit + '^{commit}').decode().strip() != commit:
        raise LayoutError('Pinned upstream Git object is unavailable')
    result = {}
    for row in git(cache, 'ls-tree', '-rz', '--full-tree', commit).split(b'\0'):
        if not row:
            continue
        metadata, rawname = row.split(b'\t', 1)
        mode, kind, oid = metadata.decode().split()
        native = str(relative(os.fsdecode(rawname)))
        if (component, native) in layout.by_native:
            continue
        if kind != 'blob' or mode not in ('100644', '100755'):
            raise LayoutError('Non-regular upstream view input: ' + native)
        result[PREFIXES[component] + '/' + native] = dict(blob=oid, mode=mode)
    return result


def verify_upstream_inputs(layout, output, lock, qualified):
    for component, receipt in qualified.items():
        spec = lock['components'].get(component)
        if spec is None or any(receipt.get(k) != spec.get(k) for k in ('url', 'ref', 'commit')):
            raise LayoutError('Stale host upstream augmentation: ' + component)
        if receipt.get('kind') != 'pinned-git-upstream-only-copies':
            raise LayoutError('Host upstream inputs lack immutable Git qualification')
        expected = upstream_entries(layout, component, receipt['git_cache'], spec['commit'])
        if receipt.get('files') != expected:
            raise LayoutError('Host upstream input membership differs from pinned tree')
        targets = [isolated_file(output, name, True) for name in expected]
        for target, entry in zip(targets, expected.values()):
            if bool(target.stat().st_mode & 0o111) != (entry['mode'] == '100755'):
                raise LayoutError('Host upstream executable mode differs from pinned Git input: ' + str(target))
        # This is the qualification boundary for upstream inputs, not a sweep of
        # ordinary project files: compare Git blob identity in one invocation.
        hashes = subprocess.run(['git', 'hash-object', '--no-filters', '--stdin-paths'],
                                input=''.join(str(p) + '\n' for p in targets).encode(),
                                capture_output=True)
        if hashes.returncode:
            raise LayoutError(hashes.stderr.decode(errors='replace'))
        if hashes.stdout.decode().splitlines() != [entry['blob'] for entry in expected.values()]:
            raise LayoutError('Host upstream bytes differ from pinned Git inputs')


def materialize_view(repo, output=None):
    layout = load_layout(repo)
    layout.validate_sources()
    repo = layout.repo
    output = output_path(repo, output, 'build/source-view')
    origins = dict(layout.by_logical)
    lock_path = layout.manifest.get('dependency_lock', 'third_party/sources.lock.json')
    lock = json.loads(safe_file(repo, lock_path).read_text())
    if lock.get('schema') != 2:
        raise LayoutError('Canonical dependency lock must use schema 2')
    legacy = json.loads(json.dumps(lock))
    legacy['schema'] = 1
    for name, spec in legacy['components'].items():
        spec['path'] = PREFIXES[name]
    receipt = dict(schema=1, kind='host-source-view', **provenance(repo),
                   manifest=layout.manifest, source_origins=origins)
    with view_lock(output):
        marker = output / 'view.json'
        for metadata in ('view.json', 'sources.lock.json', 'source-layout.json'):
            isolated_file(output, metadata)
        if output.exists() and not marker.is_file() and any(output.iterdir()):
            raise LayoutError(f'Existing output is not a registered source view: {output}')
        if marker.is_file():
            old = json.loads(marker.read_text())
            if old.get('kind') != 'host-source-view' or old.get('canonical_root') != str(repo):
                raise LayoutError('Source view ownership mismatch')
            verify_upstream_inputs(layout, output, lock, old.get('upstream_inputs', {}))
            if 'upstream_inputs' in old:
                receipt['upstream_inputs'] = old['upstream_inputs']
            previous = old['source_origins']
            if not set(previous).issubset(origins) or any(origins[name] != source for name, source in previous.items()):
                raise LayoutError('Logical inputs removed or remapped; choose a fresh source view output')
            for logical in set(origins) - set(previous):
                target = output / logical
                if target.exists() or target.is_symlink():
                    raise LayoutError('New logical input collides with unregistered output: ' + logical)
        # Validate every destination before writing any mapped file.
        for logical in origins:
            isolated_file(output, logical)
            if (output / logical).is_dir():
                raise LayoutError(f'View file/directory collision: {logical}')
        output.mkdir(parents=True, exist_ok=True)
        for logical, source in origins.items():
            target = output / logical
            original = repo / source
            if not target.is_file() or target.read_bytes() != original.read_bytes() or (target.stat().st_mode & 0o777) != (original.stat().st_mode & 0o777):
                _atomic_copy(original, target)
        _atomic_copy(repo / 'source-layout.json', output / 'source-layout.json')
        atomic_json(output / 'sources.lock.json', legacy)
        atomic_json(marker, receipt)
    return View(output, origins)


def assemble_overlay(layout, component, destination, previous=None):
    """Preflight all overlays, then install ordinary atomic copies."""
    entries = [(native, source) for (comp, native), source in layout.by_native.items() if comp == component]
    for native, source in entries:
        original = safe_file(layout.repo, source)
        target = safe_file(destination, native, required=False)
        if target.is_dir():
            raise LayoutError(f'Overlay directory conflict: {native}')
        if target.exists() and previous is not None and native in previous:
            actual = hashlib.sha256(target.read_bytes()).hexdigest()
            if actual != previous[native]:
                raise LayoutError(f'Locally modified assembled overlay: {native}')
    for native, source in entries:
        _atomic_copy(layout.repo / source, destination / native)
    return {native: hashlib.sha256((destination / native).read_bytes()).hexdigest() for native, _ in entries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('view', 'check', 'path'))
    parser.add_argument('source', nargs='?')
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        if args.action == 'view':
            print(materialize_view(args.root, args.output).root)
        else:
            layout = load_layout(args.root)
            layout.validate_sources()
            if args.action == 'path':
                print(layout.logical(args.source))
            else:
                print(f'Layout sources={len(layout.by_source)} valid')
    except (LayoutError, OSError, KeyError, TypeError) as error:
        parser.exit(1, f'layout: {error}\n')


if __name__ == '__main__':
    main()
