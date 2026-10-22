#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Fill a project overlay from an exact public upstream Git snapshot.

Archives are streamed twice: first to check conflicts and paths, then to fill
missing files. No second upstream working tree or archive file is created.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile


class PreparationError(Exception):
    """Source identity, conflict, or archive safety check failed."""


REQUIRED = {
    'linux': ('Makefile', 'Kconfig', 'scripts/Makefile.build', 'include/linux/types.h'),
    'nvidia': ('Makefile', 'kernel-open/Makefile', 'kernel-open/Kbuild'),
}


def run_git(directory, *args):
    result = subprocess.run(['git', '-C', str(directory), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise PreparationError(result.stderr.decode(errors='replace').strip())
    return result.stdout


def safe_name(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or any(p in ('..', '.git') for p in path.parts):
        raise PreparationError(f'Unsafe archive path: {name!r}')
    if str(path) in ('', '.'):
        raise PreparationError(f'Unsafe archive path: {name!r}')
    return path


def safe_parents(destination, relative):
    """Never traverse an existing symlink, even if its target is in-tree."""
    if destination.is_symlink():
        raise PreparationError(f'Symlink component directory: {destination}')
    current = destination
    for part in relative.parts[:-1]:
        current = current / part
        if current.is_symlink() or (current.exists() and not current.is_dir()):
            raise PreparationError(f'Unsafe parent path: {current}')


def safe_link(relative, target):
    if not target or PurePosixPath(target).is_absolute():
        raise PreparationError(f'Unsafe symlink: {relative} -> {target}')
    parts = list(relative.parts[:-1])
    for part in PurePosixPath(target).parts:
        if part == '..':
            if not parts:
                raise PreparationError(f'Escaping symlink: {relative} -> {target}')
            parts.pop()
        elif part not in ('', '.'):
            if part == '.git':
                raise PreparationError(f'Unsafe symlink: {relative} -> {target}')
            parts.append(part)


def validate_link_graph(links, destination):
    """Resolve all archive links together, including links listed later."""
    for origin in links:
        pending = list(PurePosixPath(origin).parts)
        resolved = []
        hops = 0
        while pending:
            part = pending.pop(0)
            if part in ('', '.'):
                continue
            if part == '..':
                if not resolved:
                    raise PreparationError(f'Escaping symlink chain: {origin}')
                resolved.pop()
                continue
            candidate = '/'.join(resolved + [part])
            target = links.get(candidate)
            if target is None and (destination / candidate).is_symlink():
                target = os.readlink(destination / candidate)
            if target is None:
                resolved.append(part)
                continue
            hops += 1
            if hops > 40 or PurePosixPath(target).is_absolute():
                raise PreparationError(f'Unsafe symlink chain: {origin}')
            pending = list(PurePosixPath(target).parts) + pending


def digest(stream):
    value = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        value.update(block)
    return value.digest()


def process_archive(archive, destination, overlay, replace, write):
    """Validate a streamed archive; optionally install non-overlay entries."""
    symlinks = set()
    links = {}
    required_bytes = 4096  # Source marker and rounding allowance.
    block = max(4096, os.statvfs(destination).f_frsize)
    for member in archive:
        # r| streams payloads but still caches TarInfo objects by default.
        # We use explicit members and never resolve files through that cache.
        archive.members.clear()
        relative = safe_name(member.name)
        name = str(relative)
        safe_parents(destination, relative)
        if any(str(parent) in symlinks for parent in relative.parents):
            raise PreparationError(f'Archive traverses symlink: {name}')
        if not (member.isdir() or member.isfile() or member.issym()):
            raise PreparationError(f'Unsupported archive entry: {name}')
        if member.issym():
            safe_link(relative, member.linkname)
            symlinks.add(name)
        if name in overlay:
            continue
        if member.issym():
            links[name] = member.linkname
        target = destination / name
        exists = target.exists() or target.is_symlink()
        if member.isdir():
            if not exists:
                required_bytes += block
            if exists and (target.is_symlink() or not target.is_dir()):
                raise PreparationError(f'Base directory conflict: {name}')
            if write:
                target.mkdir(parents=True, exist_ok=True)
            continue
        if exists and target.is_dir() and not target.is_symlink():
            raise PreparationError(f'Base directory conflict: {name}')
        same = False
        source = archive.extractfile(member) if member.isfile() else None
        if exists:
            if member.issym():
                same = target.is_symlink() and os.readlink(target) == member.linkname
            elif target.is_file() and not target.is_symlink() and not (write and replace):
                with target.open('rb') as current:
                    same = digest(current) == digest(source)
                same = same and bool(target.stat().st_mode & 0o111) == bool(member.mode & 0o111)
                source = None  # The archive stream has been consumed.
            if not same and not replace:
                raise PreparationError(f'Base file conflict: {name}; preserve it or use --replace-base')
        if not same or replace:
            # Conservative budget: each replacement can need a temporary sibling.
            required_bytes += ((member.size + block - 1) // block) * block if member.isfile() else block
        if same or not write:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        safe_parents(destination, relative)
        if member.issym():
            # A temporary sibling permits atomic replacement without following a leaf link.
            fd, temporary = tempfile.mkstemp(prefix='.xdev-ext-', dir=target.parent)
            os.close(fd)
            os.unlink(temporary)
            try:
                os.symlink(member.linkname, temporary)
                os.replace(temporary, target)
            finally:
                if os.path.lexists(temporary):
                    os.unlink(temporary)
        else:
            # In replace mode write directly from this pass; preflight already
            # checked conflicts without storing a full archive.
            if source is None:
                raise PreparationError(f'Changed base file needs replacement data: {name}')
            fd, temporary = tempfile.mkstemp(prefix='.xdev-ext-', dir=target.parent)
            try:
                with os.fdopen(fd, 'wb') as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                os.chmod(temporary, 0o755 if member.mode & 0o111 else 0o644)
                os.replace(temporary, target)
            finally:
                if os.path.lexists(temporary):
                    os.unlink(temporary)

    validate_link_graph(links, destination)
    return required_bytes


def archive_pass(cache, commit, destination, overlay, replace, write):
    # stderr goes to a small temporary stream so a Git failure cannot deadlock
    # against a full pipe while the archive reader waits for EOF.
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(['git', '-C', str(cache), 'archive', '--format=tar', commit],
                                   stdout=subprocess.PIPE, stderr=errors)
        try:
            with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
                required_bytes = process_archive(archive, destination, overlay, replace, write)
        except BaseException:
            process.kill()
            process.wait()
            raise
        finally:
            process.stdout.close()
        if process.wait():
            errors.seek(0)
            raise PreparationError(errors.read().decode(errors='replace'))
        return required_bytes


def prepare(root, component, cache, check=False, replace=False):
    lock = json.loads((root / 'sources.lock.json').read_text())
    if lock.get('schema') != 1:
        raise PreparationError('Unsupported sources.lock.json schema')
    spec = lock['components'][component]
    commit, ref, url = spec['commit'], spec['ref'], spec['url']
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise PreparationError('Pinned commit must be a complete lowercase SHA-1')
    if not ref.startswith('refs/') or any(c.isspace() for c in ref):
        raise PreparationError('Pinned ref must be a fully qualified Git ref')
    relative = safe_name(spec['path'])
    if len(relative.parts) != 1:
        raise PreparationError('Component path must be one repository-root directory')
    destination = root / str(relative)
    safe_parents(root, relative / 'placeholder')
    marker = root / 'build' / 'source-state' / f'{component}.json'
    receipt = {'schema': 1, 'component': component, 'url': url, 'ref': ref,
               'commit': commit, 'path': str(relative)}
    if check:
        if not marker.is_file() or json.loads(marker.read_text()) != receipt:
            raise PreparationError('Missing or mismatched source marker; run source preparation')
        for name in REQUIRED[component]:
            path = safe_name(name)
            safe_parents(destination, path)
            if not (destination / name).is_file() or (destination / name).is_symlink():
                raise PreparationError(f'Missing required source file: {name}')
        print(f'{component}: source marker and required files match {commit}')
        return
    tracked = run_git(root, 'ls-files', '-z', '--', str(relative) + '/')
    prefix = str(relative) + '/'
    overlay = {os.fsdecode(p)[len(prefix):] for p in tracked.split(b'\0') if p}
    cache.mkdir(parents=True, exist_ok=True)
    repository = cache / f'{component}.git'
    if repository.is_symlink():
        raise PreparationError('Cache repository must not be a symlink')
    if not repository.exists():
        repository.mkdir()
        run_git(repository, 'init', '--bare', '-q')
    # Fetch the named ref on every preparation run, then require the pinned
    # commit. Cached possession of an old commit cannot hide a moved tag.
    run_git(repository, 'fetch', '--no-tags', '--depth=1', url, ref)
    actual = run_git(repository, 'rev-parse', '--verify', 'FETCH_HEAD^{commit}').decode().strip()
    if actual != commit:
        raise PreparationError(f'Pinned commit mismatch: expected {commit}, ref resolves to {actual}')
    destination.mkdir(exist_ok=True)
    required_bytes = archive_pass(repository, commit, destination, overlay, replace, False)
    free_bytes = shutil.disk_usage(destination).free
    if required_bytes > free_bytes:
        raise PreparationError(f'Insufficient space: need at least {required_bytes} bytes, have {free_bytes}')
    archive_pass(repository, commit, destination, overlay, replace, True)
    for name in REQUIRED[component]:
        if not (destination / name).is_file():
            raise PreparationError(f'Missing required source file: {name}')
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'{component}: prepared {destination.name} at {commit}; preserved {len(overlay)} overlay files')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component', required=True, choices=sorted(REQUIRED))
    parser.add_argument('--cache', type=Path, help='Git-object cache (default: build/upstream)')
    parser.add_argument('--check', action='store_true', help='Check local marker and required files without fetching')
    parser.add_argument('--replace-base', action='store_true', help='Replace conflicting untracked upstream files')
    options = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        prepare(root, options.component, options.cache or root / 'build' / 'upstream',
                options.check, options.replace_base)
    except (PreparationError, OSError, ValueError, KeyError, tarfile.TarError) as error:
        print(f'prepare_sources: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
