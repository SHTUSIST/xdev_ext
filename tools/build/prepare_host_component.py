#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Add qualified NVIDIA upstream-only inputs to an isolated host source view.

This is explicit and offline: prepare_sources.py must first cache the pinned
component. Authored overlays remain owned by source-layout.json. Linux full
headers are deliberately not admitted to host contracts.
"""
import argparse
import json
import shutil
from pathlib import Path
import sys

for _parent in Path(__file__).resolve().parents:
    if (_parent / 'tools/layout.py').is_file():
        sys.path.insert(0, str(_parent / 'tools'))
        break
from layout import (canonical_root, load_layout, materialize_view, view_lock,
                    safe_file, isolated_file, atomic_json, upstream_entries, LayoutError)
from prepare_sources import archive_pass


def prepare(repo, component='nvidia', output=None, cache=None):
    if component != 'nvidia':
        raise LayoutError('Only explicit NVIDIA host augmentation is supported')
    repo = canonical_root(repo)
    layout = load_layout(repo)
    lock = json.loads(safe_file(repo, layout.manifest.get('dependency_lock',
                                                        'third_party/sources.lock.json')).read_text())
    spec = lock['components'][component]
    repository = (Path(cache) if cache is not None else repo / 'build/upstream') / (component + '.git')
    repository = repository.absolute()
    expected = upstream_entries(layout, component, repository, spec['commit'])
    # Full assembly is mutable. Its marker and files are deliberately not read:
    # input membership and content come from the immutable pinned Git objects.
    view = materialize_view(repo, output)
    marker = view.root / 'view.json'
    with view_lock(view.root):
        state = json.loads(isolated_file(view.root, 'view.json', True).read_text())
        previous = state.get('upstream_inputs', {}).get(component)
        for logical in expected:
            target = isolated_file(view.root, logical)
            if target.is_dir():
                raise LayoutError('Host augmentation directory conflict: ' + logical)
            if target.exists() and (previous is None or logical not in previous['files']):
                raise LayoutError('Unregistered host input exists: ' + logical)
        destination = view.nvidia
        destination.mkdir(parents=True, exist_ok=True)
        overlay = {native for comp, native in layout.by_native if comp == component}
        required = archive_pass(repository, spec['commit'], destination, overlay, False, False)
        if required > shutil.disk_usage(destination).free:
            raise LayoutError('Insufficient space for qualified host upstream inputs')
        archive_pass(repository, spec['commit'], destination, overlay, False, True)
        state.setdefault('upstream_inputs', {})[component] = dict(
            kind='pinned-git-upstream-only-copies', **spec,
            git_cache=str(repository), files=expected)
        atomic_json(marker, state)
    return dict(component=component, commit=spec['commit'], output=str(view.root),
                upstream_only_files=len(expected))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component', choices=('nvidia',), required=True)
    parser.add_argument('--root', type=Path, default=canonical_root(Path(__file__)))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--cache', type=Path, help='prepared Git-object cache root (default: build/upstream)')
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.root, args.component, args.output, args.cache), sort_keys=True))
    except (LayoutError, OSError, KeyError, ValueError) as error:
        parser.exit(1, f'prepare_host_component: {error}\n')


if __name__ == '__main__':
    main()
