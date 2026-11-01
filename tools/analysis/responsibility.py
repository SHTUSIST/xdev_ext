#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Report responsibility by actual canonical Git path changes, without LOC claims.

Choose --head REV for a committed pair or --working-tree to include staged,
unstaged and untracked files. Renames report both source and destination roles.
Raw numstat counts describe the selected Git diff, not contribution, novelty,
efficiency, or engineering cost. Binary/untracked counts are explicitly unknown.
Categories describe path ownership, not proof of semantic responsibility.
"""
import argparse
import json
from pathlib import Path
import subprocess


def git(repo, *args):
    p = subprocess.run(['git', '-C', str(repo), *args], capture_output=True)
    if p.returncode:
        raise ValueError(p.stderr.decode(errors='replace').strip())
    return p.stdout


def category(path):
    if path.endswith('.bpf.c') or path.startswith('src/bpf/'):
        return 'BPF'
    if path.startswith('src/core/'):
        return 'core'
    if path.startswith(('src/storage/', 'src/compute/', 'src/network/')):
        return 'backend'
    if path.startswith(('examples/', 'src/lib/', 'src/cli/', 'src/frontend/')):
        return 'application'
    if path.startswith(('tests/', 'tools/', 'docs/')) or path == 'source-layout.json':
        return 'support'
    return 'other'


def report(repo, base, head, working_tree):
    base_sha = git(repo, 'rev-parse', '--verify', base + '^{commit}').decode().strip()
    head_sha = None if working_tree else git(repo, 'rev-parse', '--verify', head + '^{commit}').decode().strip()
    args = ['diff', '--no-ext-diff', '--no-textconv', '-z', '--find-renames', base_sha]
    if head_sha:
        args.append(head_sha)
    fields = git(repo, *args, '--name-status', '--').decode(errors='surrogateescape').split('\0')
    stats = git(repo, *args, '--numstat', '--').decode(errors='surrogateescape').split('\0')
    counts, j = {}, 0
    while j < len(stats) and stats[j]:
        added, deleted, path = stats[j].split('\t', 2)
        j += 1
        old_path = None
        if not path:  # -z encodes rename as counts<TAB><NUL>old<NUL>new<NUL>
            old_path, path = stats[j:j+2]
            j += 2
        binary = added == deleted == '-'
        counts[(old_path, path)] = dict(added=None if binary else int(added),
                                      deleted=None if binary else int(deleted),
                                      numstat_kind='binary' if binary else 'text')
    changes, i = [], 0
    while i < len(fields) and fields[i]:
        status, path = fields[i:i+2]
        i += 2
        old_path = None
        if status.startswith(('R', 'C')):
            old_path, path = path, fields[i]
            i += 1
        categories = sorted({category(path)} | ({category(old_path)} if old_path else set()))
        if (old_path, path) not in counts:
            raise ValueError('name-status and numstat disagree; retry with a stable working tree')
        changes.append(dict(status=status, path=path, old_path=old_path, categories=categories,
                            **counts.pop((old_path, path))))
    if counts:
        raise ValueError('numstat contains unmatched paths; retry with a stable working tree')
    if working_tree:
        for path in git(repo, 'ls-files', '--others', '--exclude-standard', '-z').decode(errors='surrogateescape').split('\0'):
            if path:
                changes.append(dict(status='?', path=path, old_path=None, categories=[category(path)],
                                    added=None, deleted=None, numstat_kind='untracked'))
    return dict(schema=1, base=base_sha, head=head_sha,
                scope='working-tree' if working_tree else 'committed-pair',
                changes=sorted(changes, key=lambda x: x['path']))


def markdown(result):
    lines = ['Paths and raw Git numstat counts do not establish contribution, novelty, efficiency, or engineering cost.', '',
             f"Base: `{result['base']}`; target: `{result['head'] or 'working-tree'}`.", '']
    for group in ('application', 'BPF', 'core', 'backend', 'support', 'other'):
        changes = [x for x in result['changes'] if group in x['categories']]
        lines.append(f'{group}:')
        if not changes:
            lines.append('- No changed paths.')
        for item in changes:
            # JSON quoting preserves tabs and newlines as visible data.
            path = json.dumps(item['path'], ensure_ascii=True)
            previous = (' from ' + json.dumps(item['old_path'], ensure_ascii=True)) if item['old_path'] else ''
            raw = (f"+{item['added']}/-{item['deleted']}" if item['numstat_kind'] == 'text'
                   else item['numstat_kind'] + '; counts unavailable')
            lines.append(f"- {item['status']}: {path}{previous} ({raw})")
        lines.append('')
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    parser.add_argument('--base', default='HEAD')
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--head')
    target.add_argument('--working-tree', action='store_true')
    parser.add_argument('--format', choices=('json', 'markdown'), default='markdown')
    args = parser.parse_args()
    try:
        result = report(args.repo, args.base, args.head, args.working_tree)
    except (OSError, ValueError) as error:
        parser.exit(1, f'responsibility: {error}\n')
    print(json.dumps(result, indent=2, ensure_ascii=True) if args.format == 'json' else markdown(result))


if __name__ == '__main__':
    main()
