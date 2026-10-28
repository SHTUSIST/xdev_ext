#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute a canonical source entry in an isolated native/logical copy view.

Examples: tools/run.py tests/core/session/refs_suite.py
          tools/run.py --cwd src/cli/mechanism make lib BUILD_DIR=/tmp/lib
          tools/run.py tools/build/tp.py -- --help
"""
import argparse
import os
import shlex
from pathlib import Path
import subprocess
import sys
from layout import canonical_root, load_layout, materialize_view, LayoutError


def mapped(layout, value):
    path = Path(value)
    if path.is_absolute():
        try:
            value = path.relative_to(layout.repo).as_posix()
        except ValueError:
            return value
    if value in layout.by_source:
        return layout.logical(value)
    makefile = value.rstrip('/') + '/Makefile'
    if makefile in layout.by_source:
        return str(Path(layout.logical(makefile)).parent)
    # Directories need not be manifest entries, but every member must agree.
    prefix = value.rstrip('/') + '/'
    candidates = []
    for source, logical in layout.by_source.items():
        if source.startswith(prefix):
            tail = source[len(prefix):]
            if logical.endswith('/' + tail):
                candidates.append(logical[:-len(tail)].rstrip('/'))
    if candidates and len(set(candidates)) == 1:
        return candidates[0]
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--view', type=Path)
    parser.add_argument('--cwd', help='canonical directory to execute within')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command
    if command[:1] == ['--']:
        command = command[1:]
    if not command:
        parser.error('a canonical entry or command is required')
    try:
        layout = load_layout(args.root)
        view = materialize_view(layout.repo, args.view)
        command = [mapped(layout, arg) for arg in command]
        if command[0].endswith('.py'):
            command.insert(0, sys.executable)
        elif command[0].endswith('.sh'):
            script = view.root / command[0]
            with script.open('rb') as stream:
                shebang = stream.readline(4096).decode().strip()
            if not shebang.startswith('#!'):
                raise LayoutError('Shell entry has no declared interpreter: ' + command[0])
            command = shlex.split(shebang[2:]) + command
        # Optional -- separates entry options from runner options, not child args.
        if '--' in command and command.index('--') == 2:
            command.remove('--')
        cwd = view.root / mapped(layout, args.cwd) if args.cwd else view.root
        environment = dict(os.environ, XDEV_EXT_CANONICAL_ROOT=str(layout.repo),
                           XDEV_EXT_SOURCE_VIEW=str(view.root))
        return subprocess.run(command, cwd=cwd, env=environment).returncode
    except (LayoutError, OSError) as error:
        parser.exit(1, f'run: {error}\n')


if __name__ == '__main__':
    raise SystemExit(main())
