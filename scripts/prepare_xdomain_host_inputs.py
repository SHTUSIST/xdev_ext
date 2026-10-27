#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare only the pinned upstream NHI register header for host contracts.

Project production sources stay in the overlay. This does not assemble a kernel
or rewrite existing files; authentic upstream bytes retain their license.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from urllib.error import URLError
from urllib.request import urlopen

LINUX_COMMIT = '89be9a83ccf1f88522317ce02f854f30d6115c41'
NHI_SHA256 = '5d2c5a71004f7b0cc2ecf2d95628cb8ea679b88d599f092d57983a0125ceb7d5'
NHI_PATH = Path('kernel/drivers/thunderbolt/nhi_regs.h')
MAX_BYTES = 65536
DOWNLOAD_TIMEOUT = 20


class PreparationError(Exception):
    """Input pin, transfer, or destination qualification failed."""


def verify(data):
    if len(data) > MAX_BYTES:
        raise PreparationError('NHI input exceeds the 65536-byte size limit')
    if hashlib.sha256(data).hexdigest() != NHI_SHA256:
        raise PreparationError('NHI input SHA256 mismatch; refusing source replacement')


def check_destination(root):
    current = root
    for part in NHI_PATH.parts:
        current = current / part
        if current.is_symlink():
            raise PreparationError('Symlink NHI input path is not allowed: ' + str(current))
        if current.exists() and (current != root / NHI_PATH) and not current.is_dir():
            raise PreparationError('Non-directory NHI input parent: ' + str(current))
    if current.exists() and not current.is_file():
        raise PreparationError('Existing NHI destination is not a regular file: ' + str(current))
    return current


def prepare(root):
    root = Path(root).resolve()
    try:
        lock = json.loads((root / 'sources.lock.json').read_text())
        linux = lock['components']['linux']
        valid = (lock['schema'] == 1 and linux['commit'] == LINUX_COMMIT and
                 linux['url'] == 'https://github.com/torvalds/linux.git' and
                 linux['path'] == 'kernel')
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise PreparationError('Missing or invalid sources.lock.json: ' + str(error)) from error
    if not valid:
        raise PreparationError('Linux source lock changed; requalify the NHI commit and SHA256')
    target = check_destination(root)
    url = ('https://raw.githubusercontent.com/torvalds/linux/' + LINUX_COMMIT +
           '/drivers/thunderbolt/nhi_regs.h?host-input=1')
    receipt = dict(path=str(NHI_PATH), commit=LINUX_COMMIT, sha256=NHI_SHA256, url=url)
    if target.exists():
        with target.open('rb') as stream:
            verify(stream.read(MAX_BYTES + 1))
        return dict(receipt, status='verified-existing', bytes=target.stat().st_size)
    try:
        with urlopen(url, timeout=DOWNLOAD_TIMEOUT) as response:
            data = response.read(MAX_BYTES + 1)
    except (OSError, URLError) as error:
        raise PreparationError('NHI input download failed: ' + str(error)) from error
    verify(data)
    # Validate before creating any directories, and never follow an existing
    # symlink or open an existing author file for writing.
    check_destination(root)
    target.parent.mkdir(parents=True, exist_ok=True)
    check_destination(root)
    with target.open('xb') as stream:
        stream.write(data)
    return dict(receipt, status='prepared', bytes=len(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        receipt = prepare(args.root)
    except (PreparationError, OSError) as error:
        print('FAIL: ' + str(error), file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
