#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host checks of cross-device features whose main evidence is a KVM guest.

Runs, with durable per-command logs and a manifest, the host suites that no
other host.yml step reaches:

- the host 1 NVMe READ -> XDOMAIN -> host 2 NVMe WRITE chain composition under
  ASan/UBSan and on a dma-buf peer pool (check_xdomain_host.py runs its plain
  provider-pool form), and the XDOMAIN dma-buf requester units under
  ASan/UBSan (check_xdomain_host.py runs them plain);
- the whole-disk oracle self-tests of the attacker-brought program isolation
  and dma-buf device DMA guest tests;
- the ordered-stage abort after a program retraction (detach_generation).
  It is also in the "Mechanism source contracts" loop, which stops at an
  earlier failing command before it reaches that loop.

Host software only: no device, guest, DMA or timing claim.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

for _parent in Path(__file__).resolve().parents:
    if (_parent / 'tools/layout.py').is_file():
        sys.path.insert(0, str(_parent / 'tools'))
        break
from layout import canonical_root, materialize_view

CANONICAL_ROOT = canonical_root(Path(__file__))
VIEW = materialize_view(CANONICAL_ROOT).root
LIFECYCLE = 'kernel/tools/testing/selftests/xdev_ext_mech/core_lifecycle/'

REJECT_OUTPUT = re.compile(
    r"^\s*(?:not ok(?:\s|$)|(?:FAIL|FAILED|ERROR|UNAVAILABLE|SKIP)(?:[:(\s]|$))"
    r"|#\s*SKIP\b|\.\.\.\s+skipped\b|^OK\s*\(skipped=",
    re.IGNORECASE | re.MULTILINE,
)


def commands(out):
    """(name, argv, cwd, extra environment); explicit, so none silently disappears."""
    root = str(CANONICAL_ROOT)
    chain = 'tests/network/xdomain/chain/run.py'
    requester = 'tests/network/xdomain/dmabuf_requester/run.py'
    return (
        ('xdomain-chain-sanitize',
         ['python3', chain, '--source-root', root, '--output', str(out / 'chain-sanitize'), '--sanitize'],
         CANONICAL_ROOT, {'ASAN_OPTIONS': 'detect_leaks=0'}),
        ('xdomain-chain-dmabuf-pool',
         ['python3', chain, '--source-root', root, '--output', str(out / 'chain-dmabuf'), '--pool', 'dmabuf'],
         CANONICAL_ROOT, {}),
        ('xdomain-dmabuf-requester-sanitize',
         ['python3', requester, '--source-root', root, '--output', str(out / 'dmabuf-requester-sanitize'),
          '--sanitize'],
         CANONICAL_ROOT, {}),
        ('attack-isolation-oracle',
         ['python3', '-I', 'tests/core/program_instances/attack/attack_validate_test.py'],
         CANONICAL_ROOT, {}),
        ('dmabuf-device-dma-oracle',
         ['python3', '-I', 'tests/core/peer_dmabuf/device_dma/validate_test.py'],
         CANONICAL_ROOT, {}),
        ('retraction-abort-detach-generation',
         ['python3', LIFECYCLE + 'detach_generation_test.py'],
         VIEW, {}),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log-dir', required=True, type=Path)
    args = parser.parse_args()
    log_dir = args.log_dir.resolve()
    log_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    records = []
    for index, (name, argv, cwd, extra) in enumerate(commands(log_dir / 'outputs')):
        header = f"NAME {name}\nCWD {cwd}\nCOMMAND {shlex.join(argv)}\n"
        print(header, end='', flush=True)
        try:
            result = subprocess.run(argv, cwd=cwd, text=True, env={**os.environ, **extra},
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    timeout=900)
            output, returncode = result.stdout, result.returncode
            reason = 'failed or skipped output' if REJECT_OUTPUT.search(output) else ''
        except subprocess.TimeoutExpired as error:
            raw = error.stdout or b''
            output = raw.decode(errors='replace') if isinstance(raw, bytes) else raw
            output += '\nFAIL: host check exceeded 900 seconds\n'
            returncode, reason = 124, 'timeout'
        except OSError as error:
            output = f"FAIL: cannot execute command: {error}\n"
            returncode, reason = 126, 'command unavailable'
        failed = returncode != 0 or bool(reason)
        footer = f"EXIT {returncode} STATUS {'FAIL' if failed else 'PASS'}"
        if reason:
            footer += ' REASON ' + reason
        footer += '\n'
        path = log_dir / f"{index:02d}-{name}.log"
        path.write_text(header + output + footer)
        print(output, end='' if output.endswith('\n') else '\n', flush=True)
        print(footer, end='', flush=True)
        records.append(dict(name=name, argv=argv, cwd=str(cwd), environment=extra,
                            returncode=returncode, status='fail' if failed else 'pass',
                            reason=reason, log=path.name))
    failed = any(row['status'] == 'fail' for row in records)
    (log_dir / 'manifest.json').write_text(json.dumps(dict(
        scope='host-software', hardware='none', status='fail' if failed else 'pass',
        commands=records), indent=2) + '\n')
    print(f"CROSS-DEVICE HOST CHECKS={'FAIL' if failed else 'PASS'} commands={len(records)}", flush=True)
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
