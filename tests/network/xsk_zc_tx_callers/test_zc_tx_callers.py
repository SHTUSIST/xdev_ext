#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Transmit-only zero-copy AF_XDP callers get XDP mode before CREATE.

CREATE refuses a non-reliable zero-copy TX stage whose queue refuses a TX
wakeup (igb, ice, i40e, ixgbe -EINVAL; igc -ENXIO; mlx5 -ENETDOWN while no XDP
program is attached).  The CLI's rule (ctl_zc_tx_xdp): kick the TX queue
before CREATE; attach the pass program only when the kick is refused with
EINVAL, ENXIO or ENETDOWN; accept another owner's program (-EBUSY); detach
only what was attached.  This suite checks the shared rule in the redirect
helper.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get('XDEV_EXT_CANONICAL_ROOT') or HERE.parents[2])
CLI = ROOT / 'src/cli'
CC = os.environ.get('CC', 'gcc')


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def rule_run(redirect_text=None):
    """Build zc_tx_rule_test.c against the helper (or a mutated copy); (exit, output)."""
    with tempfile.TemporaryDirectory(prefix='zc-tx-rule-') as tmp:
        tmp = Path(tmp)
        source = CLI / 'xdev_ext_xsk_redirect.c'
        if redirect_text is not None:
            (tmp / 'include').mkdir()
            for header in (CLI / 'include').glob('xdev_ext_xsk_redirect*.h'):
                (tmp / 'include' / header.name).write_bytes(header.read_bytes())
            source = tmp / 'xdev_ext_xsk_redirect.c'
            source.write_text(redirect_text)
        exe = tmp / 'zc_tx_rule_test'
        built = run([CC, '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                     '-I' + str(CLI / 'include'), str(HERE / 'zc_tx_rule_test.c'),
                     str(source), '-o', str(exe), '-lbpf'])
        if built.returncode:
            return built.returncode, 'COMPILE FAILED\n' + built.stdout + built.stderr
        ran = run([str(exe)], timeout=60)
        return ran.returncode, ran.stdout + ran.stderr


# name -> (old, new): each reverts one part of the rule and must be detected.
RULE_MUTATIONS = {
    'attach_on_every_kick_failure': ('if (ret != -EINVAL && ret != -ENXIO && ret != -ENETDOWN)\n\t\treturn 0;',
                                     'if (!ret)\n\t\treturn 0;'),
    'attach_without_kick': ('ret = kick(xsk_fd);', 'ret = -EINVAL;'),
    'never_attach': ('if (ret != -EINVAL && ret != -ENXIO && ret != -ENETDOWN)\n\t\treturn 0;',
                     'if (ret || !ret)\n\t\treturn 0;'),
    'other_owner_is_an_error': ('xdp_flags);\n\treturn ret == -EBUSY ? 0 : ret;', 'xdp_flags);\n\treturn ret;'),
    'kick_carries_payload': ('sendto(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0)',
                             'sendto(xsk_fd, "k", 1, MSG_DONTWAIT, NULL, 0)'),
}


class SharedRule(unittest.TestCase):
    def test_rule_against_injected_kicks_and_control_plane(self):
        code, out = rule_run()
        self.assertEqual(code, 0, out)
        self.assertRegex(out, r'zc_tx_rule: \d+ checks, 0 failures')

    def test_each_reverted_part_of_the_rule_is_detected(self):
        text = (CLI / 'xdev_ext_xsk_redirect.c').read_text()
        for name, (old, new) in RULE_MUTATIONS.items():
            with self.subTest(mutation=name):
                self.assertEqual(text.count(old), 1, name + ': anchor missing or ambiguous')
                code, out = rule_run(text.replace(old, new, 1))
                self.assertNotEqual(code, 0, name + ' survived')
                self.assertNotIn('COMPILE FAILED', out, name)
                self.assertRegex(out, r'zc_tx_rule: \d+ checks, [1-9]\d* failures', name)


if __name__ == '__main__':
    unittest.main(verbosity=2)
