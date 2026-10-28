#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host policy correctness; no device emulation or performance measurement."""
from pathlib import Path
import sys
import unittest
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'xdev_ext_mech/reliable/bpf_glue'))
import glue_common as G

class Policy(unittest.TestCase):
    def test_policy_bounds_defaults_and_enforcement(self):
        self.assertTrue(G.POLICY_H.is_file(), 'ABSENCE: production policy module missing')
        _, run = G.build_and_run(self, (HERE / 'policy_test.c').read_text(), name='policy')
        self.assertIn(' 0 failures', run.stdout)


class TimeoutConsumers(unittest.TestCase):
    def test_existing_timeout_consumers_use_central_policy(self):
        root = HERE.parents[3]
        core = (root / 'io_uring/xdev_ext_mech.c').read_text()
        peer = (root / 'io_uring/xdev_ext_peer_net.c').read_text()
        iaa = (root / 'io_uring/iaa/xdev_ext_iaa.c').read_text()
        self.assertIn('#define XDEV_EXT_MECH_GROUP_TIMEOUT\txdev_ext_policy_rx_group_timeout()', core)
        self.assertIn('#include "xdev_ext_policy.h"', peer)
        self.assertIn('#define XDEV_EXT_PEER_NET_TIMEOUT xdev_ext_policy_peer_net_timeout()', peer)
        self.assertIn('#include "../xdev_ext_policy.h"', iaa)
        self.assertIn('#define IO_XDEV_EXT_IAA_TFM_IDLE xdev_ext_policy_iaa_tfm_idle()', iaa)

    def test_iaa_idle_links_without_mechanism_and_preserves_jiffies(self):
        import os, re, subprocess, tempfile
        root = HERE.parents[3]
        iaa = (root / 'io_uring/iaa/xdev_ext_iaa.c').read_text()
        block = re.search(r'^#ifdef CONFIG_XDEV_EXT_MECH\n#define IO_XDEV_EXT_IAA_TFM_IDLE .*?^#endif', iaa, re.M | re.S)
        self.assertIsNotNone(block, 'direct IAA must not require the CONFIG_XDEV_EXT_MECH object')
        policy = (root / 'io_uring/xdev_ext_policy.c').read_text()
        getters = '\n'.join(re.findall(r'^unsigned long xdev_ext_policy_\w+\(void\)\n\{.*?^\}', policy, re.M | re.S))
        with tempfile.TemporaryDirectory(prefix='policy-consumers-') as tmp:
            c = Path(tmp) / 'probe.c'; exe = Path(tmp) / 'probe'
            for hz in (100, 250, 1000):
                for enabled in (False, True):
                    # Disabled build deliberately has no external policy definition:
                    # a stray call is a linker failure, not a stubbed success.
                    source = ('#include <assert.h>\n#include "io_uring/xdev_ext_policy.h"\n'
                        '#define msecs_to_jiffies(n) (((unsigned long)(n)*HZ+999)/1000)\n'
                        + ('#define CONFIG_XDEV_EXT_MECH 1\n' + getters if enabled else '')
                        + '\n' + block[0] + '\nint main(void) { assert(IO_XDEV_EXT_IAA_TFM_IDLE == 5UL*HZ);'
                        + ('assert(xdev_ext_policy_rx_group_timeout()==HZ);assert(xdev_ext_policy_peer_net_timeout()==30UL*HZ);' if enabled else '')
                        + 'return 0;}\n')
                    c.write_text(source)
                    subprocess.run([os.environ.get('CC','cc'), '-std=gnu11','-Wall','-Wextra','-Werror',f'-DHZ={hz}','-I'+str(root),str(c),'-o',str(exe)],check=True)
                    subprocess.run([str(exe)],check=True)

if __name__ == '__main__':
    unittest.main(verbosity=2)
