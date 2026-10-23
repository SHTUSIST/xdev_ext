#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Automatic NIC-boundary fallback: the CREATE caller picks the NIC stage.

Paper 03_design.tex:30 and 04_implementation.tex:33-37: when an AF_XDP
zero-copy frame cannot be used, the NIC path copies at the NIC boundary
through an ordinary socket adapter; the other stages, the frame-offset
namespace and completion reporting do not change. Contract: track S API.md
section 4 (decision in user space, justified there). Executes the pure
decision and CREATE-rewrite rules of
tools/xdev_ext_mech/xdev_ext_mech_ctl_fallback.h against the production
CREATE checker, and pins the ctl wiring (option, READY value, accounting line).
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[5]

FIXTURE = r'''
#include <stdio.h>
#include <string.h>
#include "tools/xdev_ext_mech/xdev_ext_mech_ctl_fallback.h"
#include "io_uring/xdev_ext_mech_step.h"
static int failures;
#define EXPECT(c) do { if (!(c)) { printf("not ok - line %d: %s\n", __LINE__, #c); failures++; } } while (0)
#define ZC XDP_OPTIONS_ZEROCOPY
static int path_of(__u32 policy, bool copy, int bind_err, __u32 options, __u32 *path)
{
 *path = 0xdead;
 return xdev_ext_mech_ctl_nic_path(policy, copy, bind_err, options, path);
}
static struct xdev_ext_mech_create afxdp_rx_create(void)
{
 struct xdev_ext_mech_create c;
 memset(&c, 0, sizeof(c));
 c.abi_version = XDEV_EXT_MECH_ABI_VERSION; c.nr_stages = 2;
 c.pool_kind = XDEV_EXT_MECH_POOL_XSK; c.pool_fd = 9; c.depth = 8; c.eventfd = 11;
 c.layout = (struct xdev_ext_mech_layout){ .frame_size = 4096, .hdr_room = 256, .seg_len = 1408, .group_bytes = 8192 };
 c.peer.local_port = 0x3930; c.peer.peer_port = 0x31d4; c.peer.local_ip = 0x0202000c; c.peer.peer_ip = 0x0102000c;
 c.st[0] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_AFXDP, .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = 9 };
 c.st[1] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 10, .arg0 = 64, .arg1 = 4096 };
 c.session_id = 77;
 return c;
}
static struct xdev_ext_mech_create afxdp_tx_create(void)
{
 struct xdev_ext_mech_create c = afxdp_rx_create();
 c.nr_stages = 3;
 c.st[0] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME, .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = 10, .arg0 = 64, .arg1 = 4096 };
 c.st[1] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_CE, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 12, .arg1 = 1 << 20 };
 c.st[2] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_AFXDP, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 9 };
 return c;
}
/* Every byte except the NIC stage and the pool selection is unchanged. */
static int only_nic_changed(const struct xdev_ext_mech_create *a, const struct xdev_ext_mech_create *b, unsigned nic)
{
 struct xdev_ext_mech_create x = *a, y = *b;
 memset(&x.st[nic], 0, sizeof(x.st[nic])); memset(&y.st[nic], 0, sizeof(y.st[nic]));
 x.pool_kind = y.pool_kind = 0; x.pool_fd = y.pool_fd = 0;
 return !memcmp(&x, &y, sizeof(x));
}
int main(void)
{
 __u32 p, f0, f1;
 struct xdev_ext_mech_create a, b;

 /* Policy parsing. */
 EXPECT(!xdev_ext_mech_ctl_nic_policy_parse("auto", &p) && p == XDEV_EXT_MECH_CTL_NIC_AUTO);
 EXPECT(!xdev_ext_mech_ctl_nic_policy_parse("off", &p) && p == XDEV_EXT_MECH_CTL_NIC_REQUIRE_ZC);
 EXPECT(!xdev_ext_mech_ctl_nic_policy_parse("force", &p) && p == XDEV_EXT_MECH_CTL_NIC_FORCE_SOCKET);
 EXPECT(xdev_ext_mech_ctl_nic_policy_parse("socket", &p) == -EINVAL);
 EXPECT(xdev_ext_mech_ctl_nic_policy_parse("", &p) == -EINVAL);
 EXPECT(xdev_ext_mech_ctl_nic_policy_parse(NULL, &p) == -EINVAL);
 EXPECT(XDEV_EXT_MECH_CTL_NIC_AUTO == 0);
 EXPECT(xdev_ext_mech_ctl_nic_try_afxdp(XDEV_EXT_MECH_CTL_NIC_AUTO));
 EXPECT(xdev_ext_mech_ctl_nic_try_afxdp(XDEV_EXT_MECH_CTL_NIC_REQUIRE_ZC));
 EXPECT(!xdev_ext_mech_ctl_nic_try_afxdp(XDEV_EXT_MECH_CTL_NIC_FORCE_SOCKET));

 /* AUTO: zero-copy when admitted; the socket adapter only on the ZC refusal. */
 EXPECT(!path_of(XDEV_EXT_MECH_CTL_NIC_AUTO, false, 0, ZC, &p) && p == XDEV_EXT_MECH_CTL_NIC_AFXDP_ZC);
 EXPECT(!path_of(XDEV_EXT_MECH_CTL_NIC_AUTO, false, -EOPNOTSUPP, 0, &p) && p == XDEV_EXT_MECH_CTL_NIC_SOCKET);
 EXPECT(!path_of(XDEV_EXT_MECH_CTL_NIC_AUTO, false, 0, 0, &p) && p == XDEV_EXT_MECH_CTL_NIC_SOCKET);
 EXPECT(path_of(XDEV_EXT_MECH_CTL_NIC_AUTO, false, -ENODEV, 0, &p) == -ENODEV && p == 0xdead);
 EXPECT(path_of(XDEV_EXT_MECH_CTL_NIC_AUTO, false, -EBUSY, 0, &p) == -EBUSY && p == 0xdead);
 EXPECT(path_of(XDEV_EXT_MECH_CTL_NIC_AUTO, false, -EINVAL, 0, &p) == -EINVAL && p == 0xdead);
 EXPECT(path_of(XDEV_EXT_MECH_CTL_NIC_AUTO, false, -EPERM, 0, &p) == -EPERM && p == 0xdead);
 /* No implicit ZC -> AF_XDP copy downgrade: copy mode is explicit only. */
 EXPECT(!path_of(XDEV_EXT_MECH_CTL_NIC_AUTO, true, 0, 0, &p) && p == XDEV_EXT_MECH_CTL_NIC_AFXDP_COPY);
 EXPECT(path_of(XDEV_EXT_MECH_CTL_NIC_AUTO, true, 0, ZC, &p) == -EPROTO && p == 0xdead);
 EXPECT(path_of(XDEV_EXT_MECH_CTL_NIC_AUTO, true, -ENODEV, 0, &p) == -ENODEV);
 /* REQUIRE_ZC keeps today's strict behaviour. */
 EXPECT(!path_of(XDEV_EXT_MECH_CTL_NIC_REQUIRE_ZC, false, 0, ZC, &p) && p == XDEV_EXT_MECH_CTL_NIC_AFXDP_ZC);
 EXPECT(path_of(XDEV_EXT_MECH_CTL_NIC_REQUIRE_ZC, false, -EOPNOTSUPP, 0, &p) == -EOPNOTSUPP && p == 0xdead);
 EXPECT(path_of(XDEV_EXT_MECH_CTL_NIC_REQUIRE_ZC, false, 0, 0, &p) == -EOPNOTSUPP && p == 0xdead);
 EXPECT(path_of(XDEV_EXT_MECH_CTL_NIC_REQUIRE_ZC, true, 0, 0, &p) == -EINVAL && p == 0xdead);
 /* FORCE_SOCKET ignores bind results; conflicts with explicit copy mode. */
 EXPECT(!path_of(XDEV_EXT_MECH_CTL_NIC_FORCE_SOCKET, false, -ENODEV, ZC, &p) && p == XDEV_EXT_MECH_CTL_NIC_SOCKET);
 EXPECT(path_of(XDEV_EXT_MECH_CTL_NIC_FORCE_SOCKET, true, 0, 0, &p) == -EINVAL && p == 0xdead);
 EXPECT(path_of(9, false, 0, ZC, &p) == -EINVAL && p == 0xdead);

 /* RX stage 0: only the NIC stage and the pool kind change; CREATE still admits it. */
 a = afxdp_rx_create(); b = a;
 EXPECT(!xdev_ext_mech_create_check(&a, &f0));
 EXPECT(!xdev_ext_mech_ctl_nic_fallback_create(&b, 0, 21));
 EXPECT(b.st[0].class_id == XDEV_EXT_MECH_CLASS_SOCKET && b.st[0].direction == XDEV_EXT_MECH_DIR_FROM_DEVICE);
 EXPECT(b.st[0].fd == 21 && !b.st[0].flags && !b.st[0].arg0 && !b.st[0].arg1);
 EXPECT(b.pool_kind == XDEV_EXT_MECH_POOL_IOU_UMEM && b.pool_fd == -1);
 EXPECT(only_nic_changed(&a, &b, 0));
 EXPECT(!xdev_ext_mech_create_check(&b, &f1) && f1 == f0);	/* same frames per batch */
 /* TX last stage. */
 a = afxdp_tx_create(); b = a;
 EXPECT(!xdev_ext_mech_create_check(&a, &f0));
 EXPECT(!xdev_ext_mech_ctl_nic_fallback_create(&b, 2, 22));
 EXPECT(b.st[2].class_id == XDEV_EXT_MECH_CLASS_SOCKET && b.st[2].direction == XDEV_EXT_MECH_DIR_TO_DEVICE && b.st[2].fd == 22);
 EXPECT(only_nic_changed(&a, &b, 2));
 EXPECT(!xdev_ext_mech_create_check(&b, &f1) && f1 == f0);
 /* An IOU_UMEM pool is kept as it is. */
 a = afxdp_tx_create(); a.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM; a.pool_fd = -1; b = a;
 EXPECT(!xdev_ext_mech_ctl_nic_fallback_create(&b, 2, 22) && b.pool_kind == XDEV_EXT_MECH_POOL_IOU_UMEM && b.pool_fd == -1);
 /* Refusals leave the CREATE untouched. */
#define REFUSE(mut, stage_, fd_, want) do { a = afxdp_rx_create(); mut; b = a; \
  EXPECT(xdev_ext_mech_ctl_nic_fallback_create(&b, stage_, fd_) == want); EXPECT(!memcmp(&a, &b, sizeof(a))); } while (0)
 REFUSE((void)0, 1, 21, -EINVAL);				/* not an AF_XDP stage */
 REFUSE((void)0, 2, 21, -EINVAL);				/* beyond nr_stages */
 REFUSE((void)0, 0, -1, -EBADF);
 REFUSE(a.st[0].flags = XDEV_EXT_AFXDP_F_RELIABLE, 0, 21, -EOPNOTSUPP);
 REFUSE((a.st[0].direction = XDEV_EXT_MECH_DIR_TO_DEVICE), 0, 21, -EINVAL);	/* TX not last */
 REFUSE((a.st[1] = a.st[0], a.st[0] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
   .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = 10, .arg1 = 64 }), 1, 21, -EINVAL);	/* RX not first */
 EXPECT(xdev_ext_mech_ctl_nic_fallback_create(NULL, 0, 21) == -EINVAL);
 if (failures) printf("FAIL nic fallback choice failures=%d\n", failures);
 else printf("PASS nic fallback choice\n");
 return failures != 0;
}
'''


class NicFallbackChoice(unittest.TestCase):
    def test_pure_rules(self):
        header = ROOT / 'tools/xdev_ext_mech/xdev_ext_mech_ctl_fallback.h'
        self.assertTrue(header.exists(), 'tools/xdev_ext_mech/xdev_ext_mech_ctl_fallback.h (API.md 4.1) is missing')
        with tempfile.TemporaryDirectory(prefix='nic-fallback-') as tmp:
            source = Path(tmp) / 'choice.c'
            exe = Path(tmp) / 'choice'
            source.write_text(FIXTURE)
            build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                                    '-I' + str(ROOT), str(source), '-o', str(exe)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True)
            print(run.stdout, end='')
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_actual_ctl_nxp_create(self):
        ctl = (ROOT / 'tools/xdev_ext_mech/xdev_ext_mech_ctl.c').read_text()
        fn = re.search(r'^static int ctl_nic_nxp_create\([^;{}]*\)\s*\{.*?^\}', ctl, re.M | re.S)[0]
        pre = r'''
#include <assert.h>
#include <net/if.h>
#include <sys/ioctl.h>
struct ctl_opts {const char *ifname;__u64 wire_session;};
/* Native interface query only. CREATE mutation and policy are production. */
static int ctl_if_query(const char *name,unsigned long req,struct ifreq *out)
{assert(!strcmp(name,"fixture")&&req==SIOCGIFMTU);out->ifr_mtu=1500;return 0;}
'''
        body = r'''
int main(void)
{
 struct ctl_opts o={"fixture",270019};
 for(unsigned tx=0;tx<2;tx++){
  struct xdev_ext_mech_create before=tx?afxdp_tx_create():afxdp_rx_create(),after=before;
  __u32 stage=tx?2:0,path,frames;
  assert(!path_of(XDEV_EXT_MECH_CTL_NIC_AUTO,false,-EOPNOTSUPP,0,&path)&&path==XDEV_EXT_MECH_CTL_NIC_SOCKET);
  assert(!ctl_nic_nxp_create(&o,&after,stage,21));
  assert(after.st[stage].flags==XDEV_EXT_SOCKET_F_NXP&&after.st[stage].arg0==270019&&after.st[stage].arg1==1500);
  assert(only_nic_changed(&before,&after,stage));
  assert(!xdev_ext_mech_create_check(&after,&frames));
 }
 puts("PASS actual AUTO refusal -> NXP socket CREATE changes only NIC and pool, preserves other stages");return 0;
}
'''
        prefix = FIXTURE.split('int main(void)', 1)[0]
        with tempfile.TemporaryDirectory(prefix='nic-nxp-create-') as tmp:
            c = Path(tmp) / 'create.c'; exe = Path(tmp) / 'create'
            c.write_text(prefix + pre + fn + body)
            build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                    '-Wno-unused-variable', '-I' + str(ROOT), str(c), '-o', str(exe)], capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True)
            print(run.stdout, end=''); self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_ctl_wiring(self):
        ctl = (ROOT / 'tools/xdev_ext_mech/xdev_ext_mech_ctl.c').read_text()
        checks = (
            ('#include "xdev_ext_mech_ctl_fallback.h"', 'ctl must use the shared fallback rules'),
            ('"nic-fallback"', 'ctl needs the --nic-fallback option'),
            ('xdev_ext_mech_ctl_nic_policy_parse(', 'option value parsed by the shared rule'),
            ('xdev_ext_mech_ctl_nic_path(', 'NIC path decided by the shared rule'),
            ('xdev_ext_mech_ctl_nic_fallback_create(', 'CREATE rewritten by the shared rule'),
            ('XDEV_EXT_MECH_NIC_ACCOUNTING session=', 'accounting marker line'),
            ('XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_3', 'accounting read through TRANSPORT_STATS v3'),
            ('"socket"', 'READY xsk=socket value for the socket path'),
        )
        for needle, why in checks:
            with self.subTest(needle=needle):
                self.assertTrue(needle in ctl, why)
        line = re.search(r'XDEV_EXT_MECH_NIC_ACCOUNTING session=%llu path=%s nic_copy_ops=%llu '
                         r'nic_copy_bytes=%llu nic_zc_ops=%llu nic_zc_bytes=%llu\\n', ctl)
        self.assertTrue(line, 'accounting line format must match API.md 4.2 exactly')


if __name__ == '__main__':
    unittest.main(verbosity=2)
