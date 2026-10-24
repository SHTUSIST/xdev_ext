#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile the CPU BPF target with optional descriptor BTF and check its wire ABI.

The small vmlinux projections derive from the current UAPI/struct_ops declarations;
no kernel, guest, hardware or performance execution is implied. To also compile
against a real target's generated header, set XDEV_EXT_CPU_VMLINUX_H to its path.
Missing compilers, BPF backend or libbpf headers are failures, never skips.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import sysconfig
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[3]
TOOLS = KERNEL / 'tools/xdev_ext_mech'


def command(args):
    result = subprocess.run(list(map(str, args)), text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=60)
    return result.returncode, result.stdout


def projection(cpu):
    uapi = (KERNEL / 'include/uapi/linux/xdev_ext_mech.h').read_text()
    if not cpu:
        uapi, count = re.subn(r'struct xdev_ext_cpu_desc\s*\{[^}]*\};', '', uapi)
        if count != 1:
            raise AssertionError('CPU descriptor declaration not found exactly once')
    ops = (KERNEL / 'include/linux/xdev_ext_mech.h').read_text()
    ops = ops[ops.index('#define XDEV_EXT_MECH_OPS_TYPE'):]
    ops = ops[:ops.index('\n\nXDEV_EXT_MECH_OPS_TYPE')]
    return ('#ifndef XDEV_EXT_CPU_TEST_VMLINUX_H\n#define XDEV_EXT_CPU_TEST_VMLINUX_H\n'
            '#include <stdbool.h>\n#include <stddef.h>\n#include <linux/if_xdp.h>\n' +
            uapi + '\n' + ops +
            '\nXDEV_EXT_MECH_OPS_TYPE(xdev_ext_cpu_mech_ops);\n#endif\n')


class CpuBpfTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='xdev-cpu-bpf-')
        self.addCleanup(self.temporary.cleanup)
        self.build = Path(self.temporary.name)
        self.cc = shlex.split(os.environ.get('CC', 'cc'))
        self.clang = shlex.split(os.environ.get('CLANG', 'clang'))
        # Linux UAPI asm/types.h lives under the host compiler's multiarch dir.
        code, machine = command(self.cc + ['-dumpmachine'])
        self.assertEqual(code, 0, machine)
        multiarch = sysconfig.get_config_var('MULTIARCH') or machine.strip()
        self.includes = ['-I' + str(KERNEL / 'include/uapi/linux'),
                         '-I/usr/include/' + multiarch, '-I' + str(TOOLS)]

    def target(self, header, source=None):
        (self.build / 'vmlinux.h').write_text(header)
        obj = self.build / 'cpu_plan.bpf.o'
        code, output = command(self.clang + ['-target', 'bpf', '-D__TARGET_ARCH_x86',
            '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
            '-I' + str(self.build)] + self.includes +
            ['-c', source or TOOLS / 'cpu_plan.bpf.c', '-o', obj])
        self.assertEqual(code, 0, output)
        data = obj.read_bytes()
        self.assertEqual(data[:4], b'\x7fELF')
        self.assertEqual(int.from_bytes(data[18:20], 'little'), 247, 'must be EM_BPF')

    def test_bpf_target_without_cpu_descriptor(self):
        self.target(projection(False))

    def test_bpf_target_with_cpu_descriptor(self):
        self.target(projection(True))

    def test_descriptor_layout_and_cpu_decisions(self):
        (self.build / 'vmlinux.h').write_text(projection(True))
        fixture = self.build / 'behavior.c'
        fixture.write_text(r'''
#include <assert.h>
#include <string.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
/* libbpf's section macro uses clang pragmas; sections are irrelevant to
 * executing the same program body under the native GCC/Clang sanitizer. */
#undef SEC
#define SEC(name) __attribute__((section(name), used))
#include "cpu_plan.bpf.c"
#define SAME(member) \
 _Static_assert(__builtin_offsetof(struct xdev_ext_mp_cpu_desc, member) == \
                __builtin_offsetof(struct xdev_ext_cpu_desc, member), "offset " #member); \
 _Static_assert(__builtin_types_compatible_p( \
                __typeof__(((struct xdev_ext_mp_cpu_desc *)0)->member), \
                __typeof__(((struct xdev_ext_cpu_desc *)0)->member)), "type " #member)
_Static_assert(sizeof(struct xdev_ext_mp_cpu_desc) == sizeof(struct xdev_ext_cpu_desc), "size");
_Static_assert(_Alignof(struct xdev_ext_mp_cpu_desc) == _Alignof(struct xdev_ext_cpu_desc), "alignment");
SAME(xform); SAME(flags); SAME(param);
struct guarded { unsigned long long before; struct xdev_ext_cpu_desc d; unsigned long long after; };
static struct guarded storage;
static const struct xdev_ext_mech_ctx *wanted;
static unsigned calls;
static int refuse;
__u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *mctx, __u32 slot, size_t size)
{
 assert(mctx == wanted && slot == 0 && size == sizeof(storage.d));
 calls++;
 return refuse ? NULL : (__u8 *)&storage.d;
}
int main(void)
{
 struct xdev_ext_mech_ctx mctx = {};
 unsigned long long ctx[] = { (unsigned long long)&mctx };
 const __u64 params[] = {0, 0x0123456789abcdefULL, ~0ULL};
 unsigned i, x;
 wanted = &mctx;
 memset(&storage, 0xa5, sizeof(storage));
 cpu_xform = 0;
 assert(cpu_plan_build(ctx) == 0 && calls == 0);
 for (x = 1; x < XDEV_EXT_CPU_XFORM_MAX; x++) {
  for (i = 0; i < sizeof(params)/sizeof(params[0]); i++) {
   cpu_xform = x; cpu_param = params[i];
   memset(&storage, 0xa5, sizeof(storage));
   assert(cpu_plan_build(ctx) == XDEV_EXT_MP_BUILD_SUBMIT);
   assert(storage.d.xform == x && storage.d.flags == 0 && storage.d.param == params[i]);
   assert(storage.before == 0xa5a5a5a5a5a5a5a5ULL && storage.after == storage.before);
  }
 }
 refuse = 1;
 assert(cpu_plan_build(ctx) == XDEV_EXT_MP_BUILD_ABORT);
 assert(cpu_plan_complete(ctx) == XDEV_EXT_MP_NEXT);
 assert(cpu_plan_ops.abi_version == XDEV_EXT_MECH_CPU_ABI_VERSION);
 assert(cpu_plan_ops.build && cpu_plan_ops.complete);
 return 0;
}
''')
        binary = self.build / 'behavior'
        code, output = command(self.cc + ['-std=gnu11', '-O2', '-g', '-Wall',
            '-Wextra', '-Werror', '-fsanitize=undefined', '-fno-sanitize-recover=all',
            '-I' + str(self.build)] + self.includes + [fixture, '-o', binary])
        self.assertEqual(code, 0, output)
        code, output = command([binary])
        self.assertEqual(code, 0, output)


if os.environ.get('XDEV_EXT_CPU_VMLINUX_H'):
    def real_target_header(self):
        self.target(Path(os.environ['XDEV_EXT_CPU_VMLINUX_H']).read_text())
    CpuBpfTest.test_real_target_header = real_target_header

if __name__ == '__main__':
    unittest.main(verbosity=2)
