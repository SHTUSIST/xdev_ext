#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Reliable-transport protocol decisions live in the BPF program; C enforces.

Correctness validation on the host, no device:
- the always-compiled C enforcement helpers (core_enforcement_test.c);
- the production program's decisions with recording kfunc mocks, including
  the policy-driven emit/defer choice (program_test.c);
- the production program compiled with -target bpf: it references only
  declared kfuncs, never a CRC kfunc, and its build section never calls the
  RX-only kfuncs;
- the old in-C decisions are compiled out unless XDEV_EXT_REL_C_GLUE, and
  both variants still compile;
- the kfunc declarations, their BTF registration per member, the BTF
  emission of the view and policy types, and the build return the program
  uses to defer.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import glue_common as G  # noqa: E402

HOST_INCLUDES = ['-I', str(G.HERE / 'host'), '-I', str(G.CREF_HOST),
                 '-I', str(G.ROOT / 'tools/xdev_ext_mech')]


class CoreEnforcement(unittest.TestCase):
    def test_enforcement_helpers(self):
        source = (G.HERE / 'core_enforcement_test.c').read_text()
        _, run = G.build_and_run(self, source, name='core_enforcement')
        self.assertIn(' 0 failures', run.stdout)


class ExistingProgramBoundary(unittest.TestCase):
    """Runs against the existing production ABI: failures are behavioural."""
    def check_boundary(self, case):
        with tempfile.TemporaryDirectory(prefix='xdev_ext-rel-boundary-') as tmp:
            binary = Path(tmp) / 'probe'
            result = subprocess.run(G.cc() + G.HOST_FLAGS + ['-I', str(G.ROOT)] +
                                    HOST_INCLUDES + ['-DPROGRAM="%s"' % G.BPF,
                                    str(G.HERE / 'behavior_program_test.c'), '-o', str(binary)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary), case], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_ack_interpretation_reaches_enforcement(self):
        self.check_boundary('control')

    def test_refused_rx_view_never_takes_custody(self):
        self.check_boundary('refused-view')


class ProgramDecisions(unittest.TestCase):
    def test_program_decides_protocol(self):
        source = (G.HERE / 'program_test.c').read_text()
        _, run = G.build_and_run(self, source, name='program',
                                 extra=HOST_INCLUDES + ['-DPROGRAM="%s"' % G.BPF])
        self.assertIn(' 0 failures', run.stdout)


ALLOWED_KFUNCS = {
    'bpf_xdev_ext_info', 'bpf_xdev_ext_desc', 'bpf_xdev_ext_cqe', 'bpf_xdev_ext_frame',
    'bpf_xdev_ext_afxdp_hdr', 'bpf_xdev_ext_afxdp_hold', 'bpf_xdev_ext_afxdp_state',
    'bpf_xdev_ext_rel_rx_view', 'bpf_xdev_ext_rel_rx_data', 'bpf_xdev_ext_rel_rx_control',
    'bpf_xdev_ext_rel_policy', 'bpf_xdev_ext_rel_tx_view',
    'bpf_iter_num_new', 'bpf_iter_num_next', 'bpf_iter_num_destroy',
}
RX_ONLY = {'bpf_xdev_ext_rel_rx_data', 'bpf_xdev_ext_rel_rx_control', 'bpf_xdev_ext_afxdp_hold'}
CRC = {'bpf_xdev_ext_crc32c', 'bpf_xdev_ext_frame_crc32c'}


def libbpf_dir():
    """Directory holding bpf/bpf_helpers.h with bpf_for() (libbpf >= 1.2)."""
    for cand in (os.environ.get('XDEV_EXT_LIBBPF_INCLUDE'), str(G.ROOT / 'tools/lib')):
        if cand and (Path(cand) / 'bpf/bpf_helpers.h').is_file() and \
                'define bpf_for(' in (Path(cand) / 'bpf/bpf_helpers.h').read_text():
            return Path(cand)
    return None


def tool(env, *names):
    for name in (os.environ.get(env),) + names:
        if name and shutil.which(name):
            return name
    return None


class BpfTargetObject(unittest.TestCase):
    def test_program_compiles_for_bpf_with_bounded_kfuncs(self):
        lib = libbpf_dir()
        self.assertIsNotNone(lib, 'set XDEV_EXT_LIBBPF_INCLUDE to a libbpf tree with bpf_for() '
                                  '(e.g. the assembled kernel tools/lib)')
        clang = tool('CLANG', 'clang-14', 'clang')
        objdump = tool('LLVM_OBJDUMP', 'llvm-objdump-14', 'llvm-objdump')
        self.assertIsNotNone(clang, 'clang not found')
        self.assertIsNotNone(objdump, 'llvm-objdump not found')
        with tempfile.TemporaryDirectory(prefix='xdev_ext-rel-bpf-') as tmp:
            inc = Path(tmp) / 'inc'
            (inc / 'bpf').mkdir(parents=True)
            for name in ('bpf_helpers.h', 'bpf_tracing.h'):
                shutil.copy(lib / 'bpf' / name, inc / 'bpf' / name)
            defs = next((p for p in (lib / 'bpf/bpf_helper_defs.h', Path('/usr/include/bpf/bpf_helper_defs.h'))
                         if p.is_file()), None)
            self.assertIsNotNone(defs, 'bpf_helper_defs.h not found')
            shutil.copy(defs, inc / 'bpf' / 'bpf_helper_defs.h')
            obj = Path(tmp) / 'nxp_reliable.bpf.o'
            build = subprocess.run([clang, '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-target', 'bpf',
                                    '-D__TARGET_ARCH_x86', '-DXDEV_EXT_REL_GLUE_BPF_TARGET',
                                    '-I', str(G.HERE / 'host'), '-I', str(inc), '-I', str(G.ROOT),
                                    '-I', str(G.ROOT / 'tools/xdev_ext_mech'),
                                    '-idirafter', '/usr/include/x86_64-linux-gnu',
                                    '-c', str(G.BPF), '-o', str(obj)],
                                   capture_output=True, text=True, cwd=str(G.BPF.parent))
            self.assertEqual(build.returncode, 0, build.stderr[-6000:])
            print('BPF_TARGET_COMPILE PASS (-target bpf -Wall -Wextra -Werror; no verifier load)', flush=True)
            if os.environ.get('XDEV_EXT_BPF_OBJECT_OUT'):
                shutil.copy(obj, os.environ['XDEV_EXT_BPF_OBJECT_OUT'])
            syms = subprocess.run([objdump, '-t', str(obj)], capture_output=True, text=True).stdout
            undefined = set(re.findall(r'\*UND\*\s+\S+\s+(\S+)', syms))
            self.assertLessEqual(undefined, ALLOWED_KFUNCS, 'undeclared kfunc: %s' % (undefined - ALLOWED_KFUNCS))
            self.assertFalse(undefined & CRC, 'C owns the CRC; the program must not stream payload')
            for name in ('bpf_xdev_ext_rel_rx_view', 'bpf_xdev_ext_rel_rx_data',
                         'bpf_xdev_ext_rel_rx_control', 'bpf_xdev_ext_rel_policy'):
                self.assertIn(name, undefined, 'program does not use ' + name)
            relocs = subprocess.run([objdump, '-r', str(obj)], capture_output=True, text=True).stdout
            sections = {}
            for block in re.split(r'RELOCATION RECORDS FOR \[', relocs)[1:]:
                head, _, body = block.partition(']:')
                sections[head] = set(re.findall(r'\b(bpf_\w+)\b', body))
            build_refs = set().union(*[v for k, v in sections.items() if 'build' in k])
            self.assertFalse(build_refs & RX_ONLY, 'build references RX-only kfuncs: %s' % (build_refs & RX_ONLY))


OLD_GLUE_PROBE = r'''
#include <errno.h>
#include <stdbool.h>
#include <linux/types.h>
#include "include/linux/xdev_ext_mech_reliable_core.h"
int probe(struct xdev_ext_rel_rx *r, const struct xdev_ext_rel_msg *m);
int probe(struct xdev_ext_rel_rx *r, const struct xdev_ext_rel_msg *m)
{
 return xdev_ext_rel_rx_inspect(r, m) + xdev_ext_rel_rx_commit(r, m) +
        xdev_ext_rel_rx_reply_type(r, m->group);
}
'''

NEW_HELPER_PROBE = r'''
#include <errno.h>
#include <stdbool.h>
#include <linux/types.h>
#include "include/linux/xdev_ext_mech_reliable_core.h"
int probe(struct xdev_ext_rel_rx *r, struct xdev_ext_rel_tx *t, __u64 *owed,
          const struct xdev_ext_rel_msg *m, struct xdev_ext_rel_rx_view *v, const __u8 *hdr);
int probe(struct xdev_ext_rel_rx *r, struct xdev_ext_rel_tx *t, __u64 *owed,
          const struct xdev_ext_rel_msg *m, struct xdev_ext_rel_rx_view *v, const __u8 *hdr)
{
 xdev_ext_rel_rx_view_fill(r, *owed, m->group, v);
 return xdev_ext_rel_wire_verify(hdr, 1) + xdev_ext_rel_rx_claim_check(r, m->group, m->index, m->attempt) +
        xdev_ext_rel_rx_claim(r, m->group, m->index, m->attempt) +
        xdev_ext_rel_rx_verdict(r, owed, m->group, m->index, m->attempt, XDEV_EXT_REL_RECYCLE) +
        xdev_ext_rel_rx_control_check(r, *owed, m) +
        xdev_ext_rel_tx_control(t, m->group, m->attempt, m->credit, m->type) +
        xdev_ext_rel_tx_decline(t, m->group, 5) + (int)xdev_ext_rel_tx_scan_start(t) +
        (int)xdev_ext_rel_rto(&t->cfg, m->attempt);
}
'''


def compile_only(source, defines=()):
    with tempfile.TemporaryDirectory(prefix='xdev_ext-rel-glue-cc-') as tmp:
        path = Path(tmp) / 'probe.c'
        path.write_text(source)
        return subprocess.run(G.cc() + ['-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                        '-Werror=implicit-function-declaration', '-c',
                                        '-I', str(G.ROOT)] + ['-D' + d for d in defines] +
                              [str(path), '-o', str(Path(tmp) / 'probe.o')],
                              capture_output=True, text=True)


class OldGlueCompiledOut(unittest.TestCase):
    def test_core_glue_only_with_macro(self):
        default = compile_only(OLD_GLUE_PROBE)
        self.assertNotEqual(default.returncode, 0,
                            'old C glue (rx_inspect/rx_commit/rx_reply_type) still compiled by default')
        for name in ('xdev_ext_rel_rx_inspect', 'xdev_ext_rel_rx_commit', 'xdev_ext_rel_rx_reply_type'):
            self.assertRegex(default.stderr,
                             r'(implicit declaration of function|call to undeclared function) .?%s' % name)
        glue = compile_only(OLD_GLUE_PROBE, [G.GLUE])
        self.assertEqual(glue.returncode, 0, 'reference glue must still compile:\n' + glue.stderr)

    def test_enforcement_helpers_in_both_variants(self):
        for defines in ((), (G.GLUE,)):
            result = compile_only(NEW_HELPER_PROBE, defines)
            self.assertEqual(result.returncode, 0, 'defines=%s\n%s' % (defines, result.stderr))

    def test_provider_default_path_has_no_c_classifier(self):
        text = Path(G.INC).read_text()
        self.assertIn(G.GLUE, text, 'old provider glue must stay compiled-out under ' + G.GLUE)
        default = G.strip_comments(G.default_text(G.INC))
        glue = G.strip_comments(G.glue_text(G.INC))
        for name in ('xdev_ext_rel_rx_inspect', 'xdev_ext_rel_rx_commit', 'xdev_ext_rel_rx_reply_type'):
            self.assertNotRegex(default, r'\b%s\s*\(' % name)
        self.assertRegex(glue, r'\bxdev_ext_rel_rx_inspect\s*\(', 'reference C classifier must be kept')
        check = G.require(default, 'xsk_rel_packet_check', 'default .inc')
        rest = default.replace(check, '')
        self.assertRegex(check, r'\bxdev_ext_rel_wire_decode\s*\(')
        self.assertNotRegex(rest, r'\bxdev_ext_rel_wire_decode\s*\(',
                            'RX identity decode is the program\'s; C keeps only wire_verify')
        decode = G.require(default, 'xsk_rel_decode', 'default .inc')
        self.assertRegex(decode, r'\bxdev_ext_rel_wire_verify\s*\(')
        self.assertRegex(decode, r'\bcrc32c\s*\(', 'C keeps the single RX CRC pass')
        rx = G.require(default, 'xsk_rel_rx', 'default .inc')
        for name in ('xdev_ext_rel_tx_ack', 'xdev_ext_rel_tx_control', 'spin_lock_irqsave'):
            self.assertNotRegex(rx, r'\b%s\s*\(' % name, 'xsk_rel_rx only verifies and delivers')
        self.assertNotIn('dup_suppressed', rx)

    def test_core_header_marks_glue(self):
        text = Path(G.CORE).read_text()
        self.assertRegex(text, r'#\s*ifdef\s+' + G.GLUE)


def squash(text):
    return re.sub(r'\s+', ' ', G.strip_comments(text)).strip()


class KfuncContract(unittest.TestCase):
    PROTOS = {
        'bpf_xdev_ext_rel_rx_view':
            'extern int bpf_xdev_ext_rel_rx_view(const struct xdev_ext_mech_ctx *ctx, __u64 group, '
            'void *view, __u32 view__sz) __ksym;',
        'bpf_xdev_ext_rel_rx_data':
            'extern int bpf_xdev_ext_rel_rx_data(const struct xdev_ext_mech_ctx *ctx, __u64 group, '
            '__u32 index, __u32 attempt, __u32 verdict) __ksym;',
        'bpf_xdev_ext_rel_rx_control':
            'extern int bpf_xdev_ext_rel_rx_control(const struct xdev_ext_mech_ctx *ctx, __u64 group, '
            '__u32 attempt, __u64 credit, __u32 type) __ksym;',
        'bpf_xdev_ext_rel_policy':
            'extern int bpf_xdev_ext_rel_policy(const struct xdev_ext_mech_ctx *ctx, void *policy, '
            '__u32 policy__sz) __ksym;',
    }

    def test_declarations(self):
        text = squash(G.KFUNC_H.read_text())
        for proto in self.PROTOS.values():
            self.assertIn(squash(proto), text)

    def test_resend_choice_is_called_in_production_program(self):
        text = G.strip_comments(G.BPF.read_text())
        self.assertGreaterEqual(len(re.findall(r'\brel_choose_resend\s*\(', text)), 2,
                                'BPF must call its selector, not just define a test-only helper')
        progress = G.require(G.default_text(G.INC), 'xsk_rel_progress', str(G.INC))
        self.assertNotRegex(progress, r'\bxdev_ext_rel_tx_scan_start\s*\(',
                            'policy-directed candidate ordering belongs in BPF')

    def test_program_return_and_rule_constants(self):
        text = G.PROG_H.read_text()
        for name, value in (('XDEV_EXT_MP_BUILD_DEFAULT', 0), ('XDEV_EXT_MP_REL_ACK_EACH', 0),
                            ('XDEV_EXT_MP_REL_ACK_EVERY_N', 1), ('XDEV_EXT_MP_REL_ACK_DELAYED', 2)):
            self.assertRegex(text, r'#define\s+%s\s+%dU?\b' % (name, value))

    def kernel_text(self):
        return '\n'.join(G.strip_comments(p.read_text()) for p in (G.INC, G.XSK))

    def sets(self, text):
        found = {}
        for m in re.finditer(r'BTF_SET_START\((\w+)\)(.*?)BTF_SET_END\(\1\)', text, re.S):
            found[m.group(1)] = set(re.findall(r'BTF_ID\(func,\s*(\w+)\)', m.group(2)))
        return found

    def test_registration_per_member(self):
        text = self.kernel_text()
        for name in self.PROTOS:
            self.assertRegex(text, r'BTF_ID_FLAGS\(func,\s*%s,\s*KF_TRUSTED_ARGS' % name)
            self.assertRegex(text, r'__bpf_kfunc\s+int\s+%s\s*\(' % name)
        sets = self.sets(text)
        build = set().union(*[v for k, v in sets.items() if 'build' in k])
        complete = set().union(*[v for k, v in sets.items() if 'complete' in k])
        for name in ('bpf_xdev_ext_rel_rx_view', 'bpf_xdev_ext_rel_policy'):
            self.assertIn(name, build)
            self.assertIn(name, complete)
        for name in ('bpf_xdev_ext_rel_rx_data', 'bpf_xdev_ext_rel_rx_control'):
            self.assertIn(name, complete)
            self.assertNotIn(name, build, name + ' must not be callable from a build')
        self.assertRegex(text, r'xdev_ext_mech_class_kfunc_filter\(\s*XDEV_EXT_MECH_CLASS_AFXDP')

    def test_view_and_policy_types_reach_btf(self):
        text = '\n'.join(G.strip_comments(p.read_text()) for p in
                         (G.INC, G.XSK, G.ROOT / 'io_uring/xdev_ext_mech_ops.c'))
        for name in ('xdev_ext_rel_rx_view', 'xdev_ext_rel_policy'):
            self.assertRegex(text, r'BTF_TYPE_EMIT\(\s*struct\s+%s\s*\)' % name)


class HotPathBudget(unittest.TestCase):
    """One program invocation per received packet, as at 75b51c2 (plus the
    existing HOLD_RESULT call); guards that the move adds no second call."""

    def test_rx_calls_the_program_at_most_twice(self):
        body = G.require(G.XSK.read_text(), 'xsk_xdev_ext_mech_rx', 'xsk_xdev_ext_mech.c')
        self.assertEqual(len(re.findall(r'\bxsk_xdev_ext_mech_rx_call\s*\(', G.strip_comments(body))), 2)

    def test_reliable_rx_does_not_invoke_programs(self):
        default = G.default_text(G.INC)
        rx = G.require(default, 'xsk_rel_rx', 'default .inc')
        self.assertNotRegex(G.strip_comments(rx), r'\bxdev_ext_mech_call\s*\(')


if __name__ == '__main__':
    unittest.main(verbosity=2)
