#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Wiring of the BPF compute callback, read from the production sources.

What a host cannot execute is checked structurally here: the struct_ops
member and its kCFI stub exist for every type but only the CPU type accepts a
program for it, the compute kfunc sets and their filters, the registration
order, the CPU class call site (one call per batch, a terminal completion, no
retry), the CREATE-time program requirement, and the UAPI and tool
declarations. The verifier and a guest run check the loaded behaviour
(xdev_ext-compute.rst, Tests).
"""
import re
import unittest

from compute_extract import body, function, source

OPS = 'io_uring/xdev_ext_mech_ops.c'
CPU = 'io_uring/xdev_ext_mech_cpu.c'
MECH = 'io_uring/xdev_ext_mech.c'
LINUX = 'include/linux/xdev_ext_mech.h'
UAPI = 'include/uapi/linux/xdev_ext_mech.h'


def btf_set(text, name):
    match = re.search(r'BTF_SET_START\(' + name + r'\)\n(.*?)BTF_SET_END', text, re.S)
    if not match:
        raise AssertionError('BTF set missing: ' + name)
    return set(re.findall(r'BTF_ID\(func, (\w+)\)', match.group(1)))


class ComputeWiring(unittest.TestCase):
    def test_uapi(self):
        text = source(UAPI)
        for pattern in (r'XDEV_EXT_MECH_MEMBER_COMPUTE\s*= 4,', r'XDEV_EXT_CPU_XFORM_BPF = 10,',
                        r'XDEV_EXT_CPU_XFORM_MAX = 11,', r'#define XDEV_EXT_CPU_BPF_DELTA_MAX 256U'):
            self.assertIsNotNone(re.search(pattern, text), 'UAPI lacks ' + pattern)

    def test_member_in_every_type_after_complete(self):
        text = source(LINUX)
        macro = re.search(r'#define XDEV_EXT_MECH_OPS_TYPE\(name\)(.*?)\n}\n', text, re.S)
        self.assertIsNotNone(macro)
        members = re.findall(r'\(\*(\w+)\)\(const struct xdev_ext_mech_ctx \*ctx\)', macro.group(1))
        self.assertEqual(members, ['prepare', 'build', 'complete', 'compute'])
        ops = source(OPS)
        same = re.search(r'#define XDEV_EXT_MECH_SAME_LAYOUT\(type\)(.*?)\n\n', ops, re.S).group(1)
        self.assertIn('offsetof(struct type, compute)', same)
        self.assertIn('XDEV_EXT_MECH_SAME_LAYOUT(xdev_ext_cpu_mech_ops);', ops)
        self.assertIn('XDEV_EXT_MECH_SAME_LAYOUT(xdev_ext_net_mech_ops);', ops)
        member = body(ops, 'xdev_ext_mech_member_fn')
        self.assertRegex(member, r'case XDEV_EXT_MECH_MEMBER_COMPUTE:\s*return o->compute;')

    def test_only_cpu_type_accepts_compute(self):
        ops = source(OPS)
        # A NULL kCFI stub makes bpf_struct_ops_supported() refuse the member.
        macro = re.search(r'#define XDEV_EXT_MECH_STRUCT_OPS_X\(([^)]*)\)(.*?)\n}\n', ops, re.S)
        self.assertIsNotNone(macro)
        self.assertIn('.compute = compute_stub,', macro.group(2))
        self.assertIn('.check_member = check_member_fn,', macro.group(2))
        generic = re.search(r'#define XDEV_EXT_MECH_STRUCT_OPS\(cls, id, init_member_fn, validate_fn\)'
                            r'\s*\\\s*XDEV_EXT_MECH_STRUCT_OPS_X\(([^)]*)\)', ops)
        self.assertIsNotNone(generic)
        self.assertEqual([a.strip() for a in generic.group(1).split(',')][-2:],
                         ['xdev_ext_mech_ops_check_member', 'NULL'])
        cpu = re.search(r'XDEV_EXT_MECH_STRUCT_OPS_X\(cpu, XDEV_EXT_MECH_CLASS_CPU,([^;]*)\);', ops)
        self.assertIsNotNone(cpu)
        args = [a.strip() for a in cpu.group(1).split(',')]
        self.assertEqual(args, ['xdev_ext_mech_ops_init_member', 'xdev_ext_mech_ops_validate',
                                'xdev_ext_cpu_mech_ops_check_member', 'xdev_ext_mech_ops__compute'])
        self.assertEqual(len(re.findall(r'XDEV_EXT_MECH_STRUCT_OPS_X\(\w+,', ops)), 1)
        self.assertIn('XDEV_EXT_OPS_CFI_STUB(xdev_ext_mech_ops__compute, struct xdev_ext_mech_ctx)', ops)
        # The CPU member table lists compute as optional and never sleeping.
        table = re.search(r'xdev_ext_cpu_mech_ops_members\[\] = {\n(.*?)\n};', ops, re.S)
        self.assertIsNotNone(table)
        rows = dict(re.findall(r'offsetof\(struct xdev_ext_cpu_mech_ops, (\w+)\)(.*?)}',
                               table.group(1)))
        self.assertEqual(sorted(rows), ['build', 'complete', 'compute', 'prepare'])
        self.assertNotIn('sleepable', rows['compute'])
        self.assertNotIn('required', rows['compute'])
        check = body(ops, 'xdev_ext_cpu_mech_ops_check_member')
        self.assertIn('xdev_ext_ops_check_member(&xdev_ext_cpu_mech_ops_desc,', check)
        shared = re.search(r'xdev_ext_mech_ops_members\[\] = {\n(.*?)\n};', ops, re.S).group(1)
        self.assertNotIn('compute', shared)

    def test_kfunc_sets_and_filters(self):
        ops = source(OPS)
        ids = re.search(r'BTF_KFUNCS_START\(xdev_ext_mech_compute_kfunc_ids\)\n(.*?)BTF_KFUNCS_END',
                        ops, re.S)
        self.assertIsNotNone(ids)
        flags = dict(re.findall(r'BTF_ID_FLAGS\(func, (\w+), ([^)]*)\)', ids.group(1)))
        self.assertEqual(sorted(flags), ['bpf_xdev_ext_frame_len', 'bpf_xdev_ext_frame_rw',
                                         'bpf_xdev_ext_frame_set_len'])
        for name, value in flags.items():
            self.assertIn('KF_TRUSTED_ARGS', value, name)
            self.assertEqual('KF_RET_NULL' in value, name == 'bpf_xdev_ext_frame_rw', name)
        self.assertNotIn('KF_SLEEPABLE', ids.group(1))
        self.assertEqual(btf_set(ops, 'xdev_ext_mech_compute_only_kfuncs'), set(flags))
        # The shared kfuncs a compute program may also call.
        self.assertEqual(btf_set(ops, 'xdev_ext_mech_compute_kfuncs'),
                         {'bpf_xdev_ext_frame', 'bpf_xdev_ext_frame_crc32c', 'bpf_xdev_ext_crc32c'})
        shared = re.search(r'xdev_ext_mech_kfunc_members\[\] = {\n(.*?)\n};', ops, re.S).group(1)
        self.assertRegex(shared, r'offsetof\(struct xdev_ext_nvme_mech_ops, compute\),\s*'
                                 r'\.allowed = &xdev_ext_mech_compute_kfuncs,')
        for member in ('prepare', 'build', 'complete'):
            self.assertNotIn('bpf_xdev_ext_frame_rw', btf_set(ops, f'xdev_ext_mech_{member}_kfuncs'))
        rule = re.search(r'xdev_ext_mech_compute_kfunc_rule = {\n(.*?)\n};', ops, re.S)
        self.assertIsNotNone(rule)
        self.assertIn('.ids = &xdev_ext_mech_compute_kfunc_ids,', rule.group(1))
        self.assertIn('.st_ops = xdev_ext_mech_compute_st_ops,', rule.group(1))
        cpu_only = re.search(r'xdev_ext_mech_compute_st_ops\[\] = {\n(.*?)\n};', ops, re.S).group(1)
        self.assertEqual(cpu_only.split(), ['&bpf_xdev_ext_cpu_mech_ops,'])
        members = re.search(r'xdev_ext_mech_compute_kfunc_members\[\] = {\n(.*?)\n};', ops, re.S).group(1)
        self.assertEqual(re.findall(r'offsetof\(struct xdev_ext_cpu_mech_ops, (\w+)\)', members),
                         ['compute'])
        self.assertIn('.allowed = &xdev_ext_mech_compute_only_kfuncs,', members)
        flt = body(ops, 'xdev_ext_mech_compute_kfunc_filter')
        self.assertIn('return xdev_ext_ops_kfunc_filter(&xdev_ext_mech_compute_kfunc_rule, prog, kfunc_id);',
                      flt)
        init = ' '.join(body(ops, 'xdev_ext_mech_ops_init').split())
        first = init.index('register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &xdev_ext_mech_kfunc_set);')
        second = init.index('register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, '
                            '&xdev_ext_mech_compute_kfunc_set);')
        self.assertLess(first, second)
        self.assertLess(second, init.index('register_bpf_struct_ops(&bpf_xdev_ext_nvme_mech_ops'))

    def test_invoke_and_args(self):
        ops = source(OPS)
        args = body(ops, 'xdev_ext_mech_args_ok')
        case = args[args.index('case XDEV_EXT_MECH_MEMBER_COMPUTE:'):]
        case = case[:case.index('default:')]
        for words in ('a->callsite == XDEV_EXT_MECH_SITE_WORKER', 'a->b', 'a->nr_frames',
                      'a->out_len', '!a->scratch', '!a->cqe'):
            self.assertIn(words, case)
        invoke = body(ops, 'xdev_ext_mech_invoke')
        self.assertIn('call.out_len = a->out_len;', invoke)
        self.assertIn('call.len_delta = a->len_delta;', invoke)
        frame = body(ops, 'xdev_ext_mech_frame_bytes')
        self.assertIn('c->member != XDEV_EXT_MECH_MEMBER_COMPUTE', frame)

    def test_core_call_site_and_requirement(self):
        mech = source(MECH)
        compute = body(mech, 'xdev_ext_mech_batch_compute')
        self.assertLess(compute.index('xdev_ext_mech_cpu_out_len('),
                        compute.index('xdev_ext_mech_call('))
        self.assertLess(compute.index('xdev_ext_mech_call('),
                        compute.index('xdev_ext_mech_batch_cpu_length('))
        self.assertIn('EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_compute);', mech)
        has = body(mech, 'xdev_ext_mech_stage_has_member')
        self.assertIn('xdev_ext_mech_ops_has_member(', has)
        self.assertIn('EXPORT_SYMBOL_GPL(xdev_ext_mech_stage_has_member);', mech)
        core = source('io_uring/xdev_ext_mech_core.h')
        legal = body(core, 'xdev_ext_mech_ret_legal')
        self.assertIn('case XDEV_EXT_MECH_MEMBER_COMPUTE:', legal)

    def test_cpu_class(self):
        cpu = source(CPU)
        submit = body(cpu, 'xdev_ext_cpu_submit')
        branch = submit[submit.index('if (xdev_ext_mech_cpu_xform_bpf(cs->selected.xform))'):]
        branch = branch[:branch.index('return 0;') + len('return 0;')]
        self.assertLess(branch.index('xdev_ext_mech_batch_compute(b,'),
                        branch.index('xdev_ext_mech_batch_complete(b, ticket, err);'))
        # Once per batch, terminal, before the per-frame fixed loop.
        self.assertEqual(submit.count('xdev_ext_mech_batch_compute('), 1)
        self.assertLess(submit.index('xdev_ext_mech_batch_compute('),
                        submit.index('xdev_ext_mech_cpu_apply('))
        self.assertNotIn('-EAGAIN', branch)
        bind = body(cpu, 'xdev_ext_cpu_bind')
        self.assertRegex(bind, r'xdev_ext_mech_cpu_xform_bpf\(u->arg0\)\s*&&\s*'
                               r'!xdev_ext_mech_stage_has_member\(st, XDEV_EXT_MECH_MEMBER_COMPUTE\)')
        validate = body(cpu, 'xdev_ext_cpu_validate')
        self.assertRegex(validate, r'xdev_ext_mech_cpu_xform_bpf\(d->xform\)\s*&&\s*'
                                   r'!xdev_ext_mech_stage_has_member\(st, XDEV_EXT_MECH_MEMBER_COMPUTE\)')
        self.assertLess(validate.index('xdev_ext_mech_stage_has_member('),
                        validate.index('cs->staged = b;'))

    def test_declarations(self):
        linux = source(LINUX)
        for name in ('xdev_ext_mech_batch_compute', 'xdev_ext_mech_stage_has_member',
                     'bpf_xdev_ext_frame_len', 'bpf_xdev_ext_frame_rw',
                     'bpf_xdev_ext_frame_set_len'):
            match = re.search(r'\*/\n[^;{}]*\b' + name + r'\(', linux)
            self.assertIsNotNone(match, name)
        call = re.search(r'struct xdev_ext_mech_call {\n(.*?)\n};', linux, re.S).group(1)
        args = re.search(r'struct xdev_ext_mech_call_args {\n(.*?)\n};', linux, re.S).group(1)
        for block in (call, args):
            self.assertRegex(block, r'\bu32 \*out_len;')
            self.assertRegex(block, r'\bs32 len_delta;')
        internal = source('io_uring/xdev_ext_mech_internal.h')
        self.assertRegex(internal, r'bool xdev_ext_mech_ops_has_member\(const void \*ops, u32 member\);')
        tool = source('tools/xdev_ext_mech/xdev_ext_mech_kfunc.h')
        test = source('tools/testing/selftests/bpf/progs/xdev_ext_mech_common.h')
        for name in ('bpf_xdev_ext_frame_len', 'bpf_xdev_ext_frame_rw', 'bpf_xdev_ext_frame_set_len'):
            self.assertRegex(tool, r'extern [^;]*\b' + name + r'\([^;]*\) __ksym;')
            self.assertRegex(test, r'extern [^;]*\b' + name + r'\([^;]*\) __ksym;')
        self.assertIn('__s32 (*compute)(const struct xdev_ext_mech_ctx *ctx);', test)
        self.assertIn('XDEV_EXT_MECH_TEST_OPS(xdev_ext_cpu_mech_ops);', test)
        ctl = source('tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h')
        self.assertIn('"bpf-compute"', ctl)


if __name__ == '__main__':
    unittest.main(verbosity=2)
