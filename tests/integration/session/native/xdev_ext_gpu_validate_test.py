#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Console oracle of the real-GPU guest cases."""

import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def load():
    spec = importlib.util.spec_from_file_location('gpu_validate', HERE / 'xdev_ext_gpu_validate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CASES = ('ce-chain-d', 'ce-chain-a', 'peer-nvme', 'dmabuf-peer')


GEFORCE_CAPS = 'XDEV_EXT_GPU_CAPS bdf=0000:01:00.0 gpu_direct_rdma=0 dma_buf=0 pointer_rdma=0'
# The case lines xdev_ext_gpu_guest.sh prints for CUDA's refusals.
UNSUPPORTED = {
    'peer-nvme': 'reason=cuda-no-gpudirect-rdma step=register errno=-22 gpu_direct_rdma=0 pointer_rdma=0',
    'dmabuf-peer': 'reason=cuda-no-dma-buf dma_buf_supported=0',
}
# The raw output and kernel lines those refusals leave in the console.
RAW = {
    'peer-nvme': ['XDEV_EXT_GPU_LOG peer-nvme: peer chain: cuda va=0x7f0000000000 bytes=65536',
                  'XDEV_EXT_GPU_LOG peer-nvme: peer chain failed at register: Invalid argument (-22)',
                  '[   14.1] NVRM: XDEV_EXT peer pin: nvidia_p2p_get_pages_persistent failed: -22'],
    'dmabuf-peer': ['XDEV_EXT_GPU_LOG dmabuf-peer: XDEV_EXT_GPU_DMABUF device=0000:01:00.0 dma_buf_supported=0'],
}


# A CE window is a cuMemAlloc block only where CUDA reports GPUDirect RDMA;
# elsewhere it is a VMM allocation whose POSIX-FD export each CE stage fd
# carries.  The guest prints the mode on the case line, the tool its lines.
def ce_lines(name, mode):
    attach = ' mapped=2097152 export=posix-fd attached=2' if mode == 'vmm' else ''
    raw = [f'XDEV_EXT_GPU_LOG {name}: CUDA allocation={mode} bdf=0000:01:00.0 '
           f'va=0x7a4879200000 bytes=1048576{attach}',
           f'XDEV_EXT_GPU_LOG {name}: CUDA allocation={mode} released=yes']
    tail = f'groups=2 allocation={mode}' if name == 'ce-chain-d' else \
        f'bytes=32768 allocation={mode} compare=equal'
    return raw, tail


def console(results=None, modules='PASS', unload='XDEV_EXT_GPU_UNLOAD=PASS', extra='', caps=None,
            ce_mode=None):
    results = dict.fromkeys(CASES, 'PASS') if results is None else results
    failed = sum(value not in ('PASS', 'UNSUPPORTED') for value in results.values())
    unsupported = sum(value == 'UNSUPPORTED' for value in results.values())
    summary = 'FAIL' if failed else 'UNSUPPORTED' if unsupported else 'PASS'
    lines = ['[    1.0] boot',
             f'XDEV_EXT_GPU_MODULES={modules} release=590.48.01 device=10de:2b85 bdf=0000:01:00.0']
    if caps:
        if 'probe=failed' not in caps:
            lines.append('XDEV_EXT_GPU_LOG caps: ' + caps)
        lines.append(caps)
    mode = ce_mode or ('native' if caps and ' gpu_direct_rdma=1' in caps else 'vmm')
    for name, value in results.items():
        if value == 'UNSUPPORTED':
            lines += RAW.get(name, [])
        tail = 'bytes=32768'
        if value == 'PASS' and name.startswith('ce-chain-'):
            raw, tail = ce_lines(name, mode)
            lines += raw
        lines.append(f'XDEV_EXT_GPU_CASE name={name} result={value} ' +
                     (UNSUPPORTED.get(name, 'reason=none') if value == 'UNSUPPORTED' else tail))
    lines.append(f'XDEV_EXT_GPU_GUEST={summary} failed={failed} unsupported={unsupported}')
    lines.append(extra)
    lines.append(unload)
    return '\n'.join(lines) + '\n'


class GpuConsole(unittest.TestCase):
    def setUp(self):
        self.mod = load()

    def test_all_cases_and_clean_unload_pass(self):
        result = self.mod.validate(console(), release='590.48.01', device='10de:2b85')
        self.assertEqual(result['verdict'], 'PASS')
        self.assertEqual(result['cases'], dict.fromkeys(CASES, 'PASS'))

    def test_failed_case_is_reported_by_name(self):
        text = console(dict(zip(CASES, ('PASS', 'PASS', 'FAIL', 'PASS'))))
        result = self.mod.validate(text, release='590.48.01', device='10de:2b85')
        self.assertEqual(result['verdict'], 'FAIL')
        self.assertEqual(result['cases']['peer-nvme'], 'FAIL')
        self.assertIn('peer-nvme', ' '.join(result['problems']))

    def test_missing_case_line_fails(self):
        text = console({'ce-chain-d': 'PASS', 'ce-chain-a': 'PASS', 'peer-nvme': 'PASS'})
        result = self.mod.validate(text, release='590.48.01', device='10de:2b85')
        self.assertEqual(result['verdict'], 'FAIL')
        self.assertEqual(result['cases']['dmabuf-peer'], 'MISSING')

    def test_unclean_unload_fails_even_when_cases_pass(self):
        text = console(unload='XDEV_EXT_GPU_UNLOAD=FAIL module=nvidia refcnt=1 holders=')
        result = self.mod.validate(text, release='590.48.01', device='10de:2b85')
        self.assertEqual(result['verdict'], 'FAIL')
        self.assertFalse(result['unload_clean'])

    def test_wrong_release_or_device_fails(self):
        for kwargs in (dict(release='595.99.02', device='10de:2b85'),
                       dict(release='590.48.01', device='10de:2bb1')):
            with self.subTest(**kwargs):
                self.assertEqual(self.mod.validate(console(), **kwargs)['verdict'], 'FAIL')

    def test_module_load_failure_fails(self):
        text = 'XDEV_EXT_GPU_MODULES=FAIL step=insmod-nvidia release=590.48.01\nXDEV_EXT_GPU_UNLOAD=PASS\n'
        result = self.mod.validate(text, release='590.48.01', device='10de:2b85')
        self.assertEqual(result['verdict'], 'FAIL')
        self.assertEqual(result['modules'], 'FAIL')

    def test_gpu_fault_reports_fail(self):
        for line in ('NVRM: Xid (PCI:0000:01:00): 31, pid=12, name=ctl, Ch 00000008',
                     'NVRM: RmInitAdapter failed! (0x22:0x56:885)',
                     'NVRM: GPU 0000:01:00.0: RmInitAdapter failed!'):
            with self.subTest(line=line):
                result = self.mod.validate(console(extra=line), release='590.48.01',
                                           device='10de:2b85')
                self.assertEqual(result['verdict'], 'FAIL')
                self.assertTrue(result['gpu_errors'])

    def test_rm_lock_assertions_are_gpu_errors(self):
        # RM asserts these when a thread was left owning its locks; RM then
        # waits on that thread forever (the RTX 5090 window at 6787f2e).
        for line in ('[    8.713738] NVRM: nvAssertFailedNoLog: Assertion failed: '
                     'GPU lock already acquired by this thread @ locks.c:992',
                     '[    8.754063] NVRM: nvAssertFailedNoLog: Assertion failed: '
                     'rmGpuLocksGetOwnedMask() == 0 @ rmapi.c:566'):
            with self.subTest(line=line):
                result = self.mod.validate(console(extra=line), release='590.48.01',
                                           device='10de:2b85')
                self.assertEqual(result['verdict'], 'FAIL')
                self.assertEqual(result['gpu_errors'], [line])

    def test_duplicate_case_line_fails(self):
        text = console() + 'XDEV_EXT_GPU_CASE name=ce-chain-a result=PASS\n'
        result = self.mod.validate(text, release='590.48.01', device='10de:2b85')
        self.assertEqual(result['verdict'], 'FAIL')

    def geforce(self, **changes):
        results = dict(zip(CASES, ('PASS', 'PASS', 'UNSUPPORTED', 'UNSUPPORTED')))
        results.update(changes)
        return results

    def test_cuda_refusals_with_capability_evidence_are_unsupported_not_pass(self):
        text = console(self.geforce(), caps=GEFORCE_CAPS)
        result = self.mod.validate(text, release='590.48.01', device='10de:2b85')
        self.assertEqual(result['verdict'], 'UNSUPPORTED')
        self.assertEqual(result['unsupported'], ['dmabuf-peer', 'peer-nvme'])
        self.assertEqual(result['problems'], [])
        self.assertEqual(result['caps']['gpu_direct_rdma'], '0')

    def test_an_unsupported_verdict_never_exits_zero(self):
        with tempfile.TemporaryDirectory(prefix='gpu-validate-') as directory:
            log, out = Path(directory) / 'guest.log', Path(directory) / 'result.json'
            log.write_text(console(self.geforce(), caps=GEFORCE_CAPS))
            with contextlib.redirect_stdout(io.StringIO()) as printed:
                status = self.mod.main([str(log), str(out), '--release', '590.48.01',
                                        '--device', '10de:2b85'])
        self.assertEqual(status, 1)
        self.assertIn('XDEV_EXT_GPU_VFIO=UNSUPPORTED ', printed.getvalue())

    def test_unsupported_without_matching_cuda_evidence_fails(self):
        for name, caps, results in (
                ('no capability line', None, self.geforce()),
                ('CUDA reports RDMA and dma_buf',
                 'XDEV_EXT_GPU_CAPS bdf=0000:01:00.0 gpu_direct_rdma=1 dma_buf=1 pointer_rdma=1', self.geforce()),
                ('block RDMA-capable', GEFORCE_CAPS.replace('pointer_rdma=0', 'pointer_rdma=1'),
                 self.geforce(**{'dmabuf-peer': 'PASS'})),
                ('probe failed', 'XDEV_EXT_GPU_CAPS bdf=0000:01:00.0 probe=failed', self.geforce()),
                ('a CE chain is never unsupported', GEFORCE_CAPS, self.geforce(**{'ce-chain-d': 'UNSUPPORTED'}))):
            with self.subTest(name):
                result = self.mod.validate(console(results, caps=caps), release='590.48.01',
                                           device='10de:2b85')
                self.assertEqual(result['verdict'], 'FAIL')
                self.assertIn('UNSUPPORTED without', ' '.join(result['problems']))

    def test_unsupported_needs_the_raw_refusal_in_the_console(self):
        # The guest's own labels are not evidence: the tool output and the
        # kernel line from NVIDIA's persistent pin must be there as well.
        for name, line in (('no NVIDIA pin refusal in the kernel log', RAW['peer-nvme'][2]),
                           ('no raw REGISTER failure', RAW['peer-nvme'][1]),
                           ('no raw dma_buf refusal', RAW['dmabuf-peer'][0]),
                           ('CAPS line without the probe output', 'XDEV_EXT_GPU_LOG caps: ' + GEFORCE_CAPS)):
            with self.subTest(name):
                text = console(self.geforce(), caps=GEFORCE_CAPS).replace(line + '\n', '')
                result = self.mod.validate(text, release='590.48.01', device='10de:2b85')
                self.assertEqual(result['verdict'], 'FAIL')
                self.assertIn('UNSUPPORTED without', ' '.join(result['problems']))

    def test_unsupported_reason_must_match_the_case(self):
        text = console(self.geforce(), caps=GEFORCE_CAPS).replace(
            'step=register errno=-22', 'step=create errno=-22')
        result = self.mod.validate(text, release='590.48.01', device='10de:2b85')
        self.assertEqual(result['verdict'], 'FAIL')
        self.assertIn('peer-nvme', ' '.join(result['problems']))

    def test_a_failed_case_beside_unsupported_ones_fails(self):
        text = console(self.geforce(**{'ce-chain-a': 'FAIL'}), caps=GEFORCE_CAPS)
        result = self.mod.validate(text, release='590.48.01', device='10de:2b85')
        self.assertEqual(result['verdict'], 'FAIL')
        self.assertIn('case ce-chain-a FAIL', result['problems'])

    def test_ce_chains_pass_through_the_vmm_export_where_cuda_has_no_rdma(self):
        text = console(self.geforce(), caps=GEFORCE_CAPS)
        self.assertIn('allocation=vmm', text)
        result = self.mod.validate(text, release='590.48.01', device='10de:2b85')
        self.assertEqual(result['verdict'], 'UNSUPPORTED')
        self.assertEqual(result['cases']['ce-chain-d'], 'PASS')
        self.assertEqual(result['cases']['ce-chain-a'], 'PASS')
        self.assertEqual(result['problems'], [])

    def test_ce_allocation_must_be_the_one_cuda_capabilities_select(self):
        rdma = 'XDEV_EXT_GPU_CAPS bdf=0000:01:00.0 gpu_direct_rdma=1 dma_buf=1 pointer_rdma=1'
        for name, caps, mode in (('native on a GPU without RDMA', GEFORCE_CAPS, 'native'),
                                 ('vmm where RDMA resolves cuMemAlloc', rdma, 'vmm'),
                                 ('unknown mode', GEFORCE_CAPS, 'pinned')):
            with self.subTest(name):
                results = self.geforce() if caps == GEFORCE_CAPS else None
                result = self.mod.validate(console(results, caps=caps, ce_mode=mode),
                                           release='590.48.01', device='10de:2b85')
                self.assertEqual(result['verdict'], 'FAIL')
                self.assertIn('allocation', ' '.join(result['problems']))

    def test_ce_pass_needs_the_tools_own_allocation_lines(self):
        base = console(self.geforce(), caps=GEFORCE_CAPS)
        for name, case in (('no attach line', 'ce-chain-d'), ('no release line', 'ce-chain-a')):
            with self.subTest(name):
                raw, _ = ce_lines(case, 'vmm')
                line = raw[0] if name == 'no attach line' else raw[1]
                result = self.mod.validate(base.replace(line + '\n', ''),
                                           release='590.48.01', device='10de:2b85')
                self.assertEqual(result['verdict'], 'FAIL')
                self.assertIn(case, ' '.join(result['problems']))

    def test_ce_chain_a_pass_needs_the_equal_byte_comparison(self):
        text = console(self.geforce(), caps=GEFORCE_CAPS).replace(
            'allocation=vmm compare=equal', 'allocation=vmm')
        result = self.mod.validate(text, release='590.48.01', device='10de:2b85')
        self.assertEqual(result['verdict'], 'FAIL')
        self.assertIn('ce-chain-a', ' '.join(result['problems']))

    def test_a_guest_problem_line_fails_and_is_reported(self):
        # The guest stops its GPU cases after a step past its limit or RM lock
        # assertions; the validator names the problem, whatever the cases say.
        for line, words in (('XDEV_EXT_GPU_PROBLEM case=ce-chain-d reason=timeout limit_s=120',
                             'ce-chain-d reason=timeout'),
                            ('XDEV_EXT_GPU_PROBLEM case=ce-chain-a reason=rm-lock-state',
                             'ce-chain-a reason=rm-lock-state')):
            with self.subTest(line=line):
                result = self.mod.validate(console(extra=line), release='590.48.01',
                                           device='10de:2b85')
                self.assertEqual(result['verdict'], 'FAIL')
                self.assertIn(words, ' '.join(result['problems']))

    def test_prefixed_tool_output_is_not_mistaken_for_verdicts(self):
        text = console({'ce-chain-d': 'PASS', 'ce-chain-a': 'PASS', 'peer-nvme': 'PASS'})
        text += 'XDEV_EXT_GPU_LOG peer: XDEV_EXT_GPU_CASE name=dmabuf-peer result=PASS\n'
        result = self.mod.validate(text, release='590.48.01', device='10de:2b85')
        self.assertEqual(result['cases']['dmabuf-peer'], 'MISSING')


if __name__ == '__main__':
    unittest.main()
