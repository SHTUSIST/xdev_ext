# SPDX-License-Identifier: GPL-2.0
import importlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path[:0] = [str(ROOT/'src/compute/torch'), str(ROOT/'src/compute/vllm')]


class BootstrapConfigTests(unittest.TestCase):
    def module(self):
        import importlib.util
        self.assertIsNotNone(importlib.util.find_spec('xdev_tp_torch.config'),
                             'shipped non-pointer bootstrap configuration absent')
        return importlib.import_module('xdev_tp_torch.config')

    def options(self, **changes):
        data = dict(version=1, rank=0, world_size=2, device_index=1, mode=1,
            nvidia_node='/dev/nvidia0', bpf_object=__file__, user_bpf_object=__file__, ptx_path=__file__,
            link_token=7, allocation_bytes=65536, group_bytes=4096, depth=1,
            nr_batches=10, first_sequence=1, timeout_ns=10**9,
            communicator_id=11, epoch=2, max_payload_bytes=4000)
        data.update(changes)
        return data

    def test_valid_shipped_options_preserve_admission_values(self):
        module = self.module()
        cfg = module.validate_options(self.options(), rank=0, device_index=1, environ={})
        self.assertEqual(cfg['link_token'], 7)
        self.assertEqual(cfg['group_bytes'], 4096)

    def test_serialized_native_pointer_options_are_rejected(self):
        module = self.module()
        for key in ['context', 'stream', 'tx_endpoint', 'rx_endpoint', 'tx_va', 'd2_tx_producer']:
            with self.subTest(key=key), self.assertRaises(ValueError):
                module.validate_options(self.options(**{key: 123}), rank=0, device_index=1, environ={})

    def test_rank_device_geometry_and_depth_fail_before_owner_open(self):
        module = self.module()
        for changes in [dict(rank=1), dict(device_index=0), dict(world_size=4),
                        dict(mode=1, depth=2), dict(allocation_bytes=1024),
                        dict(group_bytes=63), dict(max_payload_bytes=4096),
                        dict(first_sequence=0), dict(epoch=0), dict(timeout_ns=-1),
                        dict(link_token=True), dict(unrecognized=1)]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                module.validate_options(self.options(**changes), rank=0, device_index=1, environ={})

    def test_d2_requires_same_actual_control_ptx_environment(self):
        module = self.module()
        cfg = self.options(mode=2, control_ptx_path=__file__)
        with self.assertRaises(ValueError):
            module.validate_options(cfg, rank=0, device_index=1, environ={})
        got = module.validate_options(cfg, rank=0, device_index=1,
                                     environ={'XDEV_EXT_CUDA_PTX': __file__})
        self.assertEqual(got['mode'], 2)

    def test_actual_owner_geometry_accepts_header_only_64_byte_group(self):
        module = self.module()
        got = module.validate_options(self.options(group_bytes=64, max_payload_bytes=0),
                                      rank=0, device_index=1, environ={})
        self.assertEqual(got['group_bytes'], 64)

    def test_actual_owner_requires_64k_allocation_alignment(self):
        module = self.module()
        with self.assertRaises(ValueError):
            module.validate_options(self.options(allocation_bytes=8192), rank=0, device_index=1, environ={})

    def test_control_plane_agreement_excludes_rank_local_pointers_and_paths(self):
        module = self.module()
        left = module.agreement_key(self.options())
        right = module.agreement_key(self.options(rank=1, device_index=0,
                            nvidia_node='/dev/nvidia1', link_token=8))
        self.assertEqual(left, right)
        self.assertNotEqual(left, module.agreement_key(self.options(epoch=9)))



class DefaultWorkerFactoryTests(unittest.TestCase):
    def test_actual_factory_agrees_before_native_owner_bootstrap(self):
        self.run_factory(mismatch=False)

    def test_peer_mismatch_never_opens_native_owner(self):
        self.run_factory(mismatch=True)

    def test_peer_not_ready_blocks_payload_publication(self):
        self.run_factory(mismatch=False, peer_not_ready=True)

    def run_factory(self, *, mismatch, peer_not_ready=False):
        from contextlib import nullcontext
        import json
        import os
        import tempfile
        import types
        from unittest.mock import patch
        from xdev_tp_torch import TorchCommunicator
        from xdev_tp_vllm.bootstrap import create_backend
        calls = []
        def agreement(peers, local, group):
            calls.append('agreement' if 'configuration' in local else 'ready')
            peers[0] = local
            peers[1] = dict(local, rank=1)
            if peer_not_ready and 'ready' in local:
                peers[1]['ready'] = False
            if mismatch and 'configuration' in local:
                peers[1]['configuration'] = dict(local['configuration'], epoch=99)
        torch = types.SimpleNamespace(cuda=types.SimpleNamespace(
            device=lambda d: nullcontext(), current_device=lambda: 1),
            distributed=types.SimpleNamespace(all_gather_object=agreement))
        comm = types.SimpleNamespace(device=1, rank_in_group=0, unique_name='tp:0', cpu_group=object())
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path = Path(directory)/'rank-0-tp:0.json'
            path.write_text(json.dumps(BootstrapConfigTests().options()))
            def open_owner(config):
                calls.append('owner_open')
                return types.SimpleNamespace(close=lambda: calls.append('owner_close'))
            with patch.dict(sys.modules, {'torch': torch}), patch.dict(os.environ,
                {'XDEV_TP_CONFIG': str(Path(directory)/'rank-{rank}-{group}.json')}, clear=False), \
                patch.object(TorchCommunicator, 'from_options', side_effect=open_owner):
                if mismatch:
                    with self.assertRaises(RuntimeError): create_backend(comm)
                    self.assertEqual(calls, ['agreement'])
                elif peer_not_ready:
                    with self.assertRaises(RuntimeError): create_backend(comm)
                    self.assertEqual(calls, ['agreement', 'owner_open', 'ready', 'owner_close'])
                else:
                    create_backend(comm)
                    self.assertEqual(calls, ['agreement', 'owner_open', 'ready'])

if __name__ == '__main__': unittest.main(verbosity=2)
