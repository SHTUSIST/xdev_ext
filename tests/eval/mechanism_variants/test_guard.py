# SPDX-License-Identifier: GPL-2.0
"""Actual host-memory snapshot checks, never guest/AF_XDP evidence."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
HERE=Path(__file__).resolve().parent
class Guard(unittest.TestCase):
    def setUp(self):
        self.assertTrue((HERE/'guard.py').is_file(),'independent guard-byte verifier missing')
        spec=importlib.util.spec_from_file_location('guard',HERE/'guard.py')
        self.module=importlib.util.module_from_spec(spec); spec.loader.exec_module(self.module)
    def test_actual_memory_bytes_and_unclaimed_frame_corruption(self):
        subprocess.run(['make','-s','-C',str(HERE),'.build/test_umem_guard'],check=True)
        with tempfile.TemporaryDirectory() as td:
            prefix=Path(td)/'guard'
            subprocess.run([str(HERE/'.build/test_umem_guard'),str(prefix),'good'],check=True)
            events=[dict(event='downstream_complete',frames=[0],frame_addresses=[88],frame_bytes=[64])]
            self.module.verify(prefix,events,42,dict(frame_size=4096,hdr_room=88,seg_len=64,group_bytes=64))
            after=Path(str(prefix)+'.umem.after'); raw=bytearray(after.read_bytes()); raw[4096+88]^=1; after.write_bytes(raw)
            with self.assertRaises(ValueError): self.module.verify(prefix,events,42,dict(frame_size=4096,hdr_room=88,seg_len=64,group_bytes=64))
    def test_corrupted_guard_or_failed_stop_rejects(self):
        with tempfile.TemporaryDirectory() as td:
            prefix=Path(td)/'guard'
            subprocess.run([str(HERE/'.build/test_umem_guard'),str(prefix),'corrupt'],check=True)
            events=[dict(event='downstream_complete',frames=[0],frame_addresses=[88],frame_bytes=[64])]
            with self.assertRaises(ValueError): self.module.verify(prefix,events,42,dict(frame_size=4096,hdr_room=88,seg_len=64,group_bytes=64))
if __name__=='__main__': unittest.main()
