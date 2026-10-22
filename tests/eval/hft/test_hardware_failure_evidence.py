#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Pure failure cleanup evidence: no socket, device, clock or performance run."""
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest

import hardware_measure as hardware

HERE=Path(__file__).resolve().parent


class FailedPeerEvidenceTests(unittest.TestCase):
    def test_failed_peer_close_retains_capture_and_error_receipt(self):
        with tempfile.TemporaryDirectory(prefix='.failure-evidence-',dir=HERE) as parent:
            directory=Path(parent)/'owned-run';directory.mkdir(mode=0o700)
            capture=directory/'capture.bin';capture.write_bytes(b'partial independent capture sentinel')
            peer=object.__new__(hardware.PeerRun)
            peer.temp=SimpleNamespace(name=str(directory),cleanup=lambda:shutil.rmtree(directory))
            peer.directory=directory
            peer.capture=capture;peer.output=capture.open('ab')
            peer.stop=SimpleNamespace(set=lambda:None)
            peer.thread=SimpleNamespace(join=lambda timeout:None,is_alive=lambda:False)
            peer.udp=SimpleNamespace(close=lambda:None)
            peer.finished=False;peer.capture_streamed=False;peer.streamed=False
            peer.error=ValueError('fixture corrupt packet; no hardware executed')
            peer.identity={'token':'1'*32,'session_base':1234}
            peer.close()
            self.assertTrue(capture.is_file(),'failed peer capture was deleted')
            self.assertEqual(capture.read_bytes(),b'partial independent capture sentinel')
            failure=directory/'failure.json'
            self.assertTrue(failure.is_file(),'failed peer diagnostic was not retained')
            result=json.loads(failure.read_text())
            self.assertEqual(result['status'],'error')
            self.assertIn('fixture corrupt packet',result['diagnostic'])


if __name__=='__main__':unittest.main()
