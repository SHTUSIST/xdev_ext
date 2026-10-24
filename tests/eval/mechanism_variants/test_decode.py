# SPDX-License-Identifier: GPL-2.0
"""Synthetic parser selfchecks only; never guest execution evidence."""
import importlib.util
import json
import struct
import subprocess
import tempfile
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


def row(phase, frame, generation, ticket, cookie, stage=0, status=0, ts=1):
    fields = dict(abi='xdev-native-v1-nvme-xsk-batch', phase=phase, origin='K',
                  session_id=7, batch_id=1, batch_key=1, frame_id=frame,
                  generation=generation, stage=stage, ticket=ticket,
                  class_id=3 if stage == 0 else 2, accepted=int(status == 0), status=status,
                  cookie=cookie, address=2080, bytes=4096, aux=2 | (7 << 8),
                  sequence=0, ts_ns=ts)
    return ' worker-5 [001] ... 1.0: native_event: ' + ' '.join(f'{k}={v}' for k,v in fields.items())


class Decode(unittest.TestCase):
    def setUp(self):
        path = HERE / 'decode_trace.py'
        self.assertTrue(path.is_file(), 'real trace decoder is missing')
        spec = importlib.util.spec_from_file_location('decoder', path)
        self.decoder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.decoder)

    def positive(self):
        result=[]
        for i,(phase,gen,ticket,cookie,stage) in enumerate([
            ('class_validate',0,0,0,0), ('native_submit',1,10,4096,0),
            ('native_complete',1,10,4096,0), ('downstream_complete',2,11,0,1),
            ('frame_recycle',2,11,0,1)]):
            for frame in (8,9):
                line=row(phase,frame,gen,ticket,cookie,stage,ts=i*10+frame)
                if stage == 1:
                    line=line.replace('address=2080',f'address={frame*4096+88}').replace('bytes=4096','bytes=2048')
                result.append(line)
        return '\n'.join(result)

    def test_actual_fields_aggregate_without_future_ticket_or_frame_renumber(self):
        events = self.decoder.decode(self.positive(), 'nvme_nic')
        self.assertEqual([e['event'] for e in events], [
            'class_validate','provider_accept','native_complete','downstream_complete','frame_recycle'])
        self.assertEqual(events[0]['ticket'], 0)
        self.assertEqual(events[1]['frames'], [8,9])
        self.assertEqual(events[1]['frame_generations'], [1,1])
        self.assertEqual(events[3]['frame_generations'], [2,2])
        self.assertEqual((events[1]['slba'],events[1]['nlb'],events[1]['bytes']), (2080,8,4096))
        self.assertEqual(events[1]['cookie'],4096)
        self.assertEqual(events[1]['request_id'],1)

    def test_reject_missing_duplicate_or_changed_claim(self):
        valid = self.positive()
        for corrupt in (valid.replace('ticket=10','ticket=12',1),
                        valid.replace('accepted=1','accepted=0',2),
                        valid + '\n' + valid.splitlines()[2],
                        '\n'.join(valid.splitlines()[:-1]),
                        valid.replace('abi=xdev-native-v1-nvme-xsk-batch','abi=unknown',1)):
            with self.subTest(corrupt=corrupt[-80:]):
                with self.assertRaises(ValueError):
                    self.decoder.decode(corrupt,'nvme_nic')

    def test_cli_binds_actual_create_result_session(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td); prefix=p/'create'
            raw=bytearray(200)
            struct.pack_into('<IIIi',raw,0,1,1,1,-1)
            struct.pack_into('<i',raw,36,-1)
            struct.pack_into('<i',raw,72,-1)
            Path(str(prefix)+'.before').write_bytes(raw)
            struct.pack_into('<Q',raw,192,42)
            Path(str(prefix)+'.after').write_bytes(raw)
            resource=dict(fd=-1,file_type=0,rdev_major=0,rdev_minor=0,inode=0,socket_family=0)
            Path(str(prefix)+'.resources.json').write_text(json.dumps({k:resource for k in ('pool','eventfd','stage0')}))
            Path(str(prefix)+'.result.json').write_text(json.dumps(dict(syscall_return=0,errno=0,session_id=42)))
            (p/'trace').write_text(self.positive())
            (p/'format').write_text('xdev-native-v1-nvme-xsk-batch u64 ticket; u64 cookie; u64 generation; u64 ts_ns;')
            (p/'stats').write_text('overrun: 0\ncommit overrun: 0\n')
            cmd=['python3',str(HERE/'decode_trace.py'),str(p/'trace'),str(p/'events'),
                 '--format',str(p/'format'),'--stats',str(p/'stats'),'--create-prefix',str(prefix)]
            run=subprocess.run(cmd,capture_output=True,text=True)
            self.assertEqual(run.returncode,1)
            self.assertIn('CREATE session',run.stderr)
            self.assertFalse((p/'events').exists())

    def test_negative_keeps_actual_rejection_and_zero_acceptance(self):
        raw='\n'.join(row('class_validate',i,0,0,0,status=-34,ts=i+1) for i in (8,9))
        negative=self.decoder.decode_negative(raw)
        self.assertEqual(negative['result'],-34)
        self.assertEqual(negative['accepted_during_capture'],0)
        with self.assertRaises(ValueError):
            self.decoder.decode_negative(raw+'\n'+row('native_submit',8,1,10,4096,ts=30))

if __name__ == '__main__':
    unittest.main()
