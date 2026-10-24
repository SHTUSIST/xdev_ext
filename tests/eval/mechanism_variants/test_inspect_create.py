# SPDX-License-Identifier: GPL-2.0
"""Synthetic audit selfchecks, not a successful actual CREATE."""
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
HERE=Path(__file__).resolve().parent

class Inspect(unittest.TestCase):
    def setUp(self):
        self.assertTrue((HERE/'inspect_create.py').is_file(),'raw CREATE audit helper missing')
        spec=importlib.util.spec_from_file_location('inspect_create',HERE/'inspect_create.py')
        self.module=importlib.util.module_from_spec(spec); spec.loader.exec_module(self.module)
    def fixture(self,path,fd_shift=0,nlb=64):
        raw=bytearray(200)
        struct.pack_into('<IIIi',raw,0,1,2,1,5+fd_shift)
        struct.pack_into('<IIII',raw,16,4096,88,1432,4096)
        struct.pack_into('<Ii',raw,32,1,6+fd_shift)
        struct.pack_into('<IIiIQQ',raw,64,3,2,7+fd_shift,0,2048,nlb)
        struct.pack_into('<IIiIQQ',raw,96,2,1,5+fd_shift,0,0,0)
        Path(str(path)+'.before').write_bytes(raw)
        struct.pack_into('<Q',raw,192,42+fd_shift)
        Path(str(path)+'.after').write_bytes(raw)
        resources={role:dict(fd=fd+fd_shift,file_type=typ,rdev_major=major,rdev_minor=minor,inode=123+fd_shift,socket_family=family)
                   for role,fd,typ,major,minor,family in [('pool',5,49152,0,0,44),('eventfd',6,0,0,0,0),('stage0',7,8192,241,1,0),('stage1',5,49152,0,0,44)]}
        Path(str(path)+'.resources.json').write_text(json.dumps(resources))
        Path(str(path)+'.result.json').write_text(json.dumps(dict(syscall_return=0,errno=0,session_id=42+fd_shift)))
    def test_preserves_bounds_and_resources_while_normalizing_only_ephemeral_identity(self):
        with tempfile.TemporaryDirectory() as td:
            a,b=Path(td)/'a',Path(td)/'b'
            self.fixture(a); self.fixture(b,fd_shift=20)
            self.assertEqual(self.module.inspect(a)['create'],self.module.inspect(b)['create'])
            self.fixture(b,fd_shift=20,nlb=63)
            self.assertNotEqual(self.module.inspect(a)['create'],self.module.inspect(b)['create'])
            self.fixture(b,fd_shift=20)
            path=Path(str(b)+'.resources.json'); data=json.loads(path.read_text()); data['stage0']['rdev_minor']=2; path.write_text(json.dumps(data))
            self.assertNotEqual(self.module.inspect(a)['create'],self.module.inspect(b)['create'])
    def test_failed_syscall_or_changed_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            a=Path(td)/'a'; self.fixture(a)
            path=Path(str(a)+'.result.json'); result=json.loads(path.read_text()); result['syscall_return']=-1; result['errno']=1; path.write_text(json.dumps(result))
            with self.assertRaises(ValueError): self.module.inspect(a)
            self.fixture(a); path=Path(str(a)+'.after'); data=bytearray(path.read_bytes()); data[88]^=1; path.write_bytes(data)
            with self.assertRaises(ValueError): self.module.inspect(a)
if __name__=='__main__': unittest.main()
