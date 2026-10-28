#!/usr/bin/env python3
"""An actual ordinary application must not silently take the old SEND arm."""
from pathlib import Path
import os
import subprocess
import sys

HERE=Path(__file__).resolve().parent
OUT=Path(os.environ.get('XDEV_EXT_PRELOAD_TEST_DIR',str(HERE)))
env=dict(os.environ,LD_PRELOAD=str(OUT/'libio_uring_unified.so'),
         XDEV_EXT_PRELOAD_SOCKET_ENABLED='1',XDEV_EXT_PRELOAD_SOCKET_MECH='1',
         XDEV_EXT_PRELOAD_REPORT='1')
r=subprocess.run([str(OUT/'xdev_ext_preload_mech_workload'),'base'],env=env,text=True,capture_output=True,timeout=30)
sys.stdout.write(r.stdout+r.stderr)
if r.returncode or 'XDEV_EXT_PRELOAD_MECH_REPORT ' not in r.stderr:
    sys.exit('FAIL: ordinary repeated app calls did not enter the requested new mechanism')
