#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Record actual compiled artifacts; build receipts never unlock execution alone."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import subprocess

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
BPF_SOURCES=('kernel/tools/xdev_ext_mech/nxp_mech.bpf.c','kernel/tools/xdev_ext_mech/xdev_ext_mech_prog.h',
 'kernel/tools/xdev_ext_mech/xdev_ext_mech_kfunc.h','kernel/include/uapi/linux/xdev_ext_mech.h',
 'kernel/include/uapi/linux/xdev_ext_binding.h')
C_SOURCES=('hft_replay.c','hft_posix.c','hft_uring.c','hft_session.c','hft_runtime.h','hft_core.h','hft_send_zc.h')


def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as stream:
        for data in iter(lambda:stream.read(1048576),b''):h.update(data)
    return h.hexdigest()


def source_digest(paths):
    h=hashlib.sha256()
    for path in paths:
        h.update(str(path.relative_to(ROOT)).encode()+b'\0');h.update(bytes.fromhex(sha(path)))
    return h.hexdigest()


def bpf_source_sha():return source_digest([ROOT/path for path in BPF_SOURCES])
def binary_source_sha():return source_digest([HERE/path for path in C_SOURCES]+[ROOT/path for path in ('kernel/include/uapi/linux/io_uring.h','kernel/include/uapi/linux/stat.h',*BPF_SOURCES[1:])])


def product_sha():
    # Source archives remain useful for software correctness. Never attribute
    # an archive to an enclosing repository's unrelated HEAD.
    try:
        top=subprocess.check_output(['git','-C',str(ROOT),'rev-parse','--show-toplevel'],text=True,stderr=subprocess.DEVNULL).strip()
        if Path(top).resolve()!=ROOT:return None
        head=subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True,stderr=subprocess.DEVNULL).strip()
        return head if re.fullmatch('[0-9a-f]{40}',head) else None
    except (OSError,subprocess.CalledProcessError):return None


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('kind',choices=('binary','bpf'));p.add_argument('--artifact',required=True,type=Path)
    p.add_argument('--btf',type=Path);p.add_argument('--uring',default='0');p.add_argument('--session',default='0')
    a=p.parse_args()
    receipt=dict(schema=1,kind=a.kind,artifact_sha256=sha(a.artifact),
        product_sha=product_sha(),
        source_sha256=binary_source_sha() if a.kind=='binary' else bpf_source_sha())
    if a.kind=='binary':receipt.update(uring=a.uring=='1',session=a.session=='1')
    else:receipt['btf_sha256']=sha(a.btf)
    path=Path(str(a.artifact)+'.build.json');temporary=Path(str(path)+'.tmp')
    temporary.write_text(json.dumps(receipt,sort_keys=True)+'\n');temporary.replace(path)
if __name__=='__main__':main()
