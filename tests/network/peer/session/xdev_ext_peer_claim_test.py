#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute actual allocation-fd exclusive authority code with file adapters."""
from pathlib import Path
import importlib.util
import subprocess
import tempfile
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('peer_lifetime', HERE/'independent_peer_lifetime.py')
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
core=module.KERNEL/'io_uring/xdev_ext_peer.c'
fd=module.actual_fd_code()
shim=module.SHIM
helpers=module.MAIN[:module.MAIN.index('int main(void)')]
fallback=''
if 'struct file *xdev_ext_peer_file_claim(' not in fd:
    fallback=r'''struct file *xdev_ext_peer_file_claim(struct file *f, u64 *len, u64 *gen) { (void)f;(void)len;(void)gen; return ERR_PTR(-ENOSYS); }'''
main=r'''
int main(void)
{
 (void)&wrong_fops;
 struct file original; struct file *authority; struct pci_dev peer={0};
 struct xdev_ext_peer_fd_lease h={}; u64 len,gen;
 assert(xdev_ext_peer_provider_register(&ops)==0);
 original=allocation(region());
 authority=xdev_ext_peer_file_claim(&original,&len,&gen);
 assert(!IS_ERR(authority));
 assert(len==131072 && gen && original.refs==2);
 assert(PTR_ERR(xdev_ext_peer_file_claim(&original,&len,&gen))==-EBUSY);
 assert(xdev_ext_peer_file_acquire(&original,&peer,gen,0,512,DMA_TO_DEVICE,&h)==-EBUSY);
 assert(xdev_ext_peer_file_acquire(authority,&peer,gen+1,0,512,DMA_TO_DEVICE,&h)==-ESTALE);
 assert(xdev_ext_peer_file_acquire(authority,&peer,gen,0,512,DMA_TO_DEVICE,&h)==0);
 xdev_ext_peer_fd_release(&h,true);
 fput(authority); assert(original.refs==1);
 assert(xdev_ext_peer_file_acquire(&original,&peer,gen,0,512,DMA_TO_DEVICE,&h)==0);
 xdev_ext_peer_fd_release(&h,true); fput(&original);
 assert(unmaps==1 && unpins==1);
 puts("ok 1 - exclusive mechanism authority rejects ordinary fd/duplicate claim and preserves generation and exact file refs");
 original=allocation(region()); gen=xdev_ext_peer_generation(((struct xdev_ext_peer_fd *)original.private_data)->region);
 rawio=false; assert(PTR_ERR(xdev_ext_peer_file_claim(&original,&len,&gen))==-EPERM); rawio=true;
 authority=xdev_ext_peer_file_claim(&original,&len,&gen); assert(!IS_ERR(authority));
 assert(xdev_ext_peer_file_acquire(authority,&peer,gen,0,512,DMA_TO_DEVICE,&h)==0);
 xdev_ext_peer_fd_release(&h,false); fput(authority);
 assert(original.refs==2);
 assert(PTR_ERR(xdev_ext_peer_file_claim(&original,&len,&gen))==-EBUSY);
 assert(xdev_ext_peer_file_acquire(&original,&peer,gen,0,512,DMA_TO_DEVICE,&h)==-EBUSY);
 fput(&original); assert(original.refs==1 && unmaps==1 && unpins==1);
 puts("ok 2 - unknown DMA retains claim owner and original file permanently; privilege checked at claim");
 return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='xdev-peer-claim-') as directory:
    p=Path(directory); (p/'test.c').write_text(shim+'\n#define XDEV_EXT_PEER_HOST_TEST\n#include "'+str(core)+'"\n'+fd+fallback+helpers+main)
    subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-function','-fsanitize=undefined','-pthread',str(p/'test.c'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True)
