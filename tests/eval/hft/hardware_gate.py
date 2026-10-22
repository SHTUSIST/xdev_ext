#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Observe local evidence; never accept CLI physical-proof fixtures."""
import gzip
import json
import os
from pathlib import Path
import re
import stat
import subprocess

import hardware_build as build
import oracle
import run as correctness

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
BIN=HERE/'.build/hft_replay'


def refuse(message,status='not_run_hardware'):raise correctness.Failure(status,message)
def read(path):return Path(path).read_text().strip()
def command(argv):
    p=subprocess.run(argv,text=True,capture_output=True,timeout=30)
    if p.returncode:refuse('observed provisioning command unavailable: '+str(argv[0]),'not_run_capability')
    return p.stdout.strip()


def required(args,role):
    common=('ifname','kernel_config','product_sha')
    extra=('bind','data_bind') if role=='peer' else ('peer_control','source_block','source_ng','local_ip','peer_ip','local_mac','peer_mac','local_port','peer_port','bpf_object','reference','nlb')
    if any(not getattr(args,key,None) for key in (*common,*extra)):refuse('explicit preprovisioned '+role+' configuration required')
    if role=='producer' and (args.actors!=1 or args.payload not in (512,1024)):refuse('native geometry supports actors1 and payload512/1024 only','not_run_capability')


def physical(ifname):
    cpu=read('/proc/cpuinfo').lower()
    if Path('/sys/hypervisor/type').exists() or 'hypervisor' in cpu.split():refuse('virtual/hypervisor environment')
    vendor=read('/sys/class/dmi/id/sys_vendor');product=read('/sys/class/dmi/id/product_name');board=read('/sys/class/dmi/id/board_vendor')
    if re.search('virtual|vmware|qemu|kvm|hvm|virtualbox|ec2|google compute|standard pc',vendor+' '+product+' '+board,re.I):refuse('virtual DMI evidence')
    if not re.search('dell|supermicro|hewlett|hpe|lenovo|asus|gigabyte|cisco|intel|tyan|fujitsu|huawei|inspur',vendor+' '+board,re.I):refuse('unknown physical platform; positive DMI evidence required')
    device=Path('/sys/class/net')/ifname/'device'
    if not device.exists() or '/pci' not in str(device.resolve()):refuse('physical PCI NIC required')
    driver=(device/'driver').resolve().name
    if re.search('virtio|vmxnet|hv_netvsc|veth|tun',driver):refuse('virtual NIC driver')
    return dict(kind='physical',verified=True,hypervisor=False,evidence=[
        'observed DMI sys_vendor='+vendor,'observed DMI product_name='+product,'observed board_vendor='+board,
        'observed PCI NIC '+device.resolve().name+' vendor='+read(device/'vendor')+' device='+read(device/'device'),
        'observed NIC MAC='+read(Path('/sys/class/net')/ifname/'address').lower()])


def kernel(config,producer):
    release=os.uname().release;path=Path(config).resolve()
    trusted=[Path('/boot')/('config-'+release),Path('/lib/modules')/release/'build/.config',Path('/proc/config.gz')]
    if path not in [p.resolve() for p in trusted] or not path.is_file():refuse('config path does not identify the running kernel','not_run_capability')
    data=gzip.decompress(path.read_bytes()) if path.name=='config.gz' else path.read_bytes()
    strict=b'CONFIG_XDEV_EXT_MECH_ZEROCOPY=y' in data.splitlines()
    if producer and not strict:refuse('strict native kernel required','not_run_capability')
    return dict(release=release,config_release=release,config_sha256=build.sha(path),strict_zero_copy=strict)


def product(expected,producer):
    observed=command(['git','-C',str(ROOT),'rev-parse','HEAD'])
    if observed!=expected:refuse('predeployed product SHA differs','not_run_capability')
    remote=command(['git','-C',str(ROOT),'remote','get-url','origin'])
    if remote.lower() not in ('https://github.com/shtusist/xdev_ext.git','git@github.com:shtusist/xdev_ext.git'):
        refuse('predeploy from the pinned product GitHub repository','not_run_capability')
    paths=['tests/eval/hft/'+name for name in (*build.C_SOURCES,'hardware_measure.py','hardware_gate.py','hardware_build.py','oracle.py','run.py')]+list(build.BPF_SOURCES)
    command(['git','-C',str(ROOT),'ls-files','--error-unmatch','--',*paths])
    if command(['git','-C',str(ROOT),'status','--porcelain','--untracked-files=no','--',*paths]):refuse('predeployed measured source differs from pinned SHA','not_run_capability')
    if producer:
        receipt=json.loads(Path(str(BIN)+'.build.json').read_text())
        expected_receipt=dict(schema=1,kind='binary',artifact_sha256=build.sha(BIN),product_sha=expected,
            source_sha256=build.binary_source_sha(),uring=True,session=True)
        if json.dumps(receipt,sort_keys=True)!=json.dumps(expected_receipt,sort_keys=True):refuse('measured producer build is not current and complete','not_run_capability')


def source(args,p):
    block=Path(args.source_block);ng=Path(args.source_ng);reference=Path(args.reference)
    if not stat.S_ISBLK(block.stat().st_mode) or not stat.S_ISCHR(ng.stat().st_mode):refuse('matching raw NVMe namespace devices required')
    b=Path('/sys/class/block')/block.name/'device';n=Path('/sys/class/nvme-generic')/ng.name/'device'
    if not b.exists() or not n.exists() or b.resolve()!=n.resolve() or '/pci' not in str(b.resolve()):refuse('physical NVMe block/generic identity mismatch')
    if not reference.is_file() or not stat.S_ISREG(reference.stat().st_mode) or reference.stat().st_mode&0o222:refuse('existing read-only immutable regular oracle reference required')
    geometry=json.loads(command([str(BIN),'--source-info',str(block)]))
    groups=p['burst_packets']*p['bursts'];length=groups*p['payload_bytes']
    if reference.stat().st_size!=length:refuse('reference must include exact warmup and measured source groups','not_run_capability')
    if not geometry['lba_bytes'] or args.slba>geometry['capacity_bytes']//geometry['lba_bytes'] or args.nlb>geometry['capacity_bytes']//geometry['lba_bytes']-args.slba or args.nlb*geometry['lba_bytes']<length:
        refuse('read-only source window out of bounds','not_run_capability')
    import hashlib
    observed=hashlib.sha256();expected=hashlib.sha256();saved=reference.stat()
    with block.open('rb',buffering=0) as raw,reference.open('rb') as ref:
        raw.seek(args.slba*geometry['lba_bytes'])
        for group in range(groups):
            wanted=oracle.payload(p,0,group);data=ref.read(p['payload_bytes']);actual=raw.read(p['payload_bytes'])
            if data!=wanted or actual!=data:refuse('reference/source differs from full independent payload bytes','not_run_capability')
            expected.update(data);observed.update(actual)
    current=reference.stat()
    if (saved.st_dev,saved.st_ino,saved.st_size,saved.st_mtime_ns)!=(current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns):refuse('immutable reference changed during admission')
    return dict(block_namespace=str(b.resolve()),ng_namespace=str(n.resolve()),read_only=True,slba=args.slba,nlb=args.nlb,
        **geometry,payload_bytes=p['payload_bytes'],groups=groups,observed_sha256=observed.hexdigest(),reference_sha256=expected.hexdigest())


def collect(args,role,p=None):
    required(args,role)
    try:
        environment=physical(args.ifname);k=kernel(args.kernel_config,role=='producer');product(args.product_sha,role=='producer')
        dev=Path('/sys/class/net')/args.ifname/'device'
        nic=dict(ifname=args.ifname,pci_bdf=dev.resolve().name,driver=(dev/'driver').resolve().name,
            mtu=int(read(Path('/sys/class/net')/args.ifname/'mtu')),queue=args.queue if role=='producer' else 0,
            zero_copy=False,copy_mode=False)
        if role=='producer' and not (Path('/sys/class/net')/args.ifname/'queues'/('tx-'+str(args.queue))).is_dir():refuse('requested physical NIC queue unavailable')
        addresses=json.loads(command(['ip','-j','address','show']))
        iface_ips=[v['local'] for row in addresses if row['ifname']==args.ifname for v in row.get('addr_info',[]) if v.get('family')=='inet']
        all_ips=[v['local'] for row in addresses for v in row.get('addr_info',[]) if v.get('family')=='inet']
        if role=='producer':
            if args.local_ip not in iface_ips or args.peer_ip in all_ips or args.peer_ip.startswith('127.') or args.peer_control[0] in all_ips or args.peer_control[0].startswith('127.'):
                refuse('a real remote peer and the actual producer NIC IPv4 address are required')
            if args.local_mac.lower()!=read(Path('/sys/class/net')/args.ifname/'address').lower():refuse('local MAC differs from intended physical NIC')
            if p['payload_bytes']+68>nic['mtu']:refuse('actual NIC MTU excludes profile','not_run_capability')
        elif args.data_bind[0] not in iface_ips:refuse('peer UDP bind must identify the actual physical NIC IPv4 address')
        receipt=dict(schema=1,role=role,product_sha=args.product_sha,environment=environment,kernel=k,nic=nic)
        if role=='producer':
            receipt['source']=source(args,p)
            obj=Path(args.bpf_object);btf=Path('/sys/kernel/btf/vmlinux')
            sidecar=json.loads(Path(str(obj)+'.build.json').read_text())
            wanted=dict(schema=1,kind='bpf',artifact_sha256=build.sha(obj),product_sha=args.product_sha,
                source_sha256=build.bpf_source_sha(),btf_sha256=build.sha(btf))
            if json.dumps(sidecar,sort_keys=True)!=json.dumps(wanted,sort_keys=True):refuse('BPF source/build/running-BTF receipt mismatch','not_run_capability')
            receipt['bpf']=dict(object_sha256=wanted['artifact_sha256'],btf_sha256=wanted['btf_sha256'],
                source_sha256=wanted['source_sha256'],target_matches=True)
        return receipt
    except correctness.Failure:raise
    except (OSError,ValueError,KeyError,subprocess.SubprocessError) as error:refuse('local hardware evidence unavailable: '+str(error),'not_run_capability')
