#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile real optional-class BPF against BTF from configured Kbuild objects.

Build io_uring/xdev_ext_mech_ops.o and net/xdp/xsk.o with DWARF and
CONFIG_XDEV_EXT_MECH=y, CONFIG_XDEV_EXT_MECH_SOCKET=n first, then pass their
O= directory. The AF_XDP object supplies the ordinary xdp_desc used by the
shared BPF helpers. No handcrafted or projected type is added. No kernel
link, verifier load, device or performance execution is implied. Dependencies
and missing debug information are errors, never skips. The object is read-only:
pahole writes detached BTF into the selected results directory.
"""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys

HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[3]
TOOLS = KERNEL / 'tools/xdev_ext_mech'


def run(command, log):
    print('COMMAND ' + shlex.join(map(str, command)), flush=True)
    result = subprocess.run(list(map(str, command)), text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=120)
    log.write_text(result.stdout)
    if result.returncode:
        print(result.stdout, end='', flush=True)
        raise RuntimeError('command failed: exit ' + str(result.returncode))
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kbuild-output', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--pahole', default=os.environ.get('PAHOLE', 'pahole'))
    parser.add_argument('--ld', default=os.environ.get('LD', 'ld'))
    parser.add_argument('--bpftool', default=os.environ.get('BPFTOOL', 'bpftool'))
    parser.add_argument('--clang', default=os.environ.get('CLANG', 'clang'))
    args = parser.parse_args()
    output = args.kbuild_output.resolve()
    results = args.results.resolve()
    results.mkdir(parents=True, exist_ok=True)
    config = (output / '.config').read_text().splitlines()
    if 'CONFIG_XDEV_EXT_MECH=y' not in config:
        raise RuntimeError('requires CONFIG_XDEV_EXT_MECH=y')
    if '# CONFIG_XDEV_EXT_MECH_SOCKET is not set' not in config:
        raise RuntimeError('regression must exercise CONFIG_XDEV_EXT_MECH_SOCKET=n')
    if 'CONFIG_DEBUG_INFO=y' not in config:
        raise RuntimeError('requires real DWARF debug information')
    obj = results / 'btf-input.o'
    run(shlex.split(args.ld) + ['-r', '-o', obj,
        output / 'io_uring/xdev_ext_mech_ops.o', output / 'net/xdp/xsk.o'],
        results / 'link.log')
    btf = results / 'ops.btf'
    run(shlex.split(args.pahole) + ['--btf_encode_detached=' + str(btf), obj],
        results / 'pahole.log')
    header = run(shlex.split(args.bpftool) + ['btf', 'dump', 'file', btf, 'format', 'c'],
                 results / 'vmlinux.h')
    # The BPF target compile below, rather than a source-line or header-string
    # assertion, tests availability and complete layout of packet descriptors.
    if not header:
        raise RuntimeError('empty BTF header')
    target = results / 'socket_sink.bpf.o'
    run(shlex.split(args.clang) + ['-target', 'bpf', '-D__TARGET_ARCH_x86',
        '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-I' + str(results),
        '-c', TOOLS / 'socket_sink.bpf.c', '-o', target], results / 'socket-bpf.log')
    elf = target.read_bytes()
    if elf[:4] != b'\x7fELF' or int.from_bytes(elf[18:20], 'little') != 247:
        raise RuntimeError('compiler did not produce an EM_BPF target')
    print('PASS: actual Kbuild DWARF -> detached BTF -> SOCKET-off BPF target', flush=True)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print('FAIL: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
