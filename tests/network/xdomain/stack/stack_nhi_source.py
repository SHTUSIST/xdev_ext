#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Prepare unmodified NHI ring bodies and shared production layouts.

This is the same ring-section extraction as peer_graph/xdomain_nhi_test.py.
The generated files contain production algorithms, never a second ring model.
"""
import hashlib
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'peer_graph'))
from xdomain_ring_test import declaration, no_includes
from xdomain_fixture import definition


def generate(kernel, directory):
    kernel, directory = Path(kernel), Path(directory)
    names = ('drivers/thunderbolt/nhi.c',
             'drivers/thunderbolt/nhi_regs.h',
             'include/linux/thunderbolt.h')
    contents = {name: (kernel / name).read_text() for name in names}
    header = contents[names[2]]
    types = ['/* Generated from production thunderbolt.h and nhi_regs.h. */',
             '#ifndef STACK_NHI_TYPES_H', '#define STACK_NHI_TYPES_H',
             declaration(header, 'enum ring_desc_flags'),
             no_includes(contents[names[1]]),
             declaration(header, 'struct tb_nhi'),
             declaration(header, 'struct tb_ring'),
             declaration(header, 'struct tb_ring_snapshot'),
             'void tb_ring_snapshot(struct tb_ring *, struct tb_ring_snapshot *);',
             'struct ring_frame;',
             'typedef void (*ring_cb)(struct tb_ring *, struct ring_frame *, bool);',
             declaration(header, 'struct ring_frame')]
    types.extend(re.findall(r'^#define (?:RING_FLAG_\w+|TB_FRAME_SIZE)\b[^\n]*',
                            header, re.M))
    prototypes = header[header.index('struct tb_ring *tb_ring_alloc_tx('):
                        header.index('/**\n * tb_ring_rx()')]
    types.append(prototypes)
    for name in ('tb_ring_rx', 'tb_ring_rx_more', 'tb_ring_tx',
                 'tb_ring_tx_more', 'tb_ring_dma_device'):
        types.append(definition(header, name))
    types += ['struct ring_frame *tb_ring_poll(struct tb_ring *);',
              'bool tb_ring_poll_pending(struct tb_ring *);',
              'void tb_ring_poll_complete(struct tb_ring *);',
              'int tb_ring_throttling(struct tb_ring *, unsigned int);',
              '#endif']
    source = contents[names[0]]
    ring = no_includes(source[:source.index('int nhi_mailbox_cmd(')])
    ring += '\n' + definition(source, 'nhi_interrupt_work')
    ring += '\n' + definition(source, 'nhi_msi') + '\n'
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'stack_nhi_types.h').write_text('\n'.join(types) + '\n')
    (directory / 'stack_nhi_source.inc').write_text(ring)
    return {name: hashlib.sha256((kernel / name).read_bytes()).hexdigest()
            for name in names}
