#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run the actual NVMe bind and native command authority, with OS adapters.

This is a host permission/control-flow check, not native DMA execution.
"""
import importlib.util
import runpy
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'source-layout.json').is_file())
spec = importlib.util.spec_from_file_location('extract_bind', ROOT / 'tests/core/admission_report/run.py')
extract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extract)
source = (ROOT / 'src/storage/drivers/nvme/host/xdev_ext_mech_nvme.c').read_text()
ioctl = (ROOT / 'src/storage/drivers/nvme/host/ioctl.c').read_text()
helpers = runpy.run_path(str(ROOT / 'tests/integration/peer_graph/nvme_peer_async_test.py'))
block = helpers['read_native'](ROOT, 'io_uring/family/xdev_ext_storfam_block.c')
header = helpers['read_native'](ROOT, 'drivers/nvme/host/nvme.h')
functions = '\n'.join([extract.function(ioctl, 'nvme_cmd_allowed'),
                       extract.function(ioctl, 'nvme_xdev_ext_mech_cmd_allowed'),
                       extract.function(header, 'nvme_xdev_ext_capture_identity')])
functions += r'''
#define nvme_xdev_ext_capture_identity(n,...) (fixture_capture_observe(n), (nvme_xdev_ext_capture_identity)(n,__VA_ARGS__))
#define nvme_xdev_ext_mech_bind_identity(i,w,bytes) (fixture_bind_observe(i,bytes), (nvme_xdev_ext_mech_bind_identity)(i,w,bytes))
'''
functions += '\n' + '\n'.join(extract.function(source, name) for name in (
    'nvme_xdev_ext_member_bind', 'nvme_xdev_ext_member_unbind',
    'nvme_xdev_ext_member_requester', 'nvme_xdev_ext_member_queue',
    'nvme_xdev_ext_member_identity', 'nvme_xdev_ext_member_decode',
    'nvme_xdev_ext_member_poll', 'nvme_xdev_ext_class_resources_free',
    'nvme_xdev_ext_peer_resources_free'))
functions = extract.function(block, 'xdev_ext_stor_block_poll') + '\n' + functions
functions += '\n' + extract.function(block, 'xdev_ext_storfam_bind')
functions += '\n' + re.search(r'^static const struct xdev_ext_stor_dev_ops nvme_xdev_ext_member_ops = \{.*?^\};', source, re.M | re.S)[0]
functions += '\n' + extract.function(source, 'nvme_xdev_ext_class_bind')
fixture = Path(__file__).with_name('peer_bind_authorization_fixture.c').read_text()
fixture = fixture.replace('/* FAMILY_TYPES */', helpers['family_types'](ROOT))
trace = helpers['read_native'](ROOT, 'drivers/nvme/host/xdev_ext_native_peer_trace.h')
types = re.search(r'^struct nvme_xdev_ext_peer_trace \{.*?^\};', trace, re.M | re.S)[0]
types += '\n' + '\n'.join(re.search(r'^struct ' + name + r' \{.*?^\};', source, re.M | re.S)[0] for name in (
    'nvme_xdev_ext_mech_stage', 'nvme_xdev_ext_mech_slot', 'nvme_xdev_ext_peer_slot', 'nvme_xdev_ext_peer_res'))
fixture = fixture.replace('/* MEMBER_TYPES */', types)
with tempfile.TemporaryDirectory(prefix='peer-bind-authority-') as tmp:
    directory = Path(tmp)
    probe = directory / 'probe.c'
    probe.write_text(fixture.replace('/* PRODUCTION */', functions))
    subprocess.run(['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-Wno-unused-function', '-Wno-unused-parameter', '-I'+str(helpers['host_headers'](ROOT, directory / 'headers')), '-fsanitize=undefined',
                    '-fno-sanitize-recover=all', str(probe), '-o', str(directory / 'probe')], check=True)
    subprocess.run([str(directory / 'probe')], check=True)
    mutations = [
        ('READ fd mode', 'if (!write && !(st->file->f_mode & FMODE_READ))', 'if (false)'),
        ('WRITE fd mode', 'if (write && !(st->file->f_mode & FMODE_WRITE))', 'if (false)'),
        ('native command effects', 'if (!nvme_xdev_ext_mech_cmd_allowed(ns, st->file, write))', 'if (false)'),
        ('LBA window', 'if (ret) {\n\t\tdev->unbind(member);', 'if (false) {\n\t\tdev->unbind(member);'),
    ]
    for name, old, new in mutations:
        if functions.count(old) != 1:
            raise RuntimeError('mutation anchor missing: ' + name)
        probe.write_text(fixture.replace('/* PRODUCTION */', functions.replace(old, new)))
        subprocess.run(['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-function', '-Wno-unused-parameter', '-I'+str(helpers['host_headers'](ROOT, directory / 'headers')), '-fsanitize=undefined',
                        '-fno-sanitize-recover=all', str(probe), '-o', str(directory / 'probe')], check=True)
        result = subprocess.run([str(directory / 'probe')], capture_output=True, text=True)
        if result.returncode == 0 or 'Assertion' not in result.stderr:
            raise RuntimeError('behavior oracle missed mutation: ' + name)
        print('ok mutation - ' + name)
