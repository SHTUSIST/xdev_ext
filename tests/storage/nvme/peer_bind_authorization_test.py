#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run the actual NVMe bind and native command authority, with OS adapters.

This is a host permission/control-flow check, not native DMA execution.
"""
import importlib.util
import subprocess
import tempfile
from pathlib import Path

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'source-layout.json').is_file())
spec = importlib.util.spec_from_file_location('extract_bind', ROOT / 'tests/core/admission_report/run.py')
extract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extract)
source = (ROOT / 'src/storage/drivers/nvme/host/xdev_ext_mech_nvme.c').read_text()
ioctl = (ROOT / 'src/storage/drivers/nvme/host/ioctl.c').read_text()
bind = extract.function(source, 'nvme_xdev_ext_class_bind')
functions = '\n'.join([extract.function(ioctl, 'nvme_cmd_allowed'),
                       extract.function(ioctl, 'nvme_xdev_ext_mech_cmd_allowed'), bind])
fixture = Path(__file__).with_name('peer_bind_authorization_fixture.c').read_text()
with tempfile.TemporaryDirectory(prefix='peer-bind-authority-') as tmp:
    directory = Path(tmp)
    probe = directory / 'probe.c'
    probe.write_text(fixture.replace('/* PRODUCTION */', functions))
    subprocess.run(['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-Wno-unused-function', '-fsanitize=undefined',
                    '-fno-sanitize-recover=all', str(probe), '-o', str(directory / 'probe')], check=True)
    subprocess.run([str(directory / 'probe')], check=True)
    mutations = [
        ('READ fd mode', 'if (!write && !(st->file->f_mode & FMODE_READ))', 'if (false)'),
        ('WRITE fd mode', 'if (write && !(st->file->f_mode & FMODE_WRITE))', 'if (false)'),
        ('native command effects', 'if (!nvme_xdev_ext_mech_cmd_allowed(ns, st->file, write))', 'if (false)'),
        ('LBA window', 'if (ret) {\n\t\tkfree(p);', 'if (false) {\n\t\tkfree(p);'),
    ]
    for name, old, new in mutations:
        if functions.count(old) != 1:
            raise RuntimeError('mutation anchor missing: ' + name)
        probe.write_text(fixture.replace('/* PRODUCTION */', functions.replace(old, new)))
        subprocess.run(['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                        '-Wno-unused-function', '-fsanitize=undefined',
                        '-fno-sanitize-recover=all', str(probe), '-o', str(directory / 'probe')], check=True)
        result = subprocess.run([str(directory / 'probe')], capture_output=True, text=True)
        if result.returncode == 0 or 'Assertion' not in result.stderr:
            raise RuntimeError('behavior oracle missed mutation: ' + name)
        print('ok mutation - ' + name)
