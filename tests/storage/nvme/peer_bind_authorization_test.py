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
import sys
import json
import os
import signal
from pathlib import Path


def original_main_assertion(raw, generated, context):
    """Locate the same unchanged public case/assertion in raw and generated C."""
    expressions=re.findall(r'\bassert\(([^;\n]+)\);',context)
    if len(expressions)!=1:
        raise ValueError('SETUP original main case must contain one assertion')
    expression=expressions[0]
    lines=[]
    for text in (raw,generated):
        if text.count('int main(void)')!=1:
            raise ValueError('SETUP original main count')
        start=text.index('int main(void)')
        main=text[start:]
        if main.count(context)!=1:
            raise ValueError('SETUP original main case anchor count')
        offset=start+main.index(context)+context.index('assert(')
        assertion='assert('+expression+');'
        if text[offset:offset+len(assertion)]!=assertion:
            raise ValueError('SETUP original main assertion changed')
        lines.append(text.count('\n',0,offset)+1)
    return expression,lines[0],lines[1]


def original_assertion_failed(result, probe, expression, line):
    """Only an abort at this original main assertion is a mutation kill."""
    diagnostic=(r'^.*: '+re.escape(str(probe))+':'+str(line)+
                r': main: Assertion [`\'\"]'+re.escape(expression)+r'[`\'\"] failed\.$')
    return (result.returncode==-signal.SIGABRT and
            re.search(diagnostic,result.stderr,re.M) is not None)


_LAYOUT_FILE = next(p / 'tools/layout.py' for p in Path(__file__).resolve().parents
                    if (p / 'tools/layout.py').is_file())
ROOT = runpy.run_path(str(_LAYOUT_FILE))['canonical_root'](Path(__file__))
_LEGACY = runpy.run_path(str(ROOT / 'tests/storage/nvme/_legacy_storfam_fixture.py'))
LegacySelection, bind_fixture = (_LEGACY[name] for name in ('LegacySelection', 'bind_fixture'))
spec = importlib.util.spec_from_file_location('extract_bind', ROOT / 'tests/core/admission_report/run.py')
extract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extract)
source = (ROOT / 'src/storage/drivers/nvme/host/xdev_ext_mech_nvme.c').read_text()
ioctl = (ROOT / 'src/storage/drivers/nvme/host/ioctl.c').read_text()
helpers = runpy.run_path(str(ROOT / 'tests/integration/peer_graph/nvme_peer_async_test.py'))
block = helpers['read_native'](ROOT, 'io_uring/family/xdev_ext_storfam_block.c')
header = helpers['read_native'](ROOT, 'drivers/nvme/host/nvme.h')
if 'return xdev_ext_storfam_submit(&p->family, b, &bp->family);' in source:
    selected=LegacySelection(ROOT)
    raw=Path(__file__).with_name('peer_bind_authorization_fixture.c').read_text()
    (generated,records),functions=bind_fixture(selected,raw)
    with tempfile.TemporaryDirectory(prefix='peer-bind-authority-') as tmp:
        directory=Path(tmp)
        probe=directory/'probe.c'
        include=helpers['host_headers'](selected.root,directory/'headers')
        command=['gcc','-std=gnu11','-Wall','-Wextra','-Werror',
                 '-Wno-unused-function','-Wno-unused-parameter','-I'+str(include),
                 '-fsanitize=undefined','-fno-sanitize-recover=all',str(probe),'-o',str(directory/'probe')]
        (directory/'assembly.json').write_text(json.dumps(selected.report(),indent=2))
        (directory/'fixture-edits.json').write_text(json.dumps(records,indent=2))
        selected.verify()
        probe.write_text(generated)
        def compile_or_setup(context):
            build=subprocess.run(command,capture_output=True,text=True)
            (directory/(context+'.compile.json')).write_text(json.dumps({
                'stage':'compile/link','case':context,'exit':build.returncode,
                'verdict':'SETUP' if build.returncode else 'COMPILED'},indent=2))
            if build.returncode:
                raise RuntimeError('SETUP compile/link failed - '+context+'\n'+build.stdout+build.stderr)
        compile_or_setup('baseline')
        subprocess.run([str(directory/'probe')],check=True)
        mutations = [
            ('READ fd mode', 'if (!write && !(st->file->f_mode & FMODE_READ))', 'if (false)'),
            ('WRITE fd mode', 'if (write && !(st->file->f_mode & FMODE_WRITE))', 'if (false)'),
            ('native command effects', 'if (!nvme_xdev_ext_mech_cmd_allowed(ns, st->file, write))', 'if (false)'),
            ('LBA window', 'if (ret) {\n\t\tdev->unbind(member);', 'if (false) {\n\t\tdev->unbind(member);'),
        ]
        original_cases={
            'READ fd mode': ('READ fd refusal',
                ' st.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE; f.f_mode=FMODE_WRITE;\n'
                ' assert(bind_case(&st,&u)==-EBADF && resources==2);'),
            'WRITE fd mode': ('WRITE fd refusal',
                ' f.f_mode=FMODE_READ; assert(bind_case(&st,&u)==-EBADF && resources==2);'),
            'native command effects': ('unsupported native effects',
                ' f.f_mode=FMODE_READ; effects=0;\n'
                ' assert(bind_case(&st,&u)==-EACCES && resources==2);'),
            'LBA window': ('LBA window overrun',
                ' st.arg0=31; st.arg1=2;\n'
                ' assert(bind_case(&st,&u)==-ERANGE && resources==2);'),
        }
        for name,old,new in mutations:
            if functions.count(old)!=1 or generated.count(functions)!=1:
                raise ValueError('SETUP mutation anchor count: '+name)
            mutant=generated.replace(functions,functions.replace(old,new,1),1)
            case,context=original_cases[name]
            expression,raw_line,generated_line=original_main_assertion(raw,mutant,context)
            probe.write_text(mutant)
            compile_or_setup(name)
            result=subprocess.run([str(directory/'probe')],capture_output=True,text=True,
                                  env={**os.environ,'LC_ALL':'C'})
            if original_assertion_failed(result,probe,expression,generated_line):
                verdict='DETECTED'
            elif result.returncode==0:
                verdict='SURVIVED'
            elif result.returncode==90 or re.search(r'^SETUP\b',result.stderr,re.M):
                verdict='SETUP'
            else:
                verdict='UNRELATED_FAILURE'
            (directory/(name+'.mutation.json')).write_text(json.dumps({
                'mutation':name,'case':case,'original_expression':expression,
                'raw_assertion_line':raw_line,'generated_assertion_line':generated_line,
                'compile_exit':0,'runtime_exit':result.returncode,'verdict':verdict},indent=2))
            if verdict!='DETECTED':
                raise RuntimeError(verdict+' - mutation '+name+' did not fail its original main case '+case+'\n'+result.stdout+result.stderr)
            print('observed original main assertion - '+case+': '+result.stderr.strip())
            print('ok mutation - '+name)
    raise SystemExit(0)
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
