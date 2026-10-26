#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run real tbnet packet callbacks and teardown callers across unregister."""
import os
from pathlib import Path
import subprocess
import tempfile
from tb_protocol_handler_lifetime_test import extract

HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[4]

def main():
    text = (KERNEL / 'drivers/net/thunderbolt/main.c').read_text()
    names = ['stop_login', 'tbnet_handle_packet', 'tbnet_stop',
             'tbnet_remove', 'tbnet_suspend', 'tbnet_disconnect_work']
    # Include the actual common teardown helper if the production fix adds one.
    if 'static void tbnet_unregister_protocol(' in text:
        names.insert(1, 'tbnet_unregister_protocol')
    code = '\n'.join(extract(text, name) for name in names)
    probe = extract(text, 'tbnet_probe')
    tail = probe[probe.index('\tret = register_netdev(dev);'):]
    code += '\nstatic int probe_tail(struct tbnet *net) { struct net_device *dev=net->dev; int ret;\n' + tail
    source = (HERE / 'tbnet_handler_teardown_fixture.c.in').read_text().replace('/* PRODUCTION */', code)
    failed = 0
    with tempfile.TemporaryDirectory(prefix='tbnet-unregister-') as tmp:
        c = Path(tmp)/'test.c'; exe=Path(tmp)/'test'; c.write_text(source)
        built = subprocess.run([os.environ.get('CC','gcc'), '-std=gnu11', '-O1', '-g', '-pthread', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-Wno-unused-function', str(c), '-o',str(exe)], capture_output=True,text=True)
        if built.returncode:
            print('SETUP_COMPILE_ERROR\n'+built.stderr);return 2
        cases = ['remove-login','remove-logout','suspend-login','suspend-logout','probe-logout','normal-drain']
        for case in cases:
            try:
                ran = subprocess.run([str(exe),case],capture_output=True,text=True,timeout=8)
                print(('not ok' if ran.returncode else 'ok')+' - '+case+' '+ran.stdout+ran.stderr,end='\n')
                failed += bool(ran.returncode)
            except subprocess.TimeoutExpired:
                print('not ok - '+case+' bounded timeout');failed+=1
    print(f'{len(cases)} cases, {failed} failures')
    return bool(failed)

if __name__ == '__main__':
    raise SystemExit(main())
