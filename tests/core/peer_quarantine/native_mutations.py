#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Each mutant of the actual nvme-pci evidence code must fail the native test.

Materializes one private source view of the canonical tree, applies one
mutant at a time to the view's copy of drivers/nvme/host/pci.c and runs the
view's xdev_ext_peer_native_test.py there. The canonical tree is read only.
Exit 0 when every mutant is detected, 1 when one survives, 2 on setup.
Not listed, equivalent by construction: ignoring the config read result
(a failed read sets the all-ones error response, Bus Master included).
"""
from pathlib import Path
import argparse
import os
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
PCI = 'kernel/drivers/nvme/host/pci.c'
TEST_DIR = 'kernel/tools/testing/selftests/xdev_ext_peer'
BEGIN = '\tepoch = nvme_pci_peer_quiesce_begin(dev);\n'
QUIESCE = '\tnvme_quiesce_io_queues(&dev->ctrl);\n'
PROOF = '\tnvme_pci_peer_quiesce_end(dev, epoch, reset);\n'
CANCEL = '\tnvme_cancel_admin_tagset(&dev->ctrl);\n'


def move(text, line, after):
    if text.count(line) != 1 or text.count(after) != 1:
        return None
    return text.replace(line, '', 1).replace(after, after + line, 1)


def replace(old, new):
    return lambda text: text.replace(old, new, 1) if text.count(old) == 1 else None


MUTANTS = (
    ('epoch begins after the dispatch quiesce', lambda t: move(t, BEGIN, QUIESCE)),
    ('proof recorded after cancellation', lambda t: move(t, PROOF, CANCEL)),
    ('shutdown counted as a Controller Reset',
     replace('reset = !nvme_disable_ctrl(&dev->ctrl, shutdown) && !shutdown;',
             'reset = !nvme_disable_ctrl(&dev->ctrl, shutdown);')),
    ('failed CSTS.RDY wait ignored',
     replace('reset = !nvme_disable_ctrl(&dev->ctrl, shutdown) && !shutdown;',
             'nvme_disable_ctrl(&dev->ctrl, shutdown); reset = !shutdown;')),
    ('Bus Master Enable not checked',
     replace(' ||\n\t    (command & PCI_COMMAND_MASTER))', ')')),
    ('submit snapshot missing from preparation',
     replace('\tnvme_pci_peer_note_submit(dev, req);\n\tnvme_start_request(req);',
             '\tnvme_start_request(req);')),
    ('UNKNOWN release without the controller',
     replace('xdev_ext_peer_fd_release_unknown(&handle, dev->peer_requester,',
             'xdev_ext_peer_fd_release_unknown(&handle, NULL,')),
    ('UNKNOWN release with an earlier epoch',
     replace('                                              trace.submit_epoch);',
             '                                              0);')),
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', type=Path, default=HERE.parents[2])
    args = parser.parse_args()
    root = args.source_root.resolve()
    sys.path.insert(0, str(root / 'tools'))
    import layout
    survivors, setup = [], []
    with tempfile.TemporaryDirectory(prefix='peer-native-mutants-') as directory:
        view = layout.materialize_view(root, Path(directory) / 'view').root
        pci = view / PCI
        original = pci.read_text()
        env = dict(os.environ, TMPDIR=directory)
        baseline = subprocess.run([sys.executable, 'xdev_ext_peer_native_test.py'],
                                  cwd=view / TEST_DIR, capture_output=True, text=True, env=env)
        if baseline.returncode:
            print(baseline.stdout + baseline.stderr)
            print('SETUP unmutated native test fails')
            return 2
        for name, mutate in MUTANTS:
            changed = mutate(original)
            if changed is None or changed == original:
                setup.append(name)
                print('SETUP anchor: ' + name)
                continue
            pci.write_text(changed)
            result = subprocess.run([sys.executable, 'xdev_ext_peer_native_test.py'],
                                    cwd=view / TEST_DIR, capture_output=True, text=True, env=env)
            pci.write_text(original)
            if result.returncode == 0:
                survivors.append(name)
            print('%s mutant: %s' % ('SURVIVED' if not result.returncode else 'DETECTED', name))
    detected = len(MUTANTS) - len(survivors) - len(setup)
    print('%s native peer evidence mutants detected=%d of %d' % (
        'PASS' if not survivors and not setup else 'FAIL', detected, len(MUTANTS)))
    return 2 if setup else 1 if survivors else 0


if __name__ == '__main__':
    sys.exit(main())
