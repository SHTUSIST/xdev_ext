#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Each mutant of the actual recovery code must make recovery_cases.c fail.

A mutant whose anchor is missing is a SETUP error, never a silent pass.
Not listed, equivalent by construction: retire's return after a failed unmap
(unpin then refuses the region that failure quarantined).
Exit 0 when every mutant is detected, 1 when one survives, 2 on setup.
"""
from pathlib import Path
import argparse
import importlib.util
import sys
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('peer_quarantine_run', HERE / 'run.py')
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

MUTANTS = (
    ('proof of the submission epoch counts', 'core',
     'covers = rq->proven > epoch;', 'covers = rq->proven >= epoch;'),
    ('requester identity not checked', 'core',
     'bound = rq && rq->pdev == m->peer &&', 'bound = rq &&'),
    ('missing submission epoch accepted', 'core',
     ' epoch != XDEV_EXT_PEER_EPOCH_NONE &&', ' true &&'),
    ('another instance may extend a record', 'core',
     '(!m->unknown || m->unknown == rq);', 'true;'),
    ('permanent cause lifted', 'core',
     '   if (!r->permanent) {\n    r->quarantined = false;', '   if (true) {\n    r->quarantined = false;'),
    ('pending record ignored', 'core',
     '  if (r->pending) {\n   list_add_tail(&r->qnode, &keep);', '  if (false) {\n   list_add_tail(&r->qnode, &keep);'),
    ('unbegun epoch accepted as proof', 'core',
     ' if (!rq || !epoch || epoch > (u64)atomic64_read(&rq->started)) return;', ' if (!rq || !epoch) return;'),
    ('later epoch does not raise the record', 'core',
     '   } else if (epoch > m->unknown_epoch) {\n    m->unknown_epoch = epoch;',
     '   } else if (false) {\n    m->unknown_epoch = epoch;'),
    ('covered release still quarantines', 'core',
     ' if (bound && xdev_ext_peer_requester_covers(rq, epoch)) {', ' if (false) {'),
    ('bound region never queued', 'core',
     '    list_add_tail(&r->qnode, &xdev_ext_peer_quarantined); r->queued = true;', '    r->queued = true;'),
    ('record keeps its requester reference', 'core',
     '    xdev_ext_peer_requester_put_locked(m->unknown);\n    m->unknown = NULL;', '    m->unknown = NULL;'),
    ('non-orphan retired by recovery', 'core',
     '    if (r->orphaned) list_add_tail(&r->qnode, &retire);', '    list_add_tail(&r->qnode, &retire);'),
    ('orphan never retires a recovered region', 'core',
     ' if (retire) xdev_ext_peer_region_retire(r);', ' (void)retire;'),
    ('fd close leaks instead of orphaning', 'fd',
     ' else xdev_ext_peer_orphan(p->region);', ''),
    ('legacy UNKNOWN not permanent', 'core',
     ' if (!quiesced) r->permanent = true; /* no evidence binding */\n', ''),
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', type=Path, default=HERE.parents[2])
    args = parser.parse_args()
    root = args.source_root.resolve()
    core = (root / run.CORE).read_text()
    fd = (root / run.FD).read_text()
    survivors, setup = [], []
    with tempfile.TemporaryDirectory(prefix='peer-quarantine-mutants-') as directory:
        for index, (name, where, old, new) in enumerate(MUTANTS):
            text = core if where == 'core' else fd
            if text.count(old) != 1:
                setup.append(name)
                print('SETUP anchor %r occurs %d times' % (name, text.count(old)))
                continue
            changed = text.replace(old, new, 1)
            try:
                source = run.assemble(root, core=changed if where == 'core' else core,
                                      fd=changed if where == 'fd' else fd)
            except run.Setup as error:
                setup.append(name)
                print('SETUP %s: %s' % (name, error))
                continue
            verdict, log, _ = run.run_unit(source, directory, 'mutant%d' % index)
            if verdict == 'PASS':
                survivors.append(name)
            elif verdict == 'SETUP':
                setup.append(name)
                print(log)
            print('%s mutant: %s' % ('SURVIVED' if verdict == 'PASS' else verdict, name))
    detected = len(MUTANTS) - len(survivors) - len(setup)
    print('%s peer-quarantine mutants detected=%d of %d' % (
        'PASS' if not survivors and not setup else 'FAIL', detected, len(MUTANTS)))
    return 2 if setup else 1 if survivors else 0


if __name__ == '__main__':
    sys.exit(main())
