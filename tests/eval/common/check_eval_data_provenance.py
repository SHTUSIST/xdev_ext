#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Report evaluation CSVs that lack provenance or call themselves estimates.

    check_eval_data_provenance.py --data-dir DIR [--plot-script PLOT.py]
                                  [--json] [--report-only]

Every CSV that feeds a figure should start with comment lines naming the
exact product commit, the harness and the run directory it was processed
from, either on one line

    # provenance: source_sha=<7-40 hex> harness=<path> run_dir=<path>

or as separate "# source_sha: ...", "# harness: ...", "# run_dir: ..." lines.
Independently, a file is flagged when its name, comment lines or column
names declare it an estimate, preview, model or projection; such data is not
a measurement whatever its header says.  With --plot-script the report marks
which CSVs the plotting script names.

Files are only read.  Exit status: 0 every file passes (or --report-only),
1 some file fails, 2 no CSV found.
"""
import argparse
import json
from pathlib import Path
import re
import sys

REQUIRED = ('source_sha', 'harness', 'run_dir')
SHA = re.compile(r'[0-9a-f]{7,40}')
COMMENT_WORDS = ('estimate', 'estimated', 'estimates', 'estimation', 'preview',
                 'model', 'modeled', 'modelled', 'projection', 'projected',
                 'placeholder', 'replace with', 'assumed', 'hypothetical')
NAME_TOKENS = {'est', 'estimate', 'estimated', 'preview', 'projected', 'projection',
               'model', 'modeled'}


def provenance(comments):
    found = {}
    for line in comments:
        body = line.lstrip('#').strip()
        m = re.match(r'(source_sha|harness|run_dir)\s*:\s*(\S+)\s*$', body)
        if m:
            found[m.group(1)] = m.group(2)
            continue
        for key, value in re.findall(r'\b(source_sha|harness|run_dir)=(\S+)', body):
            found[key] = value
    return found


def estimate_signals(name, comments, columns):
    signals = []
    tokens = re.split(r'[_.\-]+', Path(name).stem.lower())
    signals += ['file name: ' + t for t in tokens if t in NAME_TOKENS]
    text = ' '.join(comments).lower()
    for word in COMMENT_WORDS:
        if re.search(r'(?<![a-z])' + re.escape(word) + r'(?![a-z])', text):
            signals.append('comment: ' + word)
    for column in columns:
        if NAME_TOKENS & set(column.strip().lower().split('_')):
            signals.append('column: ' + column.strip())
    return signals


def inspect(name, text):
    comments, header = [], None
    for line in text.splitlines():
        if line.startswith('#'):
            comments.append(line)
        elif line.strip():
            header = line
            break
    found = provenance(comments)
    missing = [k for k in REQUIRED if not found.get(k) or
               (k == 'source_sha' and not SHA.fullmatch(found[k]))]
    columns = header.split(',') if header else []
    signals = estimate_signals(name, comments, columns)
    return dict(file=Path(name).name, provenance=found, missing=missing,
                estimate_signals=signals, ok=not missing and not signals)


def plot_inputs(script):
    return set(re.findall(r'["\']([^"\'/\\]+\.csv)["\']', Path(script).read_text()))


def scan(data_dir, plot_script=None):
    used = plot_inputs(plot_script) if plot_script else None
    rows = []
    for path in sorted(Path(data_dir).glob('*.csv')):
        r = inspect(path.name, path.read_text(errors='replace'))
        r['used_by_plot'] = None if used is None else path.name in used
        rows.append(r)
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--data-dir', required=True)
    parser.add_argument('--plot-script')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--report-only', action='store_true')
    args = parser.parse_args(argv)
    rows = scan(args.data_dir, args.plot_script) if Path(args.data_dir).is_dir() else []
    if not rows:
        print('no CSV files under ' + args.data_dir, file=sys.stderr)
        return 2
    summary = dict(files=len(rows), ok=sum(r['ok'] for r in rows),
                   missing_provenance=sum(bool(r['missing']) for r in rows),
                   self_declared_estimate=sum(bool(r['estimate_signals']) for r in rows))
    if args.json:
        print(json.dumps(dict(summary=summary, files=rows), indent=1))
    else:
        for r in rows:
            plot = '' if r['used_by_plot'] is None else \
                (' [plot input]' if r['used_by_plot'] else ' [not plotted]')
            detail = []
            if r['missing']:
                detail.append('missing ' + ','.join(r['missing']))
            if r['estimate_signals']:
                detail.append('declares ' + '; '.join(r['estimate_signals']))
            print('%s %s%s%s' % ('OK  ' if r['ok'] else 'FAIL', r['file'], plot,
                                 (': ' + ' | '.join(detail)) if detail else ''))
        print('files=%(files)d ok=%(ok)d missing_provenance=%(missing_provenance)d '
              'self_declared_estimate=%(self_declared_estimate)d' % summary)
    return 0 if args.report_only or summary['ok'] == summary['files'] else 1


if __name__ == '__main__':
    sys.exit(main())
