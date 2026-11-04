#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Recording external harness boundary. Never produces accepting guest evidence."""
import argparse
import json
import os
from pathlib import Path
import sys
from archive_recording_child import record

parser = argparse.ArgumentParser()
parser.add_argument('--scratch', required=True, type=Path)
parser.add_argument('--source', required=True, type=Path)
args, _ = parser.parse_known_args()
specification = Path(os.environ['XDEV_RECORDING_SPEC'])
spec = json.loads(specification.read_text())
index = args.scratch / 'recording-invocations.jsonl'
count = len(index.read_text().splitlines()) if index.exists() else 0
record(args.scratch, args.source, specification, 'invocation-' + str(count))
if spec.get('malformed_manifest'):
    (args.scratch / 'evidence/artifacts.sha256').write_text('deliberately malformed ordinary archive input\n')
sys.exit(spec.get('child_exit', 0))
