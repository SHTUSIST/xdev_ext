#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Deploy the pp2-nccl baseline with default configuration; --dry-run prints every command."""
import importlib.util
from pathlib import Path
import sys

_spec = importlib.util.spec_from_file_location(
    'baseline_plan', Path(__file__).resolve().with_name('baseline_plan.py'))
baseline_plan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(baseline_plan)

if __name__ == '__main__':
    sys.exit(baseline_plan.main('pp2-nccl'))
