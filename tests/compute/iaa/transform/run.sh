#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python3 -m unittest discover -s "$HERE" -p '*_test.py' -v
