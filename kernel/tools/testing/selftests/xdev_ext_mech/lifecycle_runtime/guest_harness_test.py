#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run the real harness image preparation without launching a guest."""
import pathlib, re, subprocess, sys, tempfile
kernel = pathlib.Path(__file__).resolve().parents[5]
harness = kernel/'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh'
s = harness.read_text()
image = re.search(r"python3 - \"\$SCRATCH\" \"\$GROUP_COUNT\"[^\n]* <<'PY'\n(.*?)\nPY\n", s, re.S).group(1)
with tempfile.TemporaryDirectory() as temp:
    p = pathlib.Path(temp); (p/'evidence').mkdir()
    subprocess.run([sys.executable, '-', temp, '3', '0', 'none', str(kernel), '1'], input=image, text=True, check=True)
    source = (p/'source.raw').read_bytes(); expected = (p/'expected.raw').read_bytes()
    data = source[2048*512:2048*512+3*8192]
    start = 4096*512; size = len(data)
    assert expected[start:start+size] == data
    assert expected[start+size:start+2*size] == data, 'missing second fanout sink oracle'
    transformed = expected[start+2*size:start+3*size]
    assert transformed != data and transformed != bytes(size)
    assert transformed == expected[start+3*size:start+4*size]
    assert expected[:start] == bytes(start)
    assert expected[start+4*size:] == bytes(len(expected)-start-4*size)
assert '--lifecycle)' in s and 'sh /opt/xdev_ext/xdev_ext_mech_lifecycle_guest.sh' in s
assert 'cmp "$SCRATCH/expected.raw" "$SCRATCH/destination.raw"' in s
print('PASS lifecycle harness four sink images, guards, and execution hook')
