#!/usr/bin/env python3
"""Host tests for lab_vfio_tb_check.sh: argument refusals and topology summary.

Requirement (user, 2026-11-07): re-check on lab-vfio whether the Thunderbolt
NHI sees a peer or a self-loop, with a script that can be run again later.
The script must classify the guest's topology report and refuse unsafe use.
"""
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "lab_vfio_tb_check.sh")


def run(*args):
    return subprocess.run(["bash", SCRIPT, *args], capture_output=True, text=True)


def summarize(text):
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(text)
    try:
        return run("--summarize", f.name)
    finally:
        os.unlink(f.name)


class Summary(unittest.TestCase):
    def test_no_link(self):
        r = summarize("XDEV_EXT_TB_NHI_ENUM port=0-0/usb4_port1 link=none\n"
                      "XDEV_EXT_TB_NHI_ENUM port=0-0/usb4_port3 link=none\n"
                      "XDEV_EXT_TB_NHI_ENUM summary routers=1 xdomains=0 same_uuid_xdomains=0\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("TB_LOOP_CHECK result=NO_LINK routers=1 xdomains=0 "
                      "same_uuid_xdomains=0 port_links=none:2", r.stdout)

    def test_self_loop(self):
        r = summarize("XDEV_EXT_TB_NHI_ENUM port=0-0/usb4_port1 link=usb4\n"
                      "XDEV_EXT_TB_NHI_ENUM port=0-0/usb4_port3 link=usb4\n"
                      "XDEV_EXT_TB_NHI_ENUM summary routers=1 xdomains=1 same_uuid_xdomains=1\n")
        self.assertIn("result=SELF_LOOP", r.stdout)

    def test_peer(self):
        r = summarize("XDEV_EXT_TB_NHI_ENUM summary routers=1 xdomains=1 same_uuid_xdomains=0\n")
        self.assertIn("result=PEER", r.stdout)
        r = summarize("XDEV_EXT_TB_NHI_ENUM summary routers=2 xdomains=0 same_uuid_xdomains=0\n")
        self.assertIn("result=PEER", r.stdout)

    def test_missing_summary_is_unknown_and_nonzero(self):
        r = summarize("XDEV_EXT_TB_NHI_ENUM port=0-0/usb4_port1 link=none\n")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("result=UNKNOWN reason=no-summary", r.stdout)


class Refusals(unittest.TestCase):
    def test_source_required(self):
        r = run()
        self.assertEqual(r.returncode, 2)
        self.assertIn("--source", r.stderr)

    def test_bad_nhi(self):
        with tempfile.TemporaryDirectory() as d:
            r = run("--source", d, "--nhi", "00:0d.2")
        self.assertEqual(r.returncode, 2)
        self.assertIn("bad --nhi", r.stderr)

    def test_unknown_option(self):
        r = run("--forcepower")
        self.assertEqual(r.returncode, 2)

    def test_never_writes_device_attributes(self):
        with open(SCRIPT) as f:
            lines = [l for l in f if not l.lstrip().startswith("#")]
        for word in ("authorized", "forcepower", "unbind", "/bind", "/remove", "/reset"):
            for line in lines:
                self.assertFalse(">" in line and word in line, f"writes {word}: {line}")


if __name__ == "__main__":
    unittest.main()
