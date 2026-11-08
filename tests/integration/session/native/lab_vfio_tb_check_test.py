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


SELF_LOOP = ("XDEV_EXT_TB_NHI_ENUM port=0-0/usb4_port1 link=usb4\n"
             "XDEV_EXT_TB_NHI_ENUM port=0-0/usb4_port3 link=usb4\n"
             "XDEV_EXT_TB_NHI_ENUM summary routers=1 xdomains=2 same_uuid_xdomains=2\n")
NO_LINK = ("XDEV_EXT_TB_NHI_ENUM port=0-0/usb4_port1 link=none\n"
           "XDEV_EXT_TB_NHI_ENUM summary routers=1 xdomains=0 same_uuid_xdomains=0\n")


def echo_summary(enum, echo):
    """Requirement (2026-11-07): with --selfloop-echo, a SELF_LOOP topology
    carries one small XDOMAIN exchange through the cable in the module's
    self_loop_test mode and the bytes are compared; other topologies do not
    run it (lab-vfio has no cable today, so NOT_RUN topology=NO_LINK)."""
    with tempfile.TemporaryDirectory() as d:
        e = os.path.join(d, "tb-nhi-enum.txt")
        x = os.path.join(d, "tb-selfloop-echo.txt")
        with open(e, "w") as f:
            f.write(enum)
        if echo is not None:
            with open(x, "w") as f:
                f.write(echo)
        return run("--summarize-echo", e, x)


class EchoSummary(unittest.TestCase):
    def test_no_link_does_not_run_the_echo(self):
        r = echo_summary(NO_LINK, "XDEV_EXT_TB_SELFLOOP_ECHO=NOT_RUN reason=no-self-loop same_uuid_xdomains=0\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "TB_SELFLOOP_ECHO result=NOT_RUN topology=NO_LINK")

    def test_self_loop_echo_pass(self):
        r = echo_summary(SELF_LOOP, "XDEV_EXT_TB_SELFLOOP_ECHO end=0-1.1 version=1 control_ready=1\n"
                         "XDEV_EXT_TB_SELFLOOP_ECHO=PASS ends=2 channels=1 bytes_each_way=4224 "
                         "compare=in-kernel-pattern-crc-nonce\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "TB_SELFLOOP_ECHO result=PASS topology=SELF_LOOP ends=2 "
                         "channels=1 bytes_each_way=4224 compare=in-kernel-pattern-crc-nonce")

    def test_self_loop_echo_fail_is_nonzero(self):
        r = echo_summary(SELF_LOOP, "XDEV_EXT_TB_SELFLOOP_ECHO=FAIL reason=ends-not-paired\n")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout.strip(), "TB_SELFLOOP_ECHO result=FAIL topology=SELF_LOOP reason=ends-not-paired")

    def test_self_loop_without_an_echo_report_is_a_failure(self):
        r = echo_summary(SELF_LOOP, None)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout.strip(), "TB_SELFLOOP_ECHO result=FAIL topology=SELF_LOOP reason=no-echo-report")

    def test_self_loop_echo_not_run_is_a_failure(self):
        r = echo_summary(SELF_LOOP, "XDEV_EXT_TB_SELFLOOP_ECHO=NOT_RUN reason=no-self-loop same_uuid_xdomains=0\n")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("result=FAIL topology=SELF_LOOP reason=echo-not-run", r.stdout)


class EchoOption(unittest.TestCase):
    def setUp(self):
        with open(SCRIPT) as f:
            self.script = f.read()

    def test_option_is_accepted_and_off_by_default(self):
        self.assertIn("ECHO=0", self.script)
        self.assertIn("--selfloop-echo) ECHO=1; shift ;;", self.script)

    def test_option_reaches_the_guest_harness(self):
        self.assertIn('[ "$ECHO" = 1 ] && FLAGS+=(--tb-nhi-selfloop-echo)', self.script)

    def test_an_echo_run_rebuilds_a_guest_without_the_module(self):
        self.assertIn("grep -q 'xdev_ext_xdomain.ko$' \"$SCRATCH/build/xdev-ext-artifacts.sha256\"", self.script)

    def test_echo_summary_follows_the_topology_summary(self):
        self.assertIn('summarize_echo "$OUT/tb-nhi-enum.txt" "$OUT/tb-selfloop-echo.txt"', self.script)


if __name__ == "__main__":
    unittest.main()
