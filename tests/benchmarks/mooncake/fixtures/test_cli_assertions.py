"""Self-tests for independent test transport; never execute/import the runner."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("mooncake_contract_tests", Path(__file__).resolve().parents[1] / "test_contract.py")
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class CLIAssertionTransport(unittest.TestCase):
    def test_taskset_prefix_is_separate_from_tebench_flags(self):
        argv = ["taskset", "--cpu-list", "2-5", "/missing/tebench", "--backend=tent"]
        self.assertEqual(contract.options(argv), {"backend":"tent"})

    def test_wrong_prefix_is_rejected(self):
        invalid = [
            ["bash", "--cpu-list", "2-5", "/missing/tebench", "--backend=tent"],
            ["taskset", "-c", "2-5", "/missing/tebench", "--backend=tent"],
            ["taskset", "--cpu-list", "", "/missing/tebench", "--backend=tent"],
            ["taskset", "--cpu-list", "2-5"],
        ]
        for argv in invalid:
            with self.subTest(argv=argv), self.assertRaises(AssertionError):
                contract.options(argv)

    def test_unknown_taskset_flag_is_rejected(self):
        invalid = [
            ["taskset", "--unknown", "2-5", "/missing/tebench", "--backend=tent"],
            ["taskset", "--cpu-list", "2-5", "--unknown", "/missing/tebench", "--backend=tent"],
        ]
        for argv in invalid:
            with self.subTest(argv=argv), self.assertRaises(AssertionError):
                contract.options(argv)

    def test_extra_tebench_flag_remains_visible_to_exact_set_assertion(self):
        argv = ["taskset", "--cpu-list", "2-5", "/missing/tebench", "--backend=tent", "--mixed=true"]
        flags = contract.options(argv)
        self.assertEqual(flags.get("mixed"), "true")
        # This is the same exact-key assertion used by the behavioral tests.
        # An extra algorithm flag must produce an assertion, not be stripped.
        with self.assertRaises(AssertionError):
            self.assertEqual(set(flags), {"backend"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
