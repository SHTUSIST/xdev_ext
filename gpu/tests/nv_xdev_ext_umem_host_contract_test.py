#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile actual host-bookkeeping bodies with allocation/pin-count stubs.

These tests execute ordinary host C only. They do not pin kernel pages, access
devices, resolve physical addresses, map MMIO, or perform a simulated transfer.
"""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / "kernel-open/nvidia/nv-p2p.c"
FIXTURE = HERE / "nv_xdev_ext_umem_host_contract_test.c"
FUNCTIONS = ("nv_pin_cxl_buffer", "nv_unpin_cxl_buffer",
             "nv_pin_cxl_buffer_hugepages", "nv_get_umem_buffer_info")


def extract_function(text, name):
    """Keep exact current function bytes; skip braces inside strings/comments."""
    match = re.search(r"NV_STATUS\s+NV_API_CALL\s+" + re.escape(name) + r"\s*\(", text)
    if not match:
        raise AssertionError("actual production function missing: " + name)
    opening = text.index("{", match.end())
    depth, state, index = 1, "code", opening + 1
    while index < len(text):
        char = text[index]
        pair = text[index:index+2]
        if state == "line":
            if char == "\n": state = "code"
        elif state == "comment":
            if pair == "*/": state = "code"; index += 1
        elif state in ('"', "'"):
            if char == "\\": index += 1
            elif char == state: state = "code"
        elif pair == "//": state = "line"; index += 1
        elif pair == "/*": state = "comment"; index += 1
        elif char in ('"', "'"): state = char
        elif char == "{": depth += 1
        elif char == "}":
            depth -= 1
            if not depth: return text[match.start():index+1]
        index += 1
    raise AssertionError("unbalanced actual function: " + name)


def actual_source(text):
    enum = re.search(r"typedef enum\s*\{[^}]*\}\s*nv_p2p_buffer_type_t;", text, re.S)
    record = re.search(r"typedef struct\s*\{[^}]*\}\s*nv_p2p_umem_buffer_t;", text, re.S)
    if not enum or not record:
        raise AssertionError("actual production buffer metadata missing")
    # Preserve upstream licensing alongside extracted, unmodified source bytes.
    license_end = text.index("*/") + 2
    return (text[:license_end] + "\n" + enum.group() + "\n" + record.group() +
            "\ntypedef nv_p2p_umem_buffer_t cxl_pinned_buffer_t;\n" +
            "\n\n".join(extract_function(text, name) for name in FUNCTIONS) + "\n")


class ActualHostBookkeepingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix=".umem-host-contract-", dir=HERE)
        cls.directory = Path(cls.temp.name)
        cls.source_text = SOURCE.read_text()
        generated = actual_source(cls.source_text)
        (cls.directory / "nv_xdev_ext_umem_host_contract_actual.inc").write_text(generated)
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if not compiler:
            raise AssertionError("C compiler required for ordinary host contract tests")
        cls.binaries = []
        for strict in (0, 1):
            for page_shift in (12, 16):
                binary = cls.directory / ("host-bookkeeping-" + str(strict) + "-" + str(page_shift))
                result = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-Wno-sign-compare", "-fsanitize=undefined", "-fno-sanitize-recover=all",
                    "-DNV_P2P_UMEM_STRICT_SECURITY_CHECKS=" + str(strict),
                    "-DPAGE_SHIFT=" + str(page_shift),
                    "-I", str(cls.directory), str(FIXTURE), "-o", str(binary)],
                    text=True, capture_output=True, timeout=30)
                if result.returncode:
                    raise AssertionError("actual source fixture did not compile:\n" + result.stderr)
                cls.binaries.append((strict, page_shift, binary))
        print("actual nv-p2p.c sha256=" + hashlib.sha256(cls.source_text.encode()).hexdigest())

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def check_case(self, case, hints=(0, 1)):
        for strict, page_shift, binary in self.binaries:
            for huge in hints:
                with self.subTest(strict=strict, page_shift=page_shift, huge_hint=huge, case=case):
                    result = subprocess.run([str(binary), str(huge), case],
                        text=True, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 0,
                        f"actual production host case={case}\nstdout={result.stdout}\nstderr={result.stderr}")
                    self.assertIn("ordinary host bookkeeping checks", result.stdout)

    def test_actual_function_extraction_preserves_production_bodies(self):
        generated = actual_source(self.source_text)
        for name in FUNCTIONS:
            body = extract_function(self.source_text, name)
            self.assertIn(body, generated)
            self.assertGreater(len(body), 200)

    def test_page_size_units_and_metadata_normal(self):
        self.check_case("normal")

    def test_two_megabyte_hint_still_counts_base_pages(self):
        self.check_case("hint2m")

    def test_array_allocation_512_513_boundary(self):
        self.check_case("array512")
        self.check_case("array513")

    def test_unaligned_address_and_length_cover_all_base_pages(self):
        self.check_case("unaligned")
        self.check_case("unaligned-length")
        for case in ("bytes1", "bytes-page-minus1", "bytes-page", "bytes-page-plus1",
                     "offset-page-minus1", "offset-page"):
            self.check_case(case)

    def test_null_output_and_quota_refusal_have_no_resource_side_effects(self):
        self.check_case("null-output")
        self.check_case("quota-refusal")

    def test_short_zero_and_failed_pin_release_exact_owned_count(self):
        for case in ("short", "pinerror", "pinnone"):
            self.check_case(case)

    def test_allocation_failure_rolls_back_exact_quota(self):
        for case in ("alloc1", "alloc2", "alloc3"):
            self.check_case(case)

    def test_full_pin_with_invalid_entry_releases_all_valid_owned_pages(self):
        self.check_case("nullentry")

    def test_invalid_range_before_allocation_charge_or_narrowing(self):
        for case in ("invalid-zero", "invalid-overflow", "invalid-narrowzero",
                     "invalid-narrow", "invalid-limit"):
            self.check_case(case)

    def test_valid_info_and_optional_frame_count_query(self):
        self.check_case("info-valid", (0,))
        self.check_case("info-max", (0,))
        self.check_case("info-optional", (0,))

    def test_zero_frame_size_fails_before_arithmetic_or_output_writes(self):
        self.check_case("info-zero", (0,))

    def test_nondivisible_or_narrow_frame_count_fails_without_output_writes(self):
        self.check_case("info-nondiv", (0,))
        self.check_case("info-wide", (0,))


if __name__ == "__main__":
    unittest.main()
