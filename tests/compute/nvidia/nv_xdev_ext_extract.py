#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Shared helpers for host tests that compile actual production C bodies.

The helpers copy exact production bytes (functions, typedefs, structs) into a
generated translation unit next to an ordinary host fixture.  They never
rewrite a body.  The fixtures stub only allocation, locking, RM/OS and device
boundaries; no kernel page, GPU, MMIO or DMA engine is touched.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
GPU = HERE.parent
REPO = GPU.parent


def read(rel):
    return (GPU / rel).read_text()


def _skip_balanced(text, index, opening, closing):
    """index points at opening; return index just past the matching closing."""
    depth, state = 0, "code"
    while index < len(text):
        char = text[index]
        pair = text[index:index + 2]
        if state == "line":
            if char == "\n":
                state = "code"
        elif state == "comment":
            if pair == "*/":
                state = "code"
                index += 1
        elif state in ('"', "'"):
            if char == "\\":
                index += 1
            elif char == state:
                state = "code"
        elif pair == "//":
            state = "line"
            index += 1
        elif pair == "/*":
            state = "comment"
            index += 1
        elif char in ('"', "'"):
            state = char
        elif char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    raise AssertionError("unbalanced production text")


def _line_start(text, index):
    return text.rfind("\n", 0, index) + 1


def find_function(text, name):
    """Return (start, end) of the definition of name, or None.

    Accepts kernel style (type and name on one line) and RM style (return
    type on its own line, the parameter list opening on the next line).
    """
    for match in re.finditer(r"\b" + re.escape(name) + r"\s*\(", text):
        start_line = _line_start(text, match.start())
        prefix = text[start_line:match.start()]
        # Skip calls and declarations inside other code: a definition's name is
        # preceded on its line only by return-type tokens.
        if re.search(r"[=;,(){}!&|+\-?:]|\breturn\b|\bif\b|\bwhile\b", prefix):
            continue
        paren = text.index("(", match.end() - 1)
        after = _skip_balanced(text, paren, "(", ")")
        rest = text[after:]
        stripped = rest.lstrip()
        if not stripped.startswith("{"):
            continue
        brace = after + (len(rest) - len(stripped))
        end = _skip_balanced(text, brace, "{", "}")
        start = start_line
        # RM style: prepend preceding return-type lines.
        while start > 0:
            prev_start = _line_start(text, start - 1)
            prev = text[prev_start:start - 1].strip()
            if (not prev or prev.endswith((";", "}", "*/", "{", ")")) or
                    prev.startswith(("#", "//", "*", "/*"))):
                break
            start = prev_start
        return start, end
    return None


def function(text, name):
    span = find_function(text, name)
    if span is None:
        raise AssertionError("actual production function missing: " + name)
    return text[span[0]:span[1]]


def has_function(text, name):
    return find_function(text, name) is not None


def typedef_struct(text, name):
    match = re.search(r"typedef\s+struct\s*\w*\s*\{", text[:])
    for match in re.finditer(r"typedef\s+struct\s*\w*\s*\{", text):
        end = _skip_balanced(text, match.end() - 1, "{", "}")
        tail = re.match(r"\s*(\w+)\s*;", text[end:])
        if tail and tail.group(1) == name:
            return text[match.start():end + tail.end()]
    raise AssertionError("actual production typedef missing: " + name)


def struct(text, name):
    match = re.search(r"\bstruct\s+" + re.escape(name) + r"\s*\{", text)
    if not match:
        raise AssertionError("actual production struct missing: " + name)
    end = _skip_balanced(text, match.end() - 1, "{", "}")
    semi = text.index(";", end)
    return text[match.start():semi + 1]


def license_header(text):
    return text[:text.index("*/") + 2] + "\n"


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def compilers():
    names = os.environ.get("XDEV_EXT_TEST_CCS")
    if names:
        wanted = names.split(",")
    else:
        wanted = [os.environ.get("CC", "cc")]
    found = [shutil.which(name) for name in wanted]
    if not all(found):
        raise AssertionError("requested C compiler unavailable: " +
                             ", ".join(n for n, p in zip(wanted, found) if not p))
    return found


class Build:
    """Compile one fixture with generated includes into a private directory."""

    def __init__(self, prefix):
        self.temp = tempfile.TemporaryDirectory(prefix=prefix, dir=HERE)
        self.dir = Path(self.temp.name)
        evidence = os.environ.get("XDEV_EXT_TEST_EVIDENCE")
        self.evidence = Path(evidence) / self.dir.name if evidence else None
        if self.evidence:
            self.evidence.mkdir(parents=True, exist_ok=False)

    def record(self, name, value):
        if self.evidence:
            with (self.evidence / name).open("a") as out:
                out.write(json.dumps(value, sort_keys=True) + "\n")

    def write(self, name, content):
        path = self.dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        if self.evidence:
            saved = self.evidence / name
            saved.parent.mkdir(parents=True, exist_ok=True)
            saved.write_text(content)
            self.record("extractions.jsonl", {"file": name, "sha256": sha(content)})
        return path

    def compile(self, fixture, output, defines=(), extra=(), compiler=None,
                threads=False):
        compiler = compiler or compilers()[0]
        command = [compiler, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra",
                   "-Werror", "-Wno-unused-function", "-Wno-unused-parameter",
                   "-Wno-sign-compare", "-Wno-missing-field-initializers",
                   "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                   "-fno-omit-frame-pointer", "-I", str(self.dir)]
        command += ["-D" + define for define in defines]
        command += list(extra)
        command += [str(fixture), "-o", str(self.dir / output)]
        if threads:
            command.append("-pthread")
        result = subprocess.run(command, text=True, capture_output=True,
                                timeout=120)
        if self.evidence:
            shutil.copy2(fixture, self.evidence / fixture.name)
        self.record("builds.jsonl", {"command": command, "exit": result.returncode,
                                    "stdout": result.stdout, "stderr": result.stderr})
        return result, command

    def run(self, output, *args, timeout=30):
        env = dict(os.environ)
        env.setdefault("ASAN_OPTIONS", "detect_leaks=0")
        command = [str(self.dir / output)] + list(args)
        result = subprocess.run(command, text=True, capture_output=True,
                                timeout=timeout, env=env)
        self.record("cases.jsonl", {"command": command, "exit": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        return result

    def cleanup(self):
        self.temp.cleanup()
