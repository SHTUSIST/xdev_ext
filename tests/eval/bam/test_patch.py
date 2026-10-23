#!/usr/bin/env python3
"""Host checks of the BaM compatibility patch and its pin tooling; builds and runs no BaM.

Run with python3 tests/eval/bam/test_patch.py -v.
"""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
PATCH = HERE / "bam-linux6-gcc13-compat.patch"
LOCK = HERE / "upstream.lock"
FINDER = HERE / "find_upstream_commit.sh"
FILES = ("module/map.c", "module/pci.c", "include/freestanding/libcxx/include/type_traits")


def git(cwd, *args, **kwargs):
    return subprocess.run(["git", "-C", str(cwd)] + list(args), check=True, text=True,
                          capture_output=True, **kwargs).stdout


class PatchShape(unittest.TestCase):
    def test_touches_exactly_the_three_files(self):
        text = PATCH.read_text()
        self.assertEqual(re.findall(r"^--- a/(\S+)$", text, re.M), list(FILES))
        self.assertEqual(re.findall(r"^\+\+\+ b/(\S+)$", text, re.M), list(FILES))

    def test_added_and_removed_lines_are_the_stated_edits(self):
        removed = [l[1:] for l in PATCH.read_text().splitlines()
                   if l.startswith("-") and not l.startswith("---")]
        added = [l[1:] for l in PATCH.read_text().splitlines()
                 if l.startswith("+") and not l.startswith("+++")]
        # map.c: the 6.5 branch; pci.c: version.h and the 6.4 branch; type_traits: 14 renames.
        self.assertIn("#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)", added)
        self.assertIn("    retval = get_user_pages(map->vaddr, map->n_addrs, FOLL_WRITE, pages);", added)
        self.assertIn("#include <linux/version.h>", added)
        self.assertIn("    dev_class = class_create(DRIVER_NAME);", added)
        renames = [l for l in added if "__libcpp_is_convertible" in l]
        self.assertEqual(len(renames), 14)
        self.assertEqual(len([l for l in removed if "__is_convertible<" in l or
                              l.strip() == "struct __is_convertible"]), 14)
        self.assertEqual(len(removed), 15)  # 14 renames and the replaced #else
        self.assertEqual(len(added), 22)  # map.c 3, pci.c 5, type_traits 14

    def test_lock_is_well_formed(self):
        blobs = [l.split() for l in LOCK.read_text().splitlines() if l.startswith("blob ")]
        self.assertEqual([b[1] for b in blobs], list(FILES))
        for _, _, before, after in blobs:
            self.assertRegex(before, r"^[0-9a-f]{40}$")
            self.assertRegex(after, r"^[0-9a-f]{40}$")
            self.assertNotEqual(before, after)
        self.assertIn("url https://github.com/ZaidQureshi/bam", LOCK.read_text())


@unittest.skipUnless(shutil.which("git"), "git unavailable")
class FinderOnSyntheticClone(unittest.TestCase):
    """The finder logic on a stand-in history; it says nothing about BaM itself."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bam-finder-")
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.email", "t@example.invalid")
        git(self.repo, "config", "user.name", "t")
        self.write("one\n", "two\n", "three\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "first")
        self.write("one\n", "two changed\n", "three\n")
        git(self.repo, "commit", "-qam", "second")
        self.pinned = git(self.repo, "rev-parse", "HEAD").strip()
        blobs = [git(self.repo, "rev-parse", "HEAD:" + f).strip() for f in FILES]
        self.write("one\n", "two changed\n", "three edited\n")
        patch = git(self.repo, "diff")
        after = [git(self.repo, "hash-object", f).strip() for f in FILES]
        git(self.repo, "checkout", "-q", "--", ".")
        self.write("one\n", "two changed\n", "three later\n")
        git(self.repo, "commit", "-qam", "third")
        self.lock = Path(self.temp.name) / "lock"
        self.lock.write_text("".join("blob %s %s %s\n" % (f, b, a)
                                     for f, b, a in zip(FILES, blobs, after)))
        self.patch = Path(self.temp.name) / "patch"
        self.patch.write_text(patch)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, *contents):
        for name, text in zip(FILES, contents):
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def run_finder(self, lock):
        return subprocess.run(["sh", str(FINDER), str(self.repo), str(lock), str(self.patch)],
                              text=True, capture_output=True, timeout=60)

    def test_finds_only_the_matching_commit_and_checks_the_patch(self):
        head = git(self.repo, "rev-parse", "HEAD").strip()
        result = self.run_finder(self.lock)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(re.findall(r"^match (\w+)", result.stdout, re.M), [self.pinned])
        self.assertIn("pin %s (patch applies)" % self.pinned, result.stdout)
        # Read-only: the work tree and HEAD are unchanged.
        self.assertEqual(git(self.repo, "rev-parse", "HEAD").strip(), head)
        self.assertEqual(git(self.repo, "status", "--porcelain"), "")

    def test_no_match_fails(self):
        bad = Path(self.temp.name) / "bad-lock"
        bad.write_text(self.lock.read_text().replace(self.lock.read_text().split()[2], "0" * 40, 1))
        result = self.run_finder(bad)
        self.assertEqual(result.returncode, 1)
        self.assertIn("no commit", result.stderr)


if __name__ == "__main__":
    unittest.main()
