#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the unchanged production registration function with host locks/table.

This checks synchronous admission and table publication, not kernel concurrency.
The production class declaration is retained in full. Before F1 exists only,
append its specified optional tail so baseline registration can be called with
wrong-family hooks: it must fail behaviorally, not because a symbol is missing.
The separate source-only companion verifies the real contract has that tail.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

KERNEL = Path(__file__).resolve().parents[5]


def strip_comments(text):
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)


def declaration(text, pattern):
    match = re.search(pattern, text)
    if not match:
        raise AssertionError(f"production declaration not found: {pattern}")
    start = text.find("{", match.end())
    depth = 0
    for end in range(start, len(text)):
        depth += (text[end] == "{") - (text[end] == "}")
        if depth == 0:
            return text[match.start():end + 1]
    raise AssertionError("unterminated production declaration")


PREAMBLE = r'''
#include <stdio.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_step.h"
#if __has_include("include/linux/xdev_ext_family_core.h")
#include "include/linux/xdev_ext_family_core.h"
#endif
typedef __u8 u8;
typedef __u32 u32;
typedef __s32 s32;
'''

HARNESS = r'''
static const struct xdev_ext_mech_class_ops *xdev_ext_mech_classes[64];
static int xdev_ext_mech_class_lock;
static void mutex_lock(int *lock) { (void)lock; }
static void mutex_unlock(int *lock) { (void)lock; }
'''

CASES = r'''
static unsigned int checks, failures;
#define EXPECT(c, message) do { checks++; if (!(c)) { \
 fprintf(stderr, "FAIL class=%u family=%u: %s\n", class_id, family, message); \
 failures++; } } while (0)
static int bind_ok(struct xdev_ext_mech_stage *s,
                   const struct xdev_ext_mech_stage_uapi *u)
{ (void)s; (void)u; return 0; }
static int validate_ok(struct xdev_ext_mech_stage *s,
                       struct xdev_ext_mech_batch *b, const u8 *data, u32 n)
{ (void)s; (void)b; (void)data; (void)n; return 0; }
static int submit_ok(struct xdev_ext_mech_stage *s, struct xdev_ext_mech_batch *b)
{ (void)s; (void)b; return 0; }
static struct xdev_ext_mech_class_ops valid_ops(u32 class_id)
{
 struct xdev_ext_mech_class_ops ops = { 0 };
 ops.class_id = class_id;
 ops.desc_size = 16;
 ops.desc_cap = 1;
 ops.bind = bind_ok;
 ops.validate = validate_ok;
 ops.submit = submit_ok;
 return ops;
}
int main(void)
{
 static const struct { u32 class_id, family; } cases[] = {
  { XDEV_EXT_MECH_CLASS_NET, 1 }, { XDEV_EXT_MECH_CLASS_AFXDP, 1 },
  { XDEV_EXT_MECH_CLASS_SOCKET, 1 }, { XDEV_EXT_MECH_CLASS_NVME, 2 },
  { XDEV_EXT_MECH_CLASS_CE, 3 }, { XDEV_EXT_MECH_CLASS_DMA, 3 },
  { XDEV_EXT_MECH_CLASS_IAA, 3 }, { XDEV_EXT_MECH_CLASS_CPU, 3 },
  { XDEV_EXT_MECH_CLASS_USER, 3 },
 };
 u32 class_id = 0, family = 0;
 unsigned int i, bad;

 EXPECT(xdev_ext_mech_class_register(NULL) == -EINVAL, "NULL ops accepted");
 for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
  struct xdev_ext_mech_class_ops ops;

  class_id = cases[i].class_id;
  ops = valid_ops(class_id);
  memset(xdev_ext_mech_classes, 0, sizeof(xdev_ext_mech_classes));
  EXPECT(xdev_ext_mech_class_register(&ops) == 0, "optional NULL hooks rejected");
  EXPECT(xdev_ext_mech_classes[class_id] == &ops, "successful registration not published");
  EXPECT(xdev_ext_mech_class_register(&ops) == -EBUSY, "duplicate registration accepted");

  for (family = 0; family <= 4; family++) {
   struct xdev_ext_family_hooks_hdr hdr = { .family = family };
   int result;

   memset(xdev_ext_mech_classes, 0, sizeof(xdev_ext_mech_classes));
   ops.fam.hdr = &hdr;
   result = xdev_ext_mech_class_register(&ops);
   if (family == cases[i].family) {
    EXPECT(result == 0, "matching family rejected");
    EXPECT(xdev_ext_mech_classes[class_id] == &ops, "matching hooks not published");
   } else {
    EXPECT(result == -EINVAL, "wrong-family hooks admitted");
    EXPECT(xdev_ext_mech_classes[class_id] == NULL, "rejected hooks polluted registry");
   }
  }
  /* New hooks must not bypass any existing callback/size validity check. */
  for (bad = 0; bad < 7; bad++) {
   struct xdev_ext_family_hooks_hdr hdr = { .family = cases[i].family };

   memset(xdev_ext_mech_classes, 0, sizeof(xdev_ext_mech_classes));
   ops = valid_ops(class_id);
   ops.fam.hdr = &hdr;
   switch (bad) {
   case 0: ops.bind = NULL; break;
   case 1: ops.validate = NULL; break;
   case 2: ops.submit = NULL; break;
   case 3: ops.info_size = 1; break; /* no fill_info */
   case 4: ops.cqe_size = 1; ops.cqe_cap = 1; break; /* no fill_cqe */
   case 5: ops.desc_size = XDEV_EXT_MECH_CLASS_SIZE_MAX + 1; break;
   case 6: ops.desc_cap = 0; break;
   }
   EXPECT(xdev_ext_mech_class_register(&ops) == -EINVAL, "existing validity check bypassed");
   EXPECT(xdev_ext_mech_classes[class_id] == NULL, "invalid ops published");
  }
 }
 for (class_id = 0; class_id < 64; class_id++) {
  if (xdev_ext_mech_class_known(class_id))
   continue;
  for (family = 0; family <= 3; family++) {
   struct xdev_ext_family_hooks_hdr hdr = { .family = family };
   struct xdev_ext_mech_class_ops ops = valid_ops(class_id);

   memset(xdev_ext_mech_classes, 0, sizeof(xdev_ext_mech_classes));
   ops.fam.hdr = family ? &hdr : NULL;
   EXPECT(xdev_ext_mech_class_register(&ops) == -EINVAL, "unknown class admitted");
   EXPECT(xdev_ext_mech_classes[class_id] == NULL, "unknown class published");
  }
 }
 printf("%s - behavioral registration fixture (%u checks, %u failures)\n",
        failures ? "not ok" : "ok", checks, failures);
 return failures != 0;
}
'''


class ClassRegister(unittest.TestCase):
    def test_family_admission_preserves_registry_validation(self):
        header = strip_comments((KERNEL / "include/linux/xdev_ext_mech.h").read_text())
        source = strip_comments((KERNEL / "io_uring/xdev_ext_mech_ops.c").read_text())
        cls = declaration(header, r"struct\s+xdev_ext_mech_class_ops\s*(?=\{)")
        hdr_match = re.search(r"struct\s+xdev_ext_family_hooks_hdr\s*(?=\{)", header)
        hdr = (declaration(header, r"struct\s+xdev_ext_family_hooks_hdr\s*(?=\{)")
               if hdr_match else "struct xdev_ext_family_hooks_hdr { u32 family; }")
        if not re.search(r"\}\s*fam\s*;", cls):
            cls = cls[:-1] + "union { const struct xdev_ext_family_hooks_hdr *hdr; } fam; }"
        forwards = "\n".join(f"struct {name};" for name in sorted(set(
            re.findall(r"\bstruct\s+(\w+)", cls + hdr))))
        register = declaration(source, r"int\s+xdev_ext_mech_class_register\s*\([^;]+?\)\s*(?=\{)")
        probe = PREAMBLE + forwards + "\n" + hdr + ";\n" + cls + ";\n" + HARNESS + register + CASES
        with tempfile.TemporaryDirectory(prefix="xdev-ext-family-register-") as tmp:
            cfile = Path(tmp) / "register.c"
            binary = Path(tmp) / "register"
            cfile.write_text(probe)
            build = subprocess.run([os.environ.get("CC", "gcc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                                    "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                                    "-I" + str(KERNEL), str(cfile), "-o", str(binary)],
                                   capture_output=True, text=True, timeout=30)
            self.assertEqual(build.returncode, 0, "fixture build failed:\n" + build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
