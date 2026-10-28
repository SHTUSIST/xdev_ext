#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Executes the production CREATE class-bind wrapper with a fake class; proves
ordering and the kind refusal, not any class's own bind.

F9a breaks caught: checking a kind after bind side effects; missing compute
validation; assigning visibility before/after a failed bind; changing legacy
classes without hooks; and interpreting another family's union as compute.
No test-side implementation of kind decisions or default capability rules.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile


KERNEL = Path(__file__).resolve().parents[5]


def declaration(text, pattern, label):
    """Keep production declaration bytes, locating braces outside comments/literals."""
    match = re.search(pattern, text, re.M)
    if match is None:
        raise AssertionError(f"{label} missing")
    start = match.start()
    tail = text[start:]
    clean = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                   lambda m: " " * len(m.group()), tail, flags=re.S)
    opening = clean.index("{")
    depth = 0
    for pos in range(opening, len(clean)):
        depth += clean[pos] == "{"
        depth -= clean[pos] == "}"
        if depth == 0:
            return tail[:pos + 1]
    raise AssertionError(f"{label} has no closing brace")


SHIM = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16;
typedef uint32_t u32; typedef uint64_t u64;
#include "io_uring/xdev_ext_mech_step.h"
#include "include/linux/xdev_ext_family_core.h"
struct module; struct xdev_ext_mech_stage; struct xdev_ext_mech_batch;
struct xdev_ext_rel_policy;
'''

BODY = r'''
/* Real comp hooks and pure rules; only the runtime stage envelope is replaced.
 * family_hdr and class_ops above are sliced from the real mech contract. */
#include "include/linux/xdev_ext_compfam.h"
struct xdev_ext_mech_stage {
 u32 create_valid;bool create_reporting;
 u32 class_id;
 const struct xdev_ext_mech_class_ops *cls;
 struct xdev_ext_mech_stage_caps caps;
};
static unsigned bind_calls;
static int bind_result;
static struct xdev_ext_mech_stage_caps observed;
static const struct xdev_ext_mech_stage_uapi *expected_u;
static u32 bind_visibility;

/* The callback records the state established by the real wrapper. A distinct
 * visibility value tests whether the wrapper applies hooks after success only. */
static int fake_bind(struct xdev_ext_mech_stage *st,
                     const struct xdev_ext_mech_stage_uapi *u)
{
 assert(u == expected_u);
 bind_calls++;
 observed = st->caps;
 st->caps.producer_visibility = bind_visibility;
 st->caps.native_queue = XDEV_EXT_CAP_ESTABLISHED;
 return bind_result;
}

static struct xdev_ext_mech_class_ops ops = { .bind = fake_bind };
static struct xdev_ext_mech_stage st;
static struct xdev_ext_mech_stage_uapi stage;
static struct xdev_ext_comp_hooks hooks = {
 .hdr = { .family = XDEV_EXT_FAMILY_COMPUTE },
 .kinds = 1U << XDEV_EXT_COMP_COPY_WINDOW,
 .producer_visibility = XDEV_EXT_CAP_NOT_WIRED,
};

static void reset(u32 class_id, u32 direction, u64 arg0)
{
 stage = (struct xdev_ext_mech_stage_uapi){
  .class_id = class_id, .direction = direction, .arg0 = arg0,
 };
 memset(&st, 0xa5, sizeof(st));
 /* Legacy CREATE does not request a report; retain poisoned caps so the
  * original wrapper-capability initialization assertions remain effective. */
 st.create_reporting=false;st.create_valid=0;
 st.class_id = class_id;
 st.cls = &ops;
 ops.class_id = class_id;
 ops.fam.hdr = NULL;
 expected_u = &stage;
 bind_calls = 0;
 bind_result = 0;
 bind_visibility = XDEV_EXT_CAP_ESTABLISHED;
 memset(&observed, 0, sizeof(observed));
}
'''

MAIN = r'''
int main(void)
{
 const u32 legacy[] = { XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_CLASS_DMA,
  XDEV_EXT_MECH_CLASS_IAA, XDEV_EXT_MECH_CLASS_CPU, XDEV_EXT_MECH_CLASS_USER };
 const u32 visibility[] = { XDEV_EXT_CAP_UNKNOWN, XDEV_EXT_CAP_ESTABLISHED,
  XDEV_EXT_CAP_NOT_WIRED, XDEV_EXT_CAP_NOT_APPLICABLE };
 unsigned i;

 reset(XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_DIR_FROM_DEVICE, 0);
 ops.fam.comp = &hooks;
 assert(!xdev_ext_mech_class_bind(&st, &stage, XDEV_EXT_MECH_POOL_IOU_UMEM));
 assert(bind_calls == 1 && observed.family == XDEV_EXT_FAMILY_COMPUTE);
 assert(observed.size == sizeof(observed) &&
        observed.version == XDEV_EXT_MECH_STAGE_CAPS_VERSION);
 assert(observed.producer_visibility == XDEV_EXT_CAP_NOT_APPLICABLE);
 assert(observed.native_queue == XDEV_EXT_CAP_UNKNOWN &&
        observed.p2p_distance == -1 && observed.refused == 0);
 assert(st.caps.native_queue == XDEV_EXT_CAP_ESTABLISHED);
 puts("ok 1 - default capability record precedes class bind");

 reset(XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_DIR_FROM_DEVICE, 0);
 ops.fam.comp = &hooks;
 hooks.kinds = 1U << XDEV_EXT_COMP_TRANSFORM;
 assert(xdev_ext_mech_class_bind(&st, &stage, XDEV_EXT_MECH_POOL_IOU_UMEM) == -EINVAL);
 assert(bind_calls == 0);
 hooks.kinds = 0;
 assert(xdev_ext_mech_class_bind(&st, &stage, XDEV_EXT_MECH_POOL_IOU_UMEM) == -EINVAL);
 assert(bind_calls == 0);
 hooks.kinds = 1U << XDEV_EXT_COMP_COPY_WINDOW;
 stage.direction = 0;
 assert(xdev_ext_mech_class_bind(&st, &stage, XDEV_EXT_MECH_POOL_IOU_UMEM) == -EINVAL);
 assert(bind_calls == 0);
 puts("ok 2 - missing declared kind and invalid role fail before bind");

 for (i = 0; i < sizeof(visibility) / sizeof(visibility[0]); i++) {
  reset(XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_DIR_TO_DEVICE, 0);
  ops.fam.comp = &hooks;
  hooks.producer_visibility = visibility[i];
  bind_visibility = XDEV_EXT_CAP_UNKNOWN;
  assert(!xdev_ext_mech_class_bind(&st, &stage, XDEV_EXT_MECH_POOL_IOU_UMEM));
  assert(bind_calls == 1 && st.caps.producer_visibility == visibility[i]);
  assert(st.caps.native_queue == XDEV_EXT_CAP_ESTABLISHED);
 }
 puts("ok 3 - successful compute bind reports declared producer visibility");

 reset(XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_DIR_FROM_DEVICE, 0);
 ops.fam.comp = &hooks;
 hooks.producer_visibility = XDEV_EXT_CAP_NOT_WIRED;
 bind_result = -ENODEV;
 assert(xdev_ext_mech_class_bind(&st, &stage, XDEV_EXT_MECH_POOL_IOU_UMEM) == -ENODEV);
 assert(bind_calls == 1 && st.caps.producer_visibility == XDEV_EXT_CAP_ESTABLISHED);
 puts("ok 4 - failed bind preserves its error and does not apply hook visibility");

 /* NET's real family union has another layout. Zero kinds in the stand-in
  * ensure unconditional comp interpretation refuses it instead of binding. */
 reset(XDEV_EXT_MECH_CLASS_NET, XDEV_EXT_MECH_DIR_FROM_DEVICE, 0);
 hooks.hdr.family = XDEV_EXT_FAMILY_NETWORK;
 hooks.kinds = 0;
 ops.fam.hdr = &hooks.hdr;
 assert(!xdev_ext_mech_class_bind(&st, &stage, XDEV_EXT_MECH_POOL_PEER));
 assert(bind_calls == 1 && observed.family == XDEV_EXT_FAMILY_NETWORK);
 assert(observed.producer_visibility == XDEV_EXT_CAP_NOT_WIRED);
 assert(st.caps.producer_visibility == XDEV_EXT_CAP_ESTABLISHED);
 puts("ok 5 - network family hooks are not interpreted as compute hooks");

 reset(XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_DIR_TO_DEVICE, 0);
 hooks.hdr.family = XDEV_EXT_FAMILY_STORAGE;
 ops.fam.hdr = &hooks.hdr;
 assert(!xdev_ext_mech_class_bind(&st, &stage, XDEV_EXT_MECH_POOL_PEER));
 assert(bind_calls == 1 && observed.family == XDEV_EXT_FAMILY_STORAGE);
 assert(st.caps.producer_visibility == XDEV_EXT_CAP_ESTABLISHED);
 puts("ok 6 - storage family hooks are not interpreted as compute hooks");

 for (i = 0; i < sizeof(legacy) / sizeof(legacy[0]); i++) {
  reset(legacy[i], XDEV_EXT_MECH_DIR_TO_DEVICE, XDEV_EXT_CPU_XFORM_BPF);
  assert(!xdev_ext_mech_class_bind(&st, &stage, XDEV_EXT_MECH_POOL_IOU_UMEM));
  assert(bind_calls == 1 && observed.family == XDEV_EXT_FAMILY_COMPUTE);
  assert(st.caps.producer_visibility == XDEV_EXT_CAP_ESTABLISHED);
 }
 reset(XDEV_EXT_MECH_CLASS_CPU, XDEV_EXT_MECH_DIR_TO_DEVICE, XDEV_EXT_CPU_XFORM_BPF);
 bind_result = -EOPNOTSUPP;
 assert(xdev_ext_mech_class_bind(&st, &stage, XDEV_EXT_MECH_POOL_IOU_UMEM) == -EOPNOTSUPP);
 assert(bind_calls == 1);
 puts("ok 7 - every legacy compute class without hooks keeps its bind behavior");
 return 0;
}
'''


def main():
    path = KERNEL / "io_uring/xdev_ext_mech.c"
    production = declaration(path.read_text(),
                             r"^static int xdev_ext_mech_class_bind\s*\(",
                             "xdev_ext_mech_class_bind")
    contract = (KERNEL / "include/linux/xdev_ext_mech.h").read_text()
    hdr = declaration(contract, r"^struct xdev_ext_family_hooks_hdr\s*\{",
                      "xdev_ext_family_hooks_hdr") + ";\n"
    ops = declaration(contract, r"^struct xdev_ext_mech_class_ops\s*\{",
                      "xdev_ext_mech_class_ops") + ";\n"
    with tempfile.TemporaryDirectory(prefix="compfam-class-bind-") as tmp:
        source, binary = Path(tmp) / "t.c", Path(tmp) / "t"
        source.write_text(SHIM + hdr + ops + BODY + production + MAIN)
        subprocess.run(shlex.split(os.environ.get("CC", "gcc")) + [
            "-std=gnu11", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
            "-I" + str(KERNEL), "-idirafter", str(KERNEL / "include"),
            str(source), "-o", str(binary)], check=True, timeout=30)
        subprocess.run([str(binary)], check=True, timeout=10)


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"not ok 1 - compute CREATE class-bind fixture: {exc}", file=sys.stderr)
        raise SystemExit(1)
