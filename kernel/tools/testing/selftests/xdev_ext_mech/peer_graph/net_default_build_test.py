#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the real core default-build branch and NET RX builder on host
metadata; no NIC, GPU, DMA, performance or physical completion is represented.

Catches a successful NET default builder returning its descriptor count as an
error: BUILD_DEFAULT must reach submission with three populated descriptor slots.
"""
import os
from pathlib import Path
import subprocess
import tempfile

KERNEL = Path(__file__).resolve().parents[5]

SHIM = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_step.h"
typedef uint8_t u8;
typedef uint32_t u32;
struct xdev_ext_mech_frame { u32 data_off, data_len; };
struct xdev_ext_mech_batch {
 struct xdev_ext_mech_frame f[3];
 u32 nr;
};
struct xdev_ext_mech_stage;
struct fixture_class {
 u32 desc_size, desc_cap;
 int (*default_build)(struct xdev_ext_mech_stage *, struct xdev_ext_mech_batch *, u8 *);
 int (*validate)(struct xdev_ext_mech_stage *, struct xdev_ext_mech_batch *, const u8 *, u32);
};
struct xdev_ext_mech_stage {
 void *priv;
 const struct fixture_class *cls;
};
struct xdev_ext_mech_session {
 u8 scratch[sizeof(struct xdev_ext_net_send_desc) * XDEV_EXT_NET_MAX_ENTRIES];
};
struct xdev_ext_netfam_stage { bool rx; u32 header_room; };
static u32 validated_slots, validation_calls;
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch *b)
{ return b->nr; }
static int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch *b, u32 i,
                                   struct xdev_ext_mech_frame *out)
{
 if (i >= b->nr) return -EINVAL;
 *out = b->f[i];
 return 0;
}
/* Recording boundary below the actual default branch: the fixture represents
 * only descriptor construction/worker continuation, not device validation. */
static int fixture_validate(struct xdev_ext_mech_stage *st,
                            struct xdev_ext_mech_batch *b,
                            const u8 *scratch, u32 nr)
{
 const struct xdev_ext_net_send_desc *d = (const void *)scratch;
 static const struct { u32 off, len; } want[3] = {
  {64, 1000}, {128, 1200}, {0, 512},
 };
 (void)st; (void)b;
 validation_calls++;
 validated_slots = nr;
 if (nr != 3) return -EPROTO;
 for (u32 i = 0; i < 3; i++)
  if (d[i].frame_pos != i || d[i].frame_off != want[i].off ||
      d[i].len != want[i].len || d[i].header_len != 42 ||
      d[i].flags || d[i].reserved)
   return -EPROTO;
 return 0;
}
'''

MAIN = r'''
int main(void)
{
 struct xdev_ext_netfam_stage ns = {.rx = true, .header_room = 42};
 struct fixture_class cls = {
  .desc_size = sizeof(struct xdev_ext_net_send_desc),
  .desc_cap = XDEV_EXT_NET_MAX_ENTRIES,
  .default_build = xdev_ext_net_default_build,
  .validate = fixture_validate,
 };
 struct xdev_ext_mech_stage st = {.priv = &ns, .cls = &cls};
 struct xdev_ext_mech_batch batch = {
  .nr = 3, .f = {{64, 1000}, {128, 1200}, {0, 512}},
 };
 struct xdev_ext_mech_session s;
 int err, used;
 memset(&s, 0xa5, sizeof(s)); /* The actual DEFAULT branch clears scratch. */
 err = fixture_core_build(&s, &st, &batch, XDEV_EXT_MECH_BUILD_DEFAULT);
 used = xdev_ext_mech_slots_used(s.scratch, cls.desc_size, cls.desc_cap);
 if (err || used != 3 || validation_calls != 1 || validated_slots != 3) {
  fprintf(stderr, "not ok 1 - NET RX BUILD_DEFAULT must submit with 3 used slots: "
          "build_error=%d used_slots=%d validation_calls=%u validated_slots=%u\n",
          err, used, validation_calls, validated_slots);
  return 1;
 }
 puts("ok 1 - actual core BUILD_DEFAULT reaches submit with 3 real NET RX descriptor slots");
 return 0;
}
'''


def function_body(source, signature):
    """Keep the production definition, without copying its logic into a model."""
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def production_slices():
    net = (KERNEL / "io_uring/xdev_ext_mech_net.c").read_text()
    core = (KERNEL / "io_uring/xdev_ext_mech.c").read_text()
    build = function_body(core, "static int xdev_ext_mech_build(")
    # Execute the actual dispatch, DEFAULT block, slots-used rule and call to
    # validate. The BPF return resolver is outside this fixture: BUILD_DEFAULT
    # is already a legal, resolved build callback result.
    start = build.index("\tswitch (xdev_ext_mech_build_step(")
    end = build.index("\tif (err)\n\t\txdev_ext_mech_count", start)
    wrapper = r'''
static int fixture_core_build(struct xdev_ext_mech_session *s,
                              struct xdev_ext_mech_stage *st,
                              struct xdev_ext_mech_batch *b, __s32 ret)
{
 u32 len = st->cls->desc_size * st->cls->desc_cap;
 int err, n;
''' + build[start:end] + "\n return err;\n}\n"
    return function_body(net, "static int xdev_ext_net_default_build(") + "\n" + wrapper


def main():
    code = SHIM + production_slices() + MAIN
    with tempfile.TemporaryDirectory(prefix="net-default-build-") as tmp:
        path = Path(tmp)
        source = path / "test.c"
        source.write_text(code)
        command = [os.environ.get("CC", "gcc"), "-std=gnu11", "-Wall", "-Wextra",
                   "-Werror", "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                   "-I" + str(KERNEL), str(source), "-o", str(path / "test")]
        subprocess.run(command, check=True)
        subprocess.run([str(path / "test")], check=True)


if __name__ == "__main__":
    main()
