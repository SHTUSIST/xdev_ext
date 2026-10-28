#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute production requester bind/unbind and provider describe boundaries.

Only PCI topology, provider mapping and lock/device boundaries are replaced.
Admission and default caps are real pure production rules. No DMA is performed.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

KERNEL = Path(__file__).resolve().parents[5]


def exported(path, declaration, name):
    text = (KERNEL / path).read_text() if (KERNEL / path).exists() else ""
    if declaration not in text or f"EXPORT_SYMBOL_GPL({name});" not in text:
        print(f"not ok 1 - {name} missing", flush=True)
        return None
    return text[text.index(declaration):text.index(f"EXPORT_SYMBOL_GPL({name});")]


def execute(shim, production, main):
    with tempfile.TemporaryDirectory(prefix="requester-bind-") as tmp:
        source, binary = Path(tmp) / "t.c", Path(tmp) / "t"
        source.write_text(shim + production + main)
        subprocess.run(shlex.split(os.environ.get("CC", "gcc")) + [
            "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
            "-fno-sanitize-recover=undefined", "-I" + str(KERNEL),
            "-idirafter", str(KERNEL / "include"),
            str(source), "-o", str(binary)], check=True, timeout=30)
        subprocess.run([str(binary)], check=True, timeout=10)


def static_function(name):
    text = (KERNEL / "io_uring/xdev_ext_mech.c").read_text()
    match = re.search(r"static int " + re.escape(name) + r"\s*\(", text)
    if not match:
        print(f"not ok 1 - {name} missing", flush=True)
        return None
    # These small functions contain no string literals with braces. Preserve
    # the production bytes, including comments; only use a stripped copy to
    # locate matching braces.
    start = match.start()
    scan = re.sub(r"/\*.*?\*/|//[^\n]*", lambda m: " " * len(m.group()), text[start:], flags=re.S)
    opening, depth = scan.index("{"), 0
    for i in range(opening, len(scan)):
        depth += scan[i] == "{"
        depth -= scan[i] == "}"
        if depth == 0:
            return text[start:start + i + 1]
    raise AssertionError(f"unbalanced production function {name}")


SHIM = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
enum dma_data_direction { DMA_BIDIRECTIONAL, DMA_TO_DEVICE, DMA_FROM_DEVICE };
#include "io_uring/xdev_ext_mech_step.h"
#include "include/linux/xdev_ext_requester_core.h"
#define XDEV_EXT_PEER_HOST_TEST
/* The real header catches a missing forward declaration before ->describe. */
#include "include/linux/xdev_ext_peer.h"
struct device { int id; };
struct pci_bus { int domain; unsigned char number; };
struct pci_dev { struct device dev; bool untrusted; struct pci_bus *bus; unsigned int devfn; };
static int pci_domain_nr(struct pci_bus *bus) { assert(bus); return bus->domain; }
struct file { int id; };
struct xdev_ext_mech_pool { u32 kind; };
struct xdev_ext_mech_session { struct xdev_ext_mech_pool pool; };
struct xdev_ext_mech_stage { struct xdev_ext_mech_session *s; struct xdev_ext_mech_stage_caps caps;
 bool create_reporting; u32 create_phase, create_valid;
 struct xdev_ext_mech_requester_id create_requester_id; struct pci_dev *create_requester; };
struct xdev_ext_requester {
 struct pci_dev *pdev; struct file *authority; u64 generation; struct xdev_ext_admission adm;
};
#define CAP_SYS_ADMIN 21
static struct pci_dev gpu, nhi;
static struct file authority;
static struct xdev_ext_mech_session session;
static struct xdev_ext_mech_stage st;
static struct xdev_ext_requester rq;
static struct pci_dev *describe_requester, *distance_provider;
static struct device *distance_client;
static unsigned describe_calls, distance_calls, premaps, pci_refs;
static int distance, describe_ret, premap_ret;
static bool dma_iommu_present, dma_ops_present, bounce, admin, owner_known;
static u32 describe_flags;
static int ops;
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s)
{ assert(s == &session); return &s->pool; }
static struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *p)
{ assert(p == &session.pool); return &authority; }
static u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *p)
{ assert(p == &session.pool); return UINT64_C(0x12345678abcdef01); }
int xdev_ext_peer_file_describe(struct file *f, struct pci_dev *p, struct xdev_ext_peer_backing *out)
{
 assert(f == &authority); describe_calls++; describe_requester = p;
 if (describe_ret) return describe_ret;
 *out = (struct xdev_ext_peer_backing){ .owner = owner_known ? &gpu : NULL, .flags = describe_flags };
 return 0;
}
static int pci_p2pdma_distance(struct pci_dev *p, struct device *d, bool verbose)
{ assert(verbose); distance_calls++; distance_provider = p; distance_client = d; return distance; }
static bool is_swiotlb_force_bounce(struct device *d)
{ assert(d == &nhi.dev); return bounce; }
static bool use_dma_iommu(struct device *d)
{ assert(d == &nhi.dev); return dma_iommu_present; }
static const void *get_dma_ops(struct device *d)
{ assert(d == &nhi.dev); return dma_ops_present ? &ops : NULL; }
static bool capable(int cap) { assert(cap == CAP_SYS_ADMIN); return admin; }
int xdev_ext_peer_file_premap(struct file *f, struct pci_dev *p)
{ assert(f == &authority && p == &nhi); premaps++; return premap_ret; }
static struct pci_dev *pci_dev_get(struct pci_dev *p)
{ assert(p == &nhi); pci_refs++; return p; }
static void pci_dev_put(struct pci_dev *p)
{ if (p) { assert(p == &nhi && pci_refs); pci_refs--; } }
static void reset(void)
{
 struct xdev_ext_mech_stage_uapi u = { .class_id = XDEV_EXT_MECH_CLASS_NET,
                                      .direction = XDEV_EXT_MECH_DIR_TO_DEVICE };
 memset(&rq, 0, sizeof(rq)); memset(&st, 0, sizeof(st)); memset(&nhi, 0, sizeof(nhi));
 session.pool.kind = XDEV_EXT_MECH_POOL_PEER; st.s = &session;
 xdev_ext_mech_stage_caps_default(&u, session.pool.kind, &st.caps);
 describe_requester = distance_provider = NULL; distance_client = NULL;
 describe_calls = distance_calls = premaps = pci_refs = 0;
 distance = 3; describe_ret = premap_ret = 0; owner_known = true;
 describe_flags = XDEV_EXT_PEER_BACKING_MMIO_BAR;
 dma_iommu_present = true; dma_ops_present = bounce = admin = false;
}
'''

MAIN = r'''
int main(void)
{
 unsigned i;
 static const int errors[] = { -ESTALE, -EIO, -ENOMEM };
 reset();
 assert(!xdev_ext_requester_bind(&rq, &st, &nhi, 0) && premaps == 1 && pci_refs == 1);
 assert(st.caps.reachability == XDEV_EXT_CAP_TOPOLOGY_PASSED && st.caps.requester_mapping == XDEV_EXT_CAP_ESTABLISHED);
 assert(distance_provider == &gpu && distance_client == &nhi.dev && describe_requester == &nhi);
 assert(rq.pdev == &nhi && rq.authority == &authority && rq.generation == UINT64_C(0x12345678abcdef01));
 assert(rq.adm.distance == 3 && rq.adm.backing == XDEV_EXT_PEER_BACKING_MMIO_BAR);
 assert(xdev_ext_requester_bind(&rq, &st, &nhi, 0) == -EINVAL && premaps == 1 && pci_refs == 1);
 xdev_ext_requester_unbind(&rq); assert(!rq.pdev && !pci_refs);
 xdev_ext_requester_unbind(&rq); assert(!pci_refs);
 puts("ok 1 - admitted VRAM premaps once for the actual requester and balances its PCI reference");

 reset(); distance = -1;
 assert(xdev_ext_requester_bind(&rq, &st, &nhi, 0) == -EXDEV && !premaps && !pci_refs && !rq.pdev);
 assert(st.caps.refused == XDEV_EXT_PEER_REFUSE_NO_P2P_PATH && st.caps.requester_mapping == XDEV_EXT_CAP_UNKNOWN);
 assert(st.caps.reachability == XDEV_EXT_CAP_TOPOLOGY_FAILED && st.caps.p2p_distance == -1);
 assert(xdev_ext_requester_bind(&rq, &st, &nhi, XDEV_EXT_ADMIT_F_ALLOW_UNVERIFIED) == -EXDEV && !premaps);
 admin = true;
 assert(!xdev_ext_requester_bind(&rq, &st, &nhi, XDEV_EXT_ADMIT_F_ALLOW_UNVERIFIED) && premaps == 1);
 assert(st.caps.reachability == XDEV_EXT_CAP_UNVERIFIED_FORCED && st.caps.refused == XDEV_EXT_PEER_REFUSE_NO_P2P_PATH);
 xdev_ext_requester_unbind(&rq);
 puts("ok 2 - absent topology never maps until the administrator explicitly chooses unverified forcing");

 reset(); describe_ret = -EOPNOTSUPP;
 assert(xdev_ext_requester_bind(&rq, &st, &nhi, 0) == -EXDEV && !premaps && !pci_refs);
 assert(st.caps.refused == (XDEV_EXT_PEER_REFUSE_BACKING | XDEV_EXT_PEER_REFUSE_NO_P2P_PATH));
 assert(!distance_calls && st.caps.backing == 0);
 reset(); owner_known = false;
 assert(xdev_ext_requester_bind(&rq, &st, &nhi, 0) == -EXDEV && !premaps && !distance_calls);
 assert(st.caps.refused & XDEV_EXT_PEER_REFUSE_BACKING);
 puts("ok 3 - missing provider description or owner remains unknown and never maps");

 reset(); describe_flags |= XDEV_EXT_PEER_BACKING_RAW_BUS_ADDR;
 dma_iommu_present = false; dma_ops_present = true;
 assert(xdev_ext_requester_bind(&rq, &st, &nhi, 0) == -EXDEV && !premaps && !pci_refs);
 assert(st.caps.refused == XDEV_EXT_PEER_REFUSE_IOMMU_RAW_ADDR);
 dma_ops_present = false;
 assert(!xdev_ext_requester_bind(&rq, &st, &nhi, 0) && premaps == 1);
 xdev_ext_requester_unbind(&rq);
 reset(); nhi.untrusted = true; bounce = true; admin = true;
 describe_flags |= XDEV_EXT_PEER_BACKING_EXTERNAL;
 assert(xdev_ext_requester_bind(&rq, &st, &nhi, XDEV_EXT_ADMIT_F_ALLOW_UNVERIFIED) == -EXDEV && !premaps);
 assert(st.caps.refused == (XDEV_EXT_PEER_REFUSE_UNTRUSTED | XDEV_EXT_PEER_REFUSE_SWIOTLB_FORCE | XDEV_EXT_PEER_REFUSE_EXTERNAL_OWNER));
 puts("ok 4 - requester translation, trust, bounce and external ownership hard refusals cannot be overridden");

 for (i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
  reset(); describe_ret = errors[i];
  assert(xdev_ext_requester_bind(&rq, &st, &nhi, 0) == errors[i]);
  assert(!distance_calls && !premaps && !pci_refs && !rq.pdev);
  reset(); premap_ret = errors[i];
  assert(xdev_ext_requester_bind(&rq, &st, &nhi, 0) == errors[i] && premaps == 1);
  assert(!pci_refs && !rq.pdev && st.caps.requester_mapping == XDEV_EXT_CAP_UNKNOWN);
 }
 reset(); session.pool.kind = XDEV_EXT_MECH_POOL_IOU_UMEM;
 assert(xdev_ext_requester_bind(&rq, &st, &nhi, 0) == -EINVAL && !describe_calls);
 reset(); assert(xdev_ext_requester_bind(&rq, &st, NULL, 0) == -EINVAL && !describe_calls);
 puts("ok 5 - describe and map errors propagate without a mapped capability or PCI reference");
 return 0;
}
'''

DESCRIBE_SHIM = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
enum dma_data_direction { DMA_BIDIRECTIONAL, DMA_TO_DEVICE, DMA_FROM_DEVICE };
#define XDEV_EXT_PEER_HOST_TEST
#include "include/linux/xdev_ext_peer.h"
struct pci_dev { int id; };
struct mutex { int held; };
struct provider { const struct xdev_ext_peer_provider_ops *ops; };
struct xdev_ext_peer_region {
 struct mutex lock; bool invalid, quarantined; struct provider *provider; void *allocation;
};
static void mutex_lock(struct mutex *m) { assert(!m->held); m->held = 1; }
static void mutex_unlock(struct mutex *m) { assert(m->held); m->held = 0; }
static struct pci_dev owner, requester;
static struct xdev_ext_peer_region region;
static int allocation, calls, provider_ret;
static int provider_describe(void *a, struct pci_dev *p, struct xdev_ext_peer_backing *out)
{
 assert(region.lock.held && a == &allocation && p == &requester); calls++;
 out->owner = &owner; out->flags = 17; return provider_ret;
}
'''
DESCRIBE_MAIN = r'''
int main(void)
{
 struct xdev_ext_peer_provider_ops ops = { .describe = provider_describe };
 struct provider provider = { .ops = &ops };
 struct xdev_ext_peer_backing out;
 region.provider = &provider; region.allocation = &allocation;
 assert(xdev_ext_peer_describe(NULL, &requester, &out) == -EINVAL);
 assert(xdev_ext_peer_describe(&region, NULL, &out) == -EINVAL);
 assert(xdev_ext_peer_describe(&region, &requester, NULL) == -EINVAL);
 assert(!calls && !region.lock.held);
 assert(!xdev_ext_peer_describe(&region, &requester, &out));
 assert(out.owner == &owner && out.flags == 17 && calls == 1 && !region.lock.held);
 provider_ret = -EIO;
 assert(xdev_ext_peer_describe(&region, &requester, &out) == -EIO && calls == 2 && !region.lock.held);
 ops.describe = NULL; out.owner = &owner; out.flags = 99;
 assert(xdev_ext_peer_describe(&region, &requester, &out) == -EOPNOTSUPP);
 assert(!out.owner && !out.flags && calls == 2 && !region.lock.held);
 region.invalid = true; ops.describe = provider_describe;
 assert(xdev_ext_peer_describe(&region, &requester, &out) == -ESTALE && calls == 2 && !region.lock.held);
 region.invalid = false; region.quarantined = true;
 assert(xdev_ext_peer_describe(&region, &requester, &out) == -ESTALE && calls == 2 && !region.lock.held);
 puts("ok 6 - provider describe forwards live allocation and requester under the lock and refuses stale or absent providers");
 return 0;
}
'''

FILE_DESCRIBE_SHIM = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
enum dma_data_direction { DMA_BIDIRECTIONAL, DMA_TO_DEVICE, DMA_FROM_DEVICE };
#define XDEV_EXT_PEER_HOST_TEST
#include "include/linux/xdev_ext_peer.h"
struct file_operations { int unused; };
struct file { const struct file_operations *f_op; void *private_data; };
struct xdev_ext_peer_region { int unused; };
struct pci_dev { int unused; };
struct xdev_ext_peer_fd { struct xdev_ext_peer_region *region; };
struct xdev_ext_peer_authority { struct xdev_ext_peer_fd *parent; };
static const struct file_operations xdev_ext_peer_authority_fops, foreign_fops;
static struct xdev_ext_peer_region region;
static struct pci_dev requester;
static unsigned calls;
static int provider_ret;
int xdev_ext_peer_describe(struct xdev_ext_peer_region *r, struct pci_dev *p, struct xdev_ext_peer_backing *out)
{ assert(r == &region && p == &requester); calls++; out->owner = p; out->flags = 17; return provider_ret; }
'''

FILE_DESCRIBE_MAIN = r'''
int main(void)
{
 struct xdev_ext_peer_fd parent = { .region = &region };
 struct xdev_ext_peer_authority authority = { .parent = &parent };
 struct file file = { .f_op = &xdev_ext_peer_authority_fops, .private_data = &authority };
 struct xdev_ext_peer_backing out = { 0 };
 assert(xdev_ext_peer_file_describe(NULL, &requester, &out) == -EINVAL && !calls);
 file.f_op = &foreign_fops;
 assert(xdev_ext_peer_file_describe(&file, &requester, &out) == -EINVAL && !calls);
 file.f_op = &xdev_ext_peer_authority_fops;
 assert(!xdev_ext_peer_file_describe(&file, &requester, &out) && calls == 1);
 assert(out.owner == &requester && out.flags == 17);
 provider_ret = -ESTALE;
 assert(xdev_ext_peer_file_describe(&file, &requester, &out) == -ESTALE && calls == 2);
 puts("ok 10 - authority-file describe rejects foreign files and forwards the actual region and requester");
 return 0;
}
'''

CAPS_SHIM = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_step.h"
typedef uint32_t u32;
/* The family header is kernel-only in mech.h; use the real compute contract
 * with this plain-data host declaration, without replacing any kind rule. */
struct xdev_ext_family_hooks_hdr { u32 family; };
#include "include/linux/xdev_ext_compfam.h"
#define __user
struct xdev_ext_mech_stage;
struct xdev_ext_mech_class_ops {
 int (*bind)(struct xdev_ext_mech_stage *, const struct xdev_ext_mech_stage_uapi *);
 union { const struct xdev_ext_comp_hooks *comp; } fam;
};
struct xdev_ext_mech_stage { u32 class_id; const struct xdev_ext_mech_class_ops *cls; struct xdev_ext_mech_stage_caps caps;
 bool create_reporting; u32 create_phase, create_valid; };
struct xdev_ext_mech_session { u32 nr_stages; struct xdev_ext_mech_stage st[2]; };
struct io_ring_ctx { int id; };
static struct xdev_ext_mech_session session;
static struct io_ring_ctx ring;
static bool fail_from, fail_to;
static unsigned lookups, to_calls, bind_calls;
static int bind_ret;
static unsigned long copy_from_user(void *d, const void *s, size_t n)
{ if (fail_from) return 1; memcpy(d, s, n); return 0; }
static unsigned long copy_to_user(void *d, const void *s, size_t n)
{ to_calls++; if (fail_to) return 1; memcpy(d, s, n); return 0; }
static const void *memchr_inv(const void *p, int c, size_t n)
{ const unsigned char *b = p; size_t i; for (i = 0; i < n; i++) if (b[i] != (unsigned char)c) return b + i; return NULL; }
static struct xdev_ext_mech_session *xdev_ext_mech_find(struct io_ring_ctx *ctx, uint64_t id)
{ assert(ctx == &ring); lookups++; return id == UINT64_C(0xdeadbeef12345678) ? &session : NULL; }
static int class_bind(struct xdev_ext_mech_stage *st, const struct xdev_ext_mech_stage_uapi *u)
{
 assert(u->class_id == XDEV_EXT_MECH_CLASS_NET);
 assert(st->caps.size == 64 && st->caps.version == 1 && st->caps.family == XDEV_EXT_FAMILY_NETWORK);
 assert(st->caps.export_authority == XDEV_EXT_CAP_ESTABLISHED && st->caps.requester_mapping == XDEV_EXT_CAP_UNKNOWN);
 st->caps.native_queue = XDEV_EXT_CAP_ESTABLISHED; bind_calls++; return bind_ret;
}
static struct xdev_ext_mech_stage_caps query(void)
{
 return (struct xdev_ext_mech_stage_caps){ .size = 64, .version = 1,
  .session_id = UINT64_C(0xdeadbeef12345678), .stage = 1 };
}
'''

CAPS_MAIN = r'''
int main(void)
{
 struct xdev_ext_mech_class_ops ops = { .bind = class_bind };
 struct xdev_ext_mech_stage_uapi u = { .class_id = XDEV_EXT_MECH_CLASS_NET,
  .direction = XDEV_EXT_MECH_DIR_TO_DEVICE };
 struct xdev_ext_mech_stage_caps in, saved;
 unsigned byte;
 session.nr_stages = 2; session.st[1].cls = &ops;
 session.st[1].class_id = u.class_id;
 memset(&session.st[1].caps, 0xa5, sizeof(session.st[1].caps));
 assert(!xdev_ext_mech_class_bind(&session.st[1], &u, XDEV_EXT_MECH_POOL_PEER) && bind_calls == 1);
 assert(session.st[1].caps.native_queue == XDEV_EXT_CAP_ESTABLISHED);
 bind_ret = -EIO;
 assert(xdev_ext_mech_class_bind(&session.st[1], &u, XDEV_EXT_MECH_POOL_PEER) == -EIO && bind_calls == 2);
 puts("ok 7 - every class bind receives initialized capability defaults and its own bind result propagates");

 saved = session.st[1].caps; in = query();
 assert(!xdev_ext_mech_stage_caps_op(&ring, &in));
 assert(in.session_id == UINT64_C(0xdeadbeef12345678) && in.stage == 1);
 assert(in.family == XDEV_EXT_FAMILY_NETWORK && in.native_queue == XDEV_EXT_CAP_ESTABLISHED);
 assert(in.producer_visibility == XDEV_EXT_CAP_NOT_WIRED && in.p2p_distance == -1);
 assert(!memcmp(&saved, &session.st[1].caps, sizeof(saved)));
 puts("ok 8 - stage capability query returns the chosen ring-local CREATE record without changing it");

 in = query(); in.size--; assert(xdev_ext_mech_stage_caps_op(&ring, &in) == -EINVAL);
 in = query(); in.version++; assert(xdev_ext_mech_stage_caps_op(&ring, &in) == -EINVAL);
 for (byte = offsetof(struct xdev_ext_mech_stage_caps, family); byte < sizeof(in); byte++) {
  unsigned before = lookups;
  in = query(); ((unsigned char *)&in)[byte] = 1;
  assert(xdev_ext_mech_stage_caps_op(&ring, &in) == -EINVAL && lookups == before);
 }
 in = query(); in.session_id = 0; assert(xdev_ext_mech_stage_caps_op(&ring, &in) == -ENOENT);
 in = query(); in.stage = 2; assert(xdev_ext_mech_stage_caps_op(&ring, &in) == -EINVAL);
 in = query(); in.stage = UINT32_MAX; assert(xdev_ext_mech_stage_caps_op(&ring, &in) == -EINVAL);
 in = query(); fail_from = true;
 { unsigned before = lookups; assert(xdev_ext_mech_stage_caps_op(&ring, &in) == -EFAULT && lookups == before); }
 fail_from = false; fail_to = true; in = query();
 { unsigned before = to_calls; assert(xdev_ext_mech_stage_caps_op(&ring, &in) == -EFAULT && to_calls == before + 1); }
 puts("ok 9 - capability query rejects output-as-input, invalid identity and user-copy faults");
 return 0;
}
'''


def main():
    bind = exported("io_uring/family/xdev_ext_requester.c", "int xdev_ext_requester_bind(", "xdev_ext_requester_bind")
    unbind = exported("io_uring/family/xdev_ext_requester.c", "void xdev_ext_requester_unbind(", "xdev_ext_requester_unbind")
    describe = exported("io_uring/xdev_ext_peer.c", "int xdev_ext_peer_describe(", "xdev_ext_peer_describe")
    file_describe = exported("io_uring/xdev_ext_peer_fd.c", "int xdev_ext_peer_file_describe(", "xdev_ext_peer_file_describe")
    class_bind = static_function("xdev_ext_mech_class_bind")
    caps_op = static_function("xdev_ext_mech_stage_caps_op")
    if any(item is None for item in (bind, unbind, describe, file_describe, class_bind, caps_op)):
        return 1
    mech = re.sub(r"\s+", "", (KERNEL / "io_uring/xdev_ext_mech.c").read_text())
    assert "ret=xdev_ext_mech_class_bind(st,&clean[i],c->pool_kind);" in mech, "session CREATE does not call the capability wrapper"
    assert "caseXDEV_EXT_MECH_OP_STAGE_CAPS:returnxdev_ext_mech_stage_caps_op(ctx,u64_to_user_ptr(req.arg));" in mech, "stage capability control op is not dispatched"
    execute(SHIM, bind + unbind, MAIN)
    execute(DESCRIBE_SHIM, describe, DESCRIBE_MAIN)
    execute(CAPS_SHIM, class_bind + caps_op, CAPS_MAIN)
    execute(FILE_DESCRIBE_SHIM, file_describe, FILE_DESCRIBE_MAIN)
    return 0


if __name__ == "__main__":
    sys.exit(main())
