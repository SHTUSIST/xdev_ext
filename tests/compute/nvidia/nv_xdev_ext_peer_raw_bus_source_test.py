#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin upstream MMIO fallback and execute provider raw-bus/describe slices.

Source assertions signal that an upstream change needs re-auditing; compiled
truth tables check the actual decisions for four supported conftest variants.
These are host software checks and perform no DMA or hardware discovery.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

from nv_xdev_ext_extract import find_function

GPU = Path(__file__).resolve().parents[1]


def function(text, name):
    span = find_function(text, name)
    if span is None:
        raise AssertionError(f"{name} missing")
    return text[span[0]:span[1]]


def compact(text):
    text = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
    return re.sub(r"\s+", "", text)


SHIM = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#define NV_TRUE true
#define NV_FALSE false
#define NV_DMA_REMAP_PEER_MMIO_DISABLE 7
typedef bool NvBool;
struct dma_map_ops { void *map_phys; void *map_resource; };
struct device { const struct dma_map_ops *ops; };
struct pci_dev { struct device dev; };
typedef struct { struct device *dev; } nv_dma_device_t;
static unsigned nv_dma_remap_peer_mmio;
static const struct dma_map_ops *get_dma_ops(struct device *d) { return d->ops; }
struct xdev_ext_peer_backing { struct pci_dev *owner; unsigned flags; };
struct nv_xdev_ext_peer_allocation { struct pci_dev *gpu; bool struct_page, coherent, external; };
#include "kernel-open/nvidia/nv-xdev_ext-peer-backing.h"
'''

MAIN = r'''
int main(void)
{
 unsigned disabled, present, fields, memory, count = 0;
 struct dma_map_ops ops;
 struct pci_dev requester, owner;
 nv_dma_device_t dma = { .dev = &requester.dev };
 for (disabled = 0; disabled < 2; disabled++)
 for (present = 0; present < 2; present++)
 for (fields = 0; fields < 4; fields++) {
  bool mapping;
  ops.map_resource = fields & 1 ? &ops : NULL;
  ops.map_phys = fields & 2 ? &ops : NULL;
  requester.dev.ops = present ? &ops : NULL;
  nv_dma_remap_peer_mmio = disabled ? NV_DMA_REMAP_PEER_MMIO_DISABLE : 0;
  if (disabled) mapping = false;
  else if (!present) {
#ifdef NV_DMA_IS_DIRECT_PRESENT
   mapping = true;
#else
   mapping = false;
#endif
  } else {
#ifdef NV_DMA_MAP_OPS_HAS_MAP_PHYS
   mapping = !!(fields & 2);
#else
   mapping = !!(fields & 1);
#endif
  }
  assert(nv_dma_use_map_resource(&dma) == mapping);
  assert(nv_xdev_ext_peer_raw_bus(&requester.dev) == !mapping);
  for (memory = 0; memory < 8; memory++) {
   struct nv_xdev_ext_peer_allocation allocation = {
    .gpu = &owner, .struct_page = !!(memory & 1),
    .coherent = !!(memory & 2), .external = !!(memory & 4),
   };
   struct xdev_ext_peer_backing out = { 0 };
   unsigned expected = memory & 1 ? 2 : memory & 2 ? 4 : 1;
   if (memory & 4) expected |= 8;
   if (!mapping && !(memory & 3)) expected |= 16;
   assert(!nv_xdev_ext_peer_describe(&allocation, &requester, &out));
   assert(out.owner == &owner && out.flags == expected);
   count++;
  }
 }
 printf("ok - upstream MMIO choice and actual provider raw-bus/describe agree (%u cases)\n", count);
 return 0;
}
'''


def main():
    upstream_path = GPU / "kernel-open/nvidia/nv-dma.c"
    if not upstream_path.exists():
        raise AssertionError("locked upstream nv-dma.c missing; assemble locked NVIDIA sources first")
    upstream = upstream_path.read_text()
    original = function(upstream, "nv_dma_use_map_resource")
    # This exact normalized body is deliberately a source-update alarm.
    expected = '''static NvBool nv_dma_use_map_resource(nv_dma_device_t *dma_dev) {
      const struct dma_map_ops *ops = get_dma_ops(dma_dev->dev);
      if (nv_dma_remap_peer_mmio == NV_DMA_REMAP_PEER_MMIO_DISABLE) { return NV_FALSE; }
      if (ops == NULL) {
      #if defined(NV_DMA_IS_DIRECT_PRESENT)
      return NV_TRUE;
      #else
      return NV_FALSE;
      #endif
      }
      #if defined(NV_DMA_MAP_OPS_HAS_MAP_PHYS)
      return (ops->map_phys != NULL);
      #else
      return (ops->map_resource != NULL);
      #endif
    }'''
    assert compact(original) == compact(expected), "upstream MMIO decision changed; re-audit requester description"
    fallback = compact(upstream)
    assert "if(nv_dma_use_map_resource(dma_dev)){status=nv_dma_map_mmio(dma_dev,page_count,va);}else{" in fallback, "upstream mapping/fallback branch changed"
    assert "NvU64offset=*va-res->start;*va=pci_bus_address(peer_pci_dev,bar_index)+offset;status=NV_OK;" in fallback, "upstream raw bus fallback changed"
    print("ok 1 - locked NVIDIA MMIO source still uses the audited remap/direct/map-ops and PCI bus fallback", flush=True)

    text = (GPU / "kernel-open/nvidia/nv-xdev_ext-peer.c").read_text()
    raw = function(text, "nv_xdev_ext_peer_raw_bus")
    describe = function(text, "nv_xdev_ext_peer_describe")
    # Runtime tests below cover semantics; these also pin the requester used.
    desc = compact(describe)
    assert "nv_xdev_ext_peer_backing_flags(a->struct_page,a->coherent,a->external,nv_xdev_ext_peer_raw_bus(&requester->dev))" in desc, "provider description does not evaluate the actual requester"
    pin = compact(function(text, "nv_xdev_ext_peer_pin"))
    assert "a->gpu=nvl->pci_dev;" in pin, "provider pin does not retain the GPU requester"
    for fact, native in (("struct_page", "mem_has_struct_page"),
                         ("coherent", "coherent"), ("external", "is_external_gpu")):
        assignments = (f"a->{fact}=NV_STATE_PTR(nvl)->{native};",
                       f"a->{fact}=(NV_STATE_PTR(nvl))->{native};")
        assert any(assignment in pin for assignment in assignments), \
            f"provider pin does not retain required backing fact: {fact} from {native}"
    assert ".describe=nv_xdev_ext_peer_describe" in compact(text), "provider describe is not registered"
    with tempfile.TemporaryDirectory(prefix="peer-raw-bus-") as tmp:
        source, binary = Path(tmp) / "t.c", Path(tmp) / "t"
        source.write_text(SHIM + original + raw + describe + MAIN)
        for direct in (False, True):
            for phys in (False, True):
                flags = (["-DNV_DMA_IS_DIRECT_PRESENT"] if direct else []) + (["-DNV_DMA_MAP_OPS_HAS_MAP_PHYS"] if phys else [])
                subprocess.run(shlex.split(os.environ.get("CC", "gcc")) + [
                    "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                    "-fno-sanitize-recover=undefined", "-I" + str(GPU), *flags,
                    str(source), "-o", str(binary)], check=True, timeout=30)
                subprocess.run([str(binary)], check=True, timeout=10)
    print("ok 2 - provider uses requester-specific raw BAR facts across four kernel DMA API variants")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, subprocess.CalledProcessError) as exc:
        print(f"not ok - NVIDIA requester backing source/behavior: {exc}", flush=True)
        sys.exit(1)
