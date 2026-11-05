#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Mutants for the undescribed-exporter import (prototype for ASK.70).

Each mutant changes one production rule in a minimal git copy of the inputs
the two runners compile (provenance.PRODUCTION_INPUTS), then runs the real
importer_run.py and run.py against it. A mutant is killed only by a
behavioral FAIL (exit 1) with no SETUP_ERROR; any survivor is a test gap and
makes this script exit 1. Writes mutants.json under --output.
  python3 -I tests/core/peer_dmabuf/undescribed_mutants.py --source-root ROOT --output DIR
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from provenance import PRODUCTION_INPUTS  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument("--source-root", type=Path, default=HERE.parents[2])
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
WT = args.source_root.resolve(); OUT = args.output.resolve()
OUT.mkdir(parents=True, exist_ok=True)
FILES = list(PRODUCTION_INPUTS)
D = "src/core/io_uring/xdev_ext_peer_dmabuf.c"; A = "src/core/include/linux/xdev_ext_requester_core.h"
MUTANTS = [
 ("M1-no-unbounced-certifier", D, "!dma_sgtable_is_unbounced(&peer->dev, m->sgt)", "0"),
 ("M2-undescribed-claims-host-ram", D, ".flags = XDEV_EXT_PEER_BACKING_UNDESCRIBED }",
  ".flags = XDEV_EXT_PEER_BACKING_HOST_SYSTEM | XDEV_EXT_PEER_BACKING_STRUCT_PAGE }"),
 ("M3-undescribed-admits-untrusted", D, "attach. */\n  if (peer->untrusted || is_swiotlb_force_bounce(&peer->dev)) return -EXDEV;",
  "attach. */\n  if (is_swiotlb_force_bounce(&peer->dev)) return -EXDEV;"),
 ("M3b-undescribed-admits-forced-bounce", D, "attach. */\n  if (peer->untrusted || is_swiotlb_force_bounce(&peer->dev)) return -EXDEV;",
  "attach. */\n  if (peer->untrusted) return -EXDEV;"),
 ("M4-undescribed-admits-noncoherent", D, "  if (!dev_is_dma_coherent(&peer->dev)) return -EOPNOTSUPP;\n  *out = (struct xdev_ext_peer_backing){ .flags = XDEV_EXT_PEER_BACKING_UNDESCRIBED };",
  "  *out = (struct xdev_ext_peer_backing){ .flags = XDEV_EXT_PEER_BACKING_UNDESCRIBED };"),
 ("M5-undescribed-skips-need-sync", D, "(XDEV_EXT_PEER_BACKING_HOST_SYSTEM |\n                      XDEV_EXT_PEER_BACKING_UNDESCRIBED))\n  for_each",
  "(XDEV_EXT_PEER_BACKING_HOST_SYSTEM))\n  for_each"),
 ("M6-generic-without-opt-in", D, "if (!described && (flags & XDEV_EXT_PEER_DMABUF_IMPORT_UNDESCRIBED)) {", "if (!described) {"),
 ("M7-unknown-import-flags-accepted", D, " if (flags & ~XDEV_EXT_PEER_DMABUF_IMPORT_UNDESCRIBED) return -EINVAL;\n", ""),
 ("M8-dying-descriptor-falls-back", D, "if (!described && (flags & XDEV_EXT_PEER_DMABUF_IMPORT_UNDESCRIBED)) {",
  "if ((!described || ret == -ENODEV) && (flags & XDEV_EXT_PEER_DMABUF_IMPORT_UNDESCRIBED)) {"),
 ("M9-admission-undescribed-not-exact", A, "bool undescribed = f->backing == XDEV_EXT_PEER_BACKING_UNDESCRIBED;",
  "bool undescribed = f->backing & XDEV_EXT_PEER_BACKING_UNDESCRIBED;"),
 ("M10-admission-undescribed-topology-claim", A, "if ((f->backing & XDEV_EXT_PEER_BACKING_HOST_SYSTEM) || undescribed) {",
  "if (f->backing & XDEV_EXT_PEER_BACKING_HOST_SYSTEM) {"),
 ("M11-admission-undescribed-needs-topology", A, "!(f->backing & XDEV_EXT_PEER_BACKING_HOST_SYSTEM) && !undescribed &&",
  "!(f->backing & XDEV_EXT_PEER_BACKING_HOST_SYSTEM) &&"),
 ("M12-move-notify-ignored-for-undescribed", D, " atomic_set(&a->stale, 1);\n}\nstatic const struct dma_buf_attach_ops",
  " if (a->descriptor) atomic_set(&a->stale, 1);\n}\nstatic const struct dma_buf_attach_ops"),
 ("M13-undescribed-skips-pin", D, " ret = dma_buf_pin(m->attachment);\n if (ret) goto unlock;\n pinned = true;",
  " ret = 0;\n if (a->descriptor) { ret = dma_buf_pin(m->attachment); pinned = !ret; }\n if (ret) goto unlock;"),
]
results = []
for name, rel, old, new in MUTANTS:
    root = OUT / name
    if root.exists(): shutil.rmtree(root)
    for f in FILES:
        (root / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(WT / f, root / f)
    text = (root / rel).read_text()
    assert text.count(old) == 1, (name, "pattern count", text.count(old))
    (root / rel).write_text(text.replace(old, new))
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "-c", "user.name=m", "-c", "user.email=m@m", "commit", "-qm", name], cwd=root, check=True)
    verdicts = {}
    for runner, tag in (("importer_run.py", "importer"), ("run.py", "admission")):
        out = OUT / (name + "-" + tag)
        r = subprocess.run([sys.executable, "-I", str(HERE / runner),
                            "--source-root", str(root), "--output", str(out)],
                           capture_output=True, text=True, timeout=900)
        rec = json.loads((out / "receipt.json").read_text())
        failing = [c["case"] for c in rec.get("cases", []) if c["exit"]]
        verdicts[tag] = {"exit": r.returncode, "verdict": rec.get("verdict"), "failing": failing}
        if tag == "admission":
            verdicts[tag]["not_ok"] = [l for l in (out / "output.log").read_text().splitlines() if l.startswith("not ok")]
    killed = any(v["exit"] == 1 for v in verdicts.values()) and all(v["exit"] in (0, 1) for v in verdicts.values())
    results.append({"mutant": name, "killed": killed, **verdicts})
    print(name, "KILLED" if killed else "SURVIVED", json.dumps(verdicts))
    shutil.rmtree(root)
(OUT / "mutants.json").write_text(json.dumps(results, indent=2) + "\n")
killed = sum(r["killed"] for r in results)
print("killed", killed, "of", len(results))
raise SystemExit(0 if killed == len(results) else 1)
