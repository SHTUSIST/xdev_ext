# SPDX-License-Identifier: GPL-2.0
"""Capture exact small test inputs without treating a dirty tree as its HEAD."""
from pathlib import Path
import subprocess


PRODUCTION_INPUTS = (
    "src/core/io_uring/xdev_ext_peer.c",
    "src/core/io_uring/xdev_ext_peer_dmabuf.c",
    "src/core/io_uring/xdev_ext_peer_fd.c",
    "src/core/include/linux/xdev_ext_peer.h",
    "src/core/include/linux/xdev_ext_peer_dmabuf.h",
    "src/core/include/linux/xdev_ext_requester_core.h",
    "src/core/include/uapi/linux/xdev_ext_mech.h",
    "src/core/include/uapi/linux/xdev_ext_binding.h",
)


def capture(root, paths, destination):
    root, destination = Path(root).resolve(), Path(destination).resolve()
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    status = subprocess.check_output(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root, text=True)
    selected_status = subprocess.check_output(
        ["git", "status", "--porcelain=v1", "--untracked-files=all", "--", *paths],
        cwd=root, text=True)
    files, missing = [], []
    for relative in paths:
        source, target = root / relative, destination / relative
        if source.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
            files.append(relative)
        else:
            missing.append(relative)
            # A reused evidence directory must not compile a stale snapshot.
            if target.is_file():
                target.unlink()
    return {"source_root": str(root), "source_revision": revision,
            "dirty": bool(status), "source_inputs_dirty": bool(selected_status),
            "source_state": "uncommitted-working-tree" if selected_status else "commit-inputs",
            "source_git_status": selected_status.splitlines(),
            "compile_source_root": str(destination),
            "source_snapshot_files": files, "source_snapshot_missing": missing}


def capture_fixture(here, destination):
    root = here.parents[2]
    paths = [str(path.relative_to(root)) for path in sorted(here.iterdir())
             if path.is_file() and path.suffix in {".c", ".h", ".in", ".py", ".md"}]
    info = capture(root, paths, destination)
    return destination / here.relative_to(root), info
