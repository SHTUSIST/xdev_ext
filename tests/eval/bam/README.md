# BaM baseline: compatibility patch

[BaM](https://github.com/ZaidQureshi/bam) lets GPU threads issue NVMe
commands themselves through a user-space NVMe driver (`libnvm`) and a GPU
software cache. It is a reviewer-requested NVMe<->GPU baseline. This
directory holds only our own edits to it and the means to pin and rebuild it.
**Nothing here builds or runs BaM, and no BaM result exists in this
repository.**

## Contents

- `bam-linux6-gcc13-compat.patch`: the three compatibility edits, against the
  BaM repository root.
  - `module/map.c`: Linux 6.5 removed the `vmas` argument of
    `get_user_pages()`; a `LINUX_VERSION_CODE >= 6.5` branch calls the
    four-argument form.
  - `module/pci.c`: Linux 6.4 removed the owner argument of `class_create()`;
    the call is guarded by `LINUX_VERSION_CODE`, and `<linux/version.h>` is
    included for that guard.
  - `include/freestanding/libcxx/include/type_traits`: GCC 13 treats
    `__is_convertible` as a built-in trait name, so the bundled libc++ helper
    template is renamed `__libcpp_is_convertible` (14 lines, no other change).
- `upstream.lock`: the upstream URL and, per patched file, the git blob id
  before and after the patch.
- `find_upstream_commit.sh`: lists the commits of a BaM clone whose three
  files are exactly the pre-patch blobs and checks that the patch applies on
  the newest one. It only reads the clone.
- `test_patch.py`: host checks of the patch shape, the lock file and the
  finder (on a small synthetic git history).

## Provenance and pin status

The edited files come from the archived BaM copy
`archive/conduit-legacy/baselines/ubr_eval_baselines/bam/bam/` (outer private
tree), sha256
`166ef9977517a0e78041bb770fffd6e966ac2491784c1deac80e596d41063bcb` (`module/map.c`),
`fcf8289424c7437d3cee47b6ac6bc9953b0aab8930d132dca52b8ba46e14af4c` (`module/pci.c`) and
`2df254bb4f9922c20c13abf87e705a193130257c5eec38f3cf2208e4f42dd47b` (`type_traits`),
the post-patch blobs of `upstream.lock`; identical copies are in
`archive/eval-legacy/remote_patch_work/bam/`. That copy was cloned on
2026-03-30 without its `.git` directory, so **the upstream commit was not
recorded**. Only these three files have a modification time later than the
checkout time of the other 7206 files.

The pre-patch files were reconstructed by undoing the edits. Compiler
diagnostics captured when the edits were made quote the original text of
every changed line at the same line numbers (type_traits 1461–1483, map.c
151, pci.c 331, and pci.c without `<linux/version.h>`). The reconstruction is
an inference until `find_upstream_commit.sh` finds a matching upstream
commit; then record that commit as `commit` in `upstream.lock`.

## Rebuilding (on a suitable GPU/NVMe host only)

```sh
git clone https://github.com/ZaidQureshi/bam && cd bam
/path/to/tests/eval/bam/find_upstream_commit.sh .   # prints "pin <commit>"
git checkout <commit> && git submodule update --init --recursive
git apply /path/to/tests/eval/bam/bam-linux6-gcc13-compat.patch
mkdir -p build && cd build && cmake .. && make libnvm && make benchmarks
cd module && make
```

BaM's own requirements apply: a Volta-or-newer datacenter GPU whose memory is
exposed for PCIe peer-to-peer access, Above 4G Decoding, IOMMU and ACS
disabled, NVIDIA driver kernel symbols, and an NVMe SSD **unbound from the
Linux nvme driver** (`make load` binds `libnvm` to it; its data can be
overwritten). The patch changes only compilation against newer kernels and
GCC; it does not change these requirements.

## Checks

```sh
make -C tests/eval/bam check
```
