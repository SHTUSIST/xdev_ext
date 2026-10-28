# Source layout and naming

Device families share the same structure: compute, storage and network are
siblings. A GPU is one compute implementation. It does not define a separate
top-level source tree or a different ownership model.

This layout follows the responsibility boundaries and out-of-source build
practice used by [bpftime](https://github.com/eunomia-bpf/bpftime), rather than
copying its runtime architecture or its particular component names.

## Directory ownership

```text
src/
  core/                 shared lifecycle, admission, requester and integration
  compute/              compute-family mechanisms and implementations
    nvidia/             NVIDIA driver integration
    cuda/               CUDA owner and visibility interface
    collectives/        compute/communication operators
  storage/              storage-family mechanisms and native integration
  network/              NIC, socket, XDP and Thunderbolt/XDOMAIN mechanisms
  lib/                  shared application/session interfaces
  cli/                  production command-line tools
  frontend/             compatibility and application frontends
  bpf/                  loadable reference mechanism programs and shared glue
examples/
  compute/
  storage/
  network/
  pipelines/
tests/
  core/
  compute/
  storage/
  network/
  integration/
  benchmarks/
  support/
docs/                   public architecture, APIs, build and testing
tools/                  build, CI, packaging and analysis entrypoints
third_party/            pinned dependency and provenance metadata
build/                  generated views, upstream trees and build outputs
```

Create a subdirectory when it owns real code. Do not add empty provider,
backend or device-pair trees to make every family look identical.

Shared contracts have one owner. Common lifecycle, requester/retention,
admission, io_uring build glue and generic DMA belong to core. CPU transforms,
CE and IAA belong to compute. NVMe/block integration belongs to storage.
Thunderbolt/XDOMAIN belongs to network. A class-specific contract follows its
family; a contract used across families stays in core.

Keep production library/operator code in `src`, runnable demonstrations in
`examples`, and tests or measurement workloads in `tests`. A build script is a
tool; a command-line interface shipped to applications is production source.
Do not store implementation code under a benchmark merely because that
benchmark was its first consumer.

## Stable names

- Use English, lowercase names for new directories, with a short functional
  name. Retain native vendor suffixes when integration requires them.
- Use `compute`, `storage` and `network` for family ownership; put vendor names
  below a family, such as `compute/nvidia`.
- Public source directory names contain no dates, session identifiers or
  temporary labels such as `new`, `old`, `final` or `misc`.
- Use plural `examples`, `tests`, `docs` and `tools`, and `third_party` for
  dependency metadata. Keep the same names in new features and build commands.
- Preserve native ABI names, exported symbols, licenses and required upstream
  relative paths. Moving a file does not authorize renaming its public API.

## Native integration and generated views

`source-layout.json` maps each canonical file to one Linux/NVIDIA native
destination or one logical support path. Dependency versions are pinned in
`third_party/sources.lock.json`. Two source files must not own the same native
destination.

Native Linux/NVIDIA relative hierarchies are assembled under ignored build
outputs. The canonical source tree has no root-level `kernel`, `gpu` or
`scripts` compatibility aliases. Native suffixes inside a family are allowed
when they explain the upstream integration point.

`build/source-view` is a materialized build/test input tree. It may retain
native or historical logical paths so unchanged relative includes and tests
can run. Its files are ordinary copies, not hardlinks or symlinks to canonical
source; mutation tests must never edit the maintained source through a view.
The view is not a Git checkout. Provenance always identifies the canonical
repository and maps logical inputs back to their canonical files.

Use the root build commands and `tools/run.py` or `tools/test.py` to select
canonical entrypoints. Explicit-revision readers use that revision's source
map; they must not fall back to a current file or a similarly named parent
directory.

## Adding or moving code

1. Choose the family or shared responsibility that owns the implementation.
2. Add the canonical/native mapping and retain the dependency's license and
   pinned provenance. Keep shared integration files owned only once.
3. Update affected build, installation, packaging and example entrypoints.
4. For a pure move, preserve source and reuse its existing behavioral evidence.
   Check mapping, paths, includes, provenance and affected build inputs.
5. Run behavior tests when logic changes or a concrete concern remains. A path
   change alone is not a reason to rerun unrelated test suites.

Reusable build caches and original test evidence are separate from source
organization. Do not delete them merely to make a source tree look clean.
