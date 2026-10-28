# Licenses and source provenance

Licenses apply by component and file. Existing copyright notices and SPDX identifiers are retained.

- Linux-derived files follow the upstream [Linux COPYING notice](LICENSES/Linux-COPYING), the [GPL version 2 text](LICENSES/GPL-2.0-only.txt), and the [syscall exception](LICENSES/Linux-syscall-note.txt) where specified by the file.
- NVIDIA-derived files retain the upstream [NVIDIA COPYING notice](LICENSES/NVIDIA-COPYING), including its MIT terms and MIT/GPLv2 terms for the linked Linux module. Individual file notices take precedence.
- Files with separate SPDX expressions retain those terms; host networking examples include [BSD-2-Clause](LICENSES/BSD-2-Clause.txt) and [LGPL-2.1](LICENSES/LGPL-2.1.txt) alternatives.
- The fixed vLLM method fixture in `tests/compute/tp/framework/fixtures/` retains its upstream contributor notice and [Apache-2.0 license](LICENSES/Apache-2.0.txt). Its source revision is recorded in the fixture.
- New project preparation scripts carry `SPDX-License-Identifier: GPL-2.0-only`.

The upstream repositories, release references and exact source revisions are recorded in [sources.lock.json](third_party/sources.lock.json). The source preparation script combines those public bases with the canonical project files under `src/compute`, `src/storage`, `src/network`, and `src/core`. The prepared trees retain their upstream license files.
