# Test code discovery

Search canonical, Git tracked test files from the repository root, without
building a source view or running any selected test:

```bash
python3 tools/test_catalog.py query --module network fifo
python3 tools/test_catalog.py query --module storage nvme --role entry
python3 tools/test_catalog.py query completion --json
python3 tools/test_catalog.py check
```

Queries match all supplied terms, ignoring case, across canonical paths,
known logical paths, family, role and titles. No matches return exit status 1;
invalid paths, metadata or stale snapshots return 2. Success returns 0.
New files appear after `git add`; untracked scratch files are excluded.

The catalog reuses `tools/layout.py` and `source-layout.json`; it does not own a
second path map. Files without an existing mapping show `logical: unknown`.
A title quotes the first description in the file header or the closest tracked
README heading. `title_source` identifies which file supplied it; a README
heading describes the directory. Without either source, the filename is shown
and the purpose remains unknown.

Roles describe how code is organized, not whether it passed:

- `entry`: a Python script with a top-level `__main__` guard, a shell script
  with a shebang, or an explicitly reviewed metadata entry. This does not
  establish a safe command, dependencies, device permissions or environment.
- `fixture`: a fixture directory or clearly named fixture input. Tests of a
  fixture retain their own role. Fixture names take precedence over entry
  detection.
- `documentation` and `build`: Markdown documentation and known build files.
- `unknown`: no conservative rule or reviewed metadata establishes a role.
  In particular, a C file is not assumed to be directly runnable.

Read the selected file, Makefile and local README before invoking it. The
[testing guide](../docs/guides/testing.md) documents canonical runners and
evidence boundaries. This catalog carries no execution status or performance
claim; test results belong in the project's separate result ledger.

For an optional searchable Markdown snapshot:

```bash
python3 tools/test_catalog.py write-index
python3 tools/test_catalog.py check --index tests/TEST_CODE_INDEX.md
```

Regenerate after changing tracked files, headers or metadata. The generated
snapshot is optional; dynamic search remains current without a committed
copy. `write-index` refuses to overwrite tracked source files other than its
standard `tests/TEST_CODE_INDEX.md` output. Output must be a Markdown file
beneath `tests/`; an existing file must carry the generated-index marker.

Use descriptive names for new files: subsystem, mechanism and assertion, such
as `nic_completion_batching_test.py`. Existing short names retain their paths
and consumers; add a precise module docstring or header description to improve
search results. Do not rename files solely to populate the catalog.

`tests/test_catalog/entries.json` accepts a small list of reviewed overrides.
Each record has exactly `canonical_path`, `role`, `title`, and `title_source`.
Both paths must be tracked test files. The title must appear verbatim within
the first 16 KiB of its README source or its extracted source header;
metadata cannot cite itself, and fixture inputs cannot be promoted to entries.
Use these records for reviewed hotspots that automatic detection leaves
unknown. Keep commands, environments and results out of this metadata.

Run the catalog's own Git fixture and CLI checks directly:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 tests/test_catalog/test_catalog.py -v
```

These use tiny temporary repositories beneath `tests/test_catalog/`, clean
them on exit, and require no devices, source view, downloaded dependencies or
kernel build.

## Targeted component cost checks

For the changed data-path interfaces, start with the
[AF_XDP completion cost checks](network/performance/README.md) and
[NVMe lease-retirement cost checks](storage/nvme/performance/README.md).
Both execute actual production rules at documented host boundaries.
Their host CPU/operation counts are distinct from device/kernel performance.
New files use subsystem, operation and purpose in their names; established
runner names keep their existing consumers and gain searchable source titles.
