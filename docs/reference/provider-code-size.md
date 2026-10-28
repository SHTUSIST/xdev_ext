# Provider code size

`tools/analysis/provider_loc.py` counts the lines of each device provider class from the files
the canonical Git repository tracks, at `HEAD` unless `--worktree` is given.
Explicit revisions use that revision’s source manifest; generated source-view
paths do not supply a separate Git identity.

```sh
python3 tools/analysis/provider_loc.py          # table
python3 tools/analysis/provider_loc.py --json
python3 tools/run.py --cwd tests/integration/analysis/providers make check
```

A class has two kinds of files:

- its own files, counted whole (code, comment and blank lines);
- hook files: upstream files the class modifies. Only the lines that differ
  from the upstream commit pinned in `third_party/sources.lock.json` count.

The upstream base is read from the source-preparation cache
`build/upstream/<component>.git`, or from `--upstream-git COMPONENT=GITDIR`.
When that commit is absent, a hook is listed with `added: null` and a `?` in
the table. No estimate replaces the missing count.

`core` is the shared session contract that every provider uses; it is not a
provider. `shared_hooks` are upstream changes not specific to one device. The
catalog in `tools/analysis/provider_loc.py` is maintained by hand. Tracked kernel or GPU files
that no class names are listed as `unclassified`. A catalog entry that matches
no tracked file is listed as `missing` and makes the report exit 1, so the
catalog cannot silently drift from the tree.
