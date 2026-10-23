# Provider code size

`loc_report.py` counts the lines of each device provider class from the files
Git tracks, at `HEAD` unless `--worktree` is given.

```sh
python3 tests/eval/providers/loc_report.py          # table
python3 tests/eval/providers/loc_report.py --json
make -C tests/eval/providers check
```

A class has two kinds of files:

- its own files, counted whole (code, comment and blank lines);
- hook files: upstream files the class modifies. Only the lines that differ
  from the upstream commit pinned in `sources.lock.json` count.

The upstream base is read from the source-preparation cache
`build/upstream/<component>.git`, or from `--upstream-git COMPONENT=GITDIR`.
When that commit is absent, a hook is listed with `added: null` and a `?` in
the table. No estimate replaces the missing count.

`core` is the shared session contract that every provider uses; it is not a
provider. `shared_hooks` are upstream changes not specific to one device. The
catalog in `loc_report.py` is maintained by hand. Tracked kernel or GPU files
that no class names are listed as `unclassified`. A catalog entry that matches
no tracked file is listed as `missing` and makes the report exit 1, so the
catalog cannot silently drift from the tree.
