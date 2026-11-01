# Native system-heap REGISTER acceptance

This program tests the production kernel with real DMA heap descriptors and the production REGISTER ioctl. Enabled-mode success establishes whole-export registration, duplicate authority exclusion, fd lifetime, MEMLOCK quota enforcement/recovery and synchronized CPU byte preservation. It does not establish any requester DMA access. Host CLI tests establish only argument/setup classification; root runs the executable in the matching strict kernel and registers that result separately.

The allocation fd has no userspace INFO/query operation in the current UAPI. The program observes REGISTER's returned generation, fd CLOEXEC/liveness, repeat registration, real finite-quota results and `/proc/self/status` VmPin. It does not call internal `xdev_ext_peer_file_info`, CREATE, requester map, SG conversion, lease, native DMA, move/invalidation, quarantine or fence APIs. No new provider or device substitute is installed. No performance is measured.

## Build and run

Build requires GCC and system Linux DMA heap/buf UAPI headers. The Makefile includes the product peer UAPI directly and links only libc. It never links the sibling kernel shim. Keep output in project-owned storage; the default is ignored `build/native-tests/` in this checkout.

```sh
make -C tests/core/peer_dmabuf cli-test
```

On the matching kernel, expose the real system heap and `/dev/xdev_ext_peer`, and provide CAP_SYS_RAWIO. Enable CONFIG_XDEV_EXT_MECH, CONFIG_XDEV_EXT_PEER_DMABUF, CONFIG_DMA_SHARED_BUFFER, CONFIG_DMABUF_HEAPS and CONFIG_DMABUF_HEAPS_SYSTEM. Procfs must be mounted. The process's MEMLOCK hard limit must allow three system pages. Because accounting is UID-wide, the initial one-export finite-budget import requires no preexisting locked_vm charge against this UID. Existing unrelated charges yield SETUP_ERROR rather than weakened assertions. A private correctness guest with no competing registrations is suitable. Root's provenance must bind the kernel/config and tested UAPI to the actual run.

```sh
build/native-tests/dmabuf_import
build/native-tests/dmabuf_import --heap /dev/dma_heap/system --control /dev/xdev_ext_peer
```

To observe a valid REGISTER returning EOPNOTSUPP, use the compatibility option:

```sh
build/native-tests/dmabuf_import --expect-disabled
```

The legacy option name `--expect-disabled` is preserved for compatibility. Its case `register-returned-EOPNOTSUPP` and scope `register-EOPNOTSUPP-observation-only` assert only the actual errno from one valid REGISTER after real heap/control setup. They make no claim about kernel configuration. An enabled importer refusing an unsupported exporter can return the same errno. A config-off conclusion requires root to bind the running kernel to its matching `.config` as external evidence and register that conclusion separately.

Exit 0 with a final `PASS scope=...` means the requested native scope passed. Exit 1 is a behavioral mismatch. Exit 2 is SETUP_ERROR, including missing/incorrect devices, access denial, unavailable VmPin, insufficient hard limit or initial finite-budget setup failure. There is no SKIP result. `--help` returns 0 without PASS. Individual `PASS case=...` lines are partial observations; only the final scope line plus exit 0 signifies complete requested scope.

## Oracle and limits

CPU initialization writes every byte of a three-system-page export with `(offset * 37 + 11) & 255`, wrapped by DMA_BUF_IOCTL_SYNC START/END and mmap/munmap. A separate synchronized read after import checks every byte. No CPU mapping remains during the source-fd closure checks, and no native device work is submitted. This is CPU preservation only.

Enabled mode sets only its soft RLIMIT_MEMLOCK to exactly one export and restores the original limit on exit. A first import must return a live CLOEXEC fd and nonzero generation, with an exact VmPin increase equal to the complete export. Unknown flags, input generation, nonzero offset, zero/unaligned/prefix/oversized lengths and a regular anonymous memfd must fail EINVAL; source fd -1 must fail EBADF.

Repeated import of the original source and its dup must fail EBUSY. Closing the original peer while its dup survives must retain both identity and charge; a distinct second export must fail ENOMEM under the one-export budget. Closing the final peer dup must restore VmPin and permit reimport of the original source alias.

The program then closes every source fd, retaining only the imported peer. A peer dup must remain possible, charge must remain, and the second export must still fail ENOMEM. Closing all peer fds must return VmPin to baseline and permit the second export. These checks establish retained authority/accounting lifetime; fcntl by itself proves no mapped data path. Every peer fd and dup is closed before the final quota and accounting assertions.

A zero MEMLOCK limit must reject import with ENOMEM without a VmPin increment; restoring the one-export budget must permit the same source to register again. This also checks failed import released its live-identity reservation. Immediate post-close observations intentionally verify the no-native-lease destruction path; no sleep/retry hides leaked identity or accounting. This test does not examine process-exit, SCM_RIGHTS, concurrent import, active-request close or UNKNOWN retention.

## Host verification boundary

`native_cli_test.py` uses missing paths, a regular file and `/dev/null` only. It checks help's explicit observation/configuration boundary, invalid arguments, missing device and failed real ALLOC ioctl handling in enabled and EOPNOTSUPP-observation modes. It never opens an existing heap or production control device, and never reports native importer behavior PASS. Native acceptance remains a separate root-run command and evidence entry under `/root/xdev_ext/test-results/`.
