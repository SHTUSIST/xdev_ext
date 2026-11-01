# Independent shared receive acceptance tests

These tests derive from TODO.32, opus_plan §8.3 and the root-accepted shared receive contract. The test author has not read the candidate implementation or its artifacts. Existing baseline session C provides a semantic RED: RX setup/map is absent and an RX mapping error is never reached.

The host suite executes production C against explicit OS boundaries. It covers ring construction/custody, public option/order rejection, borrowed socket identity, dispatcher instruction behavior and shared-manager ownership with real files, flock and fork. Native BPF verification and driver support remain separate root checks.

## Remaining coverage boundaries

The receive-options case checks invalid options, IOU-UMEM rejection and refusal after actual library CREATE state. It does not yet exercise a successful `configure_receive`, duplicate configuration, retained network cleanup integrated with kernel STOP, PEER-pool rejection, or copy-source seed timing after START. The ring case checks no premature seeding at open and all ring release paths, including RX mmap failure. Root must retain these distinctions when deciding final acceptance.

The ownership boundary stores opaque map keys/values and object attributes. It does not interpret owner transactions or recreate the manager's state machine. Hardware rules are literal ethtool structures. The insertion-crash scenario terminates the process immediately after an ntuple insertion side effect, before its returned location reaches production C. Real kernel map schemas, BPF verifier behavior, actual device diagnostics, hostile cross-admin mutation and physical DMA are not proved by this fixture.

## Replay commands

Every case takes an explicit candidate source root and a fresh persistent output directory. The runner snapshots the production native view and the complete fixture before GCC compilation. No Git commit or manifest mutation is needed to run it.

```sh
python3 tests/network/shared_receive/run.py \
  --source-root /path/to/candidate \
  --output /root/xdev_ext/staging/completion-20261101/network-lib-tests/replay-rings \
  --case rings \
  --libbpf-include /root/xdev_ext/staging/wave2-20261022/results/T3/libbpf/include \
  --libbpf-archive /root/xdev_ext/staging/wave2-20261022/results/T3/libbpf/libbpf.a
```

Use separate fresh outputs with `--case rx-map-failure`, `--case receive-options`, `--case dispatcher`, `--case socket-identity --scenario all`, and `--case ownership --scenario all`.

The ownership suite's scenarios can also be selected individually: `basic`, `queue-conflict`, `flow-conflict`, `tuple-conflict`, `foreign-rule`, `changed-rule`, `foreign-link`, `replaced-link`, `corrupt-pin`, `namespaces`, `multiprocess`, `fork-policy`, `insertion-crash`, `recorded-crash`, `changed-crash-rule`.

The runner's exact compiler command appears in `result.json`. It uses GCC with GNU11, `-Wall -Wextra -Werror`, function/data sections and linker garbage collection. Modern libbpf is linked with `-lelf -lz`. It compiles the real session unit for session cases and real shared/steer units from the frozen file map whenever present. No LLVM is used by these host tests.

## Boundary behavior

- Rings: substitute socket, socket options, bind, mmap/munmap, eventfd, close, interface lookup and existing io_uring syscall hooks. All library allocation and lifecycle decisions are real. Ring offsets are distinct literal fixtures.
- Socket identity: substitute socket options and netlink XDP diagnostics. Any pin/control/device/BPF access fails through a visible permission gate. Valid identity reaches that gate; invalid identity must be rejected earlier. No borrowed `getsockname` fallback is accepted.
- Dispatcher: interpret actual builder output at the BPF ISA/helper boundary using synthetic address regions and literal map entries. Reads of uninitialized stack or inaccessible memory fail. Successful interpretation does not establish native verifier acceptance.
- Ownership: canonical `/run` and `/sys` paths are translated under the test output's sandbox. Namespace device/inode and socket cookies are fixtures; no setns occurs. Map and pin data are persistent opaque files, and link lifetime is represented by pin state plus real file descriptor locks. All production queue/global lease file locks and child processes are real. BPF/ethtool/network calls never reach the host kernel.

`result.json` distinguishes compile infrastructure errors from execution assertion failures. `run.log`, per-scenario logs, `compile.log`, `fixtures/` and `production/` preserve replay evidence. A candidate failure requires root's REAL/TEST/AMBIGUOUS triage before assertion changes.

## Integration paths

The new tests are all under `tests/network/shared_receive/`. Root can register this path in the product test manifest and refresh source-layout metadata centrally. The test owner has not changed product manifests, CI, server state or test-results catalog.
