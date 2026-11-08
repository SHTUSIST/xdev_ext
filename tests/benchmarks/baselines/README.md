# RQ1 baseline deployment

One runner per baseline of the evaluation plan's RQ1: E1 (restoring KV cache
from the neighbour host's SSD) and E2 (two-host tensor-parallel inference).
Every runner starts the baseline with its ordinary default configuration.
Read the [performance evaluation policy](../../../docs/reference/performance-policy.md)
before changing any command here.

| Runner | Baseline | Hosts |
|---|---|---|
| `lmcache_mooncake.py` | vLLM + `LMCacheMPConnector`, LMCache MP server with a `mooncake_store` L2 adapter, Mooncake master and SSD offload on host 1, TCP over thunderbolt0 | 1 and 2 |
| `mooncake_store.py` | vLLM `MooncakeStoreConnector`, same Mooncake deployment on host 1 | 1 and 2 |
| `recompute.py` | vLLM with no KV connector (prefix recomputed) | 2 |
| `tp2_nccl.py` | vLLM 0.10.2 TP=2 across the two hosts, NCCL Socket over thunderbolt0, Ray | 1 and 2 |
| `pp2_nccl.py` | vLLM 0.10.2 PP=2, same network and Ray cluster | 1 and 2 |

## Usage

```sh
python3 tests/benchmarks/baselines/lmcache_mooncake.py --dry-run \
  --host1 tb-host1 --host2 tb-host2 --host1-ip 10.77.0.1 --host2-ip 10.77.0.2 \
  --workdir /srv/xdev-baselines --model Qwen/Qwen3-8B \
  --l1-size-gb 8 --host1-ssd-dir /nvme/mooncake_offload
```

`--dry-run` prints every command with the host it runs on, the readiness
probe after each service, the check commands and the version pins. It runs
nothing. Without `--dry-run`, at least one `--phase` is required:

- `install` creates one virtualenv per baseline under `--workdir` and installs
  the pinned versions. The LMCache runner also clones and builds Mooncake and
  LMCache from source at the pinned commits (see Versions). Mooncake's
  `dependencies.sh` installs system packages with `sudo`.
- `up` writes config files, starts each persistent service with `nohup` over `ssh`,
  records its PID and waits until its readiness probe exits 0. Logs go to
  `<workdir>/logs/<service>.log` and are overwritten by the next `up`, so copy
  them into the test record before restarting. Recompute is different: `up`
  prepares the cold helper and request file and starts no persistent server.
- `check` reads the thunderbolt0 `rx_bytes` and `tx_bytes` counters on the
  hosts the baseline uses, sends one completion request of about 1,000 tokens
  (greedy, 16 output tokens), waits 5 seconds and reads the counters again.
  E1 cache arms require `--expected-kv-bytes` for this same smoke request:
  both counters must increase and at least one direction on each host must
  cover those known payload bytes. Unknown size and keepalive-only volume are
  refused. This is a necessary volume check, not proof of the flow's identity;
  the route record therefore still says `qualified: false`. The NCCL runners apply
  `qualify_nccl_route` from `tests/benchmarks/tp/run.py` to the `vllm serve`
  log: NCCL must report `NET/Socket` using thunderbolt0 and no other interface,
  and no NCCL tuning variable may be set.
- `down` sends SIGTERM to the recorded PIDs in reverse start order.

Pass `--state FILE` so `down` can find the PIDs started by `up`. The state
file is written even when a phase fails.

The check is one smoke preflight. Derive the known payload bound from the
actual smoke request's serialized KV blocks, not its word count or a fixed
keepalive allowance. Other traffic can satisfy even a large interface delta,
so per-run flow/path evidence is still required. A successful check does not
qualify later long-running measurements. NCCL's separate transport selection
preflight likewise does not establish transferred KV volume.

## Recompute cold requests

`recompute.py --phase up --phase check --cold-port PORT ...` runs exactly one
unchanged smoke request through a fresh vLLM process. Choose an explicit unused
local port; an existing listener is refused and is never stopped. Each later
cold request must invoke `cold_request.py` again with its request file and
server argv. The helper CLI defaults to dry-run; `--execute` is required to
launch the child. No prefix-cache flag or prompt-prefix modification is used.

The helper owns its Popen child/session, serializes this tool's use of the port
with a project/UID/port flock. Before sending any health or inference bytes it
connects explicitly, finds that connection's reverse ESTABLISHED TCP tuple in
Linux `/proc/net/tcp`, and proves its server-side inode is held by a process
in that anchored child session/group. It sends once on the same connection;
automatic reconnects, redirects and proxies are disabled. A listener snapshot
alone cannot qualify the peer. Missing ownership evidence refuses the request.
Only a health GET precedes the one inference POST. The request
file's bytes are sent unchanged. Every reported `cached_tokens` must be numeric
zero; when the field is absent, the result says the counter was not reported
and preserves the fresh-process evidence separately.

Startup, health readiness and final owned-group cleanup are outside the timer.
The result's `elapsed_ns` measures the complete HTTP response, **not TTFT**.
The HTTP operation includes its connection ownership check; this helper does
not certify model performance or a long-running workload. Startup and health
checks remain outside that interval. Catchable TERM/INT/HUP cancellation in the
CLI runs owned-group cleanup, including cancellation during spawn or cleanup.
The unreaped direct child anchors group signaling. SIGKILL cannot run cleanup;
descendants that deliberately leave the owned session/group are outside this
group-only guarantee. Library callers of `run_request` must arrange their own
signal policy; the helper CLI installs and restores its temporary handlers.
The helper always terminates and waits for its owned group; it never reads a
serialized PID to choose a process to stop. Recompute's `down` phase therefore
has no persistent service to signal. This per-request entry does not certify
requests sent to an external or reused long-running vLLM service, and its
full-response interval cannot stand in for the E1 TTFT measurement.

## What the runners set, and why

No runner sets a vLLM, LMCache, Mooncake or NCCL performance option. Every
value given explicitly falls into one of these groups:

- **Address and interface selection.** Host 1's thunderbolt0 address for the
  Mooncake master and client and the Ray head; `VLLM_HOST_IP` (vLLM uses it
  as the Mooncake requester hostname and for Ray);
  `NCCL_SOCKET_IFNAME='=thunderbolt0'` and `GLOO_SOCKET_IFNAME=thunderbolt0`;
  Ray `--node-ip-address`.
- **Values required without a default.** `lmcache server` refuses to start
  without `--l1-size-gb` and `--eviction-policy` (LMCache v0.5.7
  `lmcache/v1/distributed/config.py:1065`). `--l1-size-gb` is an argument
  because every LMCache arm must use the same value. `LRU` is the value in
  every LMCache example.
- **Values the upstream file reader defaults differently from Mooncake.**
  vLLM 0.33.0's `MooncakeStoreConfig.from_file` defaults `protocol` to
  `rdma`, so the vLLM-side file says `tcp`, which is also Mooncake's default
  (`mooncake-store/include/types.h:261`). The LMCache adapter states `tcp`
  for the same reason.
- **The experiment's topology.** Host 2 contributes no Mooncake memory
  (`global_segment_size` 0, and `standalone-store` mode for vLLM, which
  requires 0), so the only copy of a KV chunk is on host 1. SSD offload is
  enabled with `--enable_offload=true` on the master and on host 1's
  standalone `mooncake_client`, with `MOONCAKE_OFFLOAD_FILE_STORAGE_PATH` set
  to `--host1-ssd-dir`. `metadata_server` is `P2PHANDSHAKE`, as in both the
  Mooncake and the vLLM guides, so no HTTP metadata server runs. TP=2 or PP=2
  with `--distributed-executor-backend ray`: vLLM 0.10.2 documents Ray as the
  runtime multi-node deployments require.
- **Logging.** `NCCL_DEBUG=INFO` and `NCCL_DEBUG_SUBSYS=INIT,NET`, needed by
  the route qualifier.

Left at their defaults, among others: LMCache chunk size (256), host, port
(5555) and HTTP port (8080); the connectors' `lmcache.mp.*` options; Mooncake
master offload thresholds (`--offload_on_evict=false`, so objects are written
to SSD as soon as they are stored); the owner's memory pool (`4 GB`), port and
protocol; LMCache's Mooncake `local_buffer_size` (16 MiB) and vLLM's (4 GiB);
the vLLM port (8000), block size, automatic prefix caching (on), CUDA graphs
and memory utilisation; NCCL algorithm, protocol, channels and buffers.

LMCache's 16MiB Mooncake local buffer and MooncakeStoreConnector's 4GiB local
buffer are different vendor defaults, not matched capacities. Both remain
unchanged; report the asymmetry and any resulting qualification failure.

## Versions

`pins.json` holds the exact versions. They were checked on 2026-11-08.

- vLLM 0.33.0 (commit `4ba787ec9959e566d3b587a796dff07673324da5`) for the
  three E1 runners.
- LMCache v0.5.7 (`236f3eec32a2d330662a1795d90a01a1e0782c49`), built from
  source with `BUILD_MOONCAKE=1`, because the prebuilt wheels do not include
  the `lmcache.lmcache_mooncake` extension that the `mooncake_store` adapter
  needs.
- Mooncake v0.3.14 (`e1ea5d31bb5e46ff2df9f90e7c2fbaf52fcdee8c`): built from
  source on host 2 for the LMCache build; the wheel
  `mooncake-transfer-engine-cuda13==0.3.14` provides `mooncake_master` and
  `mooncake_client` on host 1 and the Python store for vLLM on host 2.
- vLLM 0.10.2 (`01efc7ef781391e744ed08c3292817a773d654e6`) with
  `ray[cgraph]==2.48.0` for E2, because `src/compute/vllm` accepts exactly
  vLLM 0.10.2.

The existing Mooncake restore arm in `tests/benchmarks/kv_restore` stays at
its own fixed commit `d01447808d10af78011e9203d53796a15a032a03`, 35 commits
before v0.3.14.

## Not yet verified on hardware

The command lines follow the pinned sources. They have not run on the
two-host testbed. These points need the first functional run:

- whether the LMCache source build links against the listed Mooncake include
  directories and the shared `libmooncake_store` (`-DBUILD_SHARED_LIBS=ON`);
- whether a requester on host 2 reads chunks that exist only on host 1's SSD,
  through LMCache's adapter and through `MooncakeStoreConnector`;
- whether Mooncake's default 16 MiB `local_buffer_size` on host 2 is large
  enough for one LMCache chunk over TCP;
- whether vLLM 0.33.0 and LMCache v0.5.7 work together on an RTX 5090, and
  whether `torch` installed by vLLM 0.33.0 uses CUDA 13 as the
  `cuda13` Mooncake wheel assumes;
- whether vLLM 0.10.2 runs on the RTX 5090 across two hosts, and whether NCCL
  lines from Ray workers reach the `vllm serve` log.

If a default turns out not to work, record the failure and the replacement
value before changing anything.

## Tests

```sh
python3 -I -m unittest discover -s tests/benchmarks/baselines -p 'test_*.py' -v
```

The tests check the generated commands and config files against the pinned
upstream keys, the absence of tuning options, the start order, the route
check, and that `--dry-run` prints every command and executes nothing.
