# Redis fragmented-response correctness

Follow the [evaluation policy](../PERFORMANCE_POLICY.md) for baseline changes, comparison eligibility and performance claims.

This independently authored runner retains nine response shapes from the project's earlier Redis scenario specification: GET of 256 KiB, 512 KiB, 1 MiB and 2 MiB; MGET of 16×16 KiB, 32×16 KiB and 64×8 KiB; and LRANGE of 128×4 KiB and 256×4 KiB. Earlier runner source was not copied. Each element has distinct deterministic binary data; the oracle checks every byte, array count and order.

Run the host contracts and real Redis cases with:

```sh
make check
```

Dependencies are Python 3, a real `redis-server` executable on PATH, and `cc` for the harmless shared-library mapping positive control. Linux `/proc/PID/maps` establishes an explicitly requested preload mapping. Redis is separately installed and remains subject to its distribution's own license; no Redis source is bundled. This runner and its tests carry GPL-2.0 SPDX notices.

To save a new correctness result:

```sh
python3 run_redis_fragmented_eval.py --redis-server redis-server \
  --mode correctness --output result.json
```

`--scratch-root DIR` selects an existing parent for a fresh private 0700 directory. The runner starts only its own Redis with port 0, a protected Unix socket and persistence disabled. It never connects to an external server. It terminates/reaps its owned process group and removes its private directory after success, startup failure, timeout, short response, wrong response or interruption. It refuses to overwrite an existing result. Success is published only after complete verification and cleanup.

The bounded RESP2 parser handles binary bulk strings, short reads, empty/nil values, integers and arrays. It rejects invalid lengths, excessive nesting/items/bytes, error responses, truncated messages and extra bytes in a complete-message decode. A final QUIT reply and EOF reject unsolicited trailing replies in the live connection.

Baseline server environments clear inherited `LD_PRELOAD` and `UBR_`/`XDEV_EXT_` variables. `--preload /absolute/path/library.so` runs both baseline and explicit-library arms. The latter succeeds only if the requested file's device/inode is actually present in that owned Redis process's maps; ignored loader errors cannot pass. Mapping proves that the library was loaded. It does not prove an xdev data path was used. A missing executable or unavailable requested preload capability exits 4 with no success output. Runtime or oracle failures return nonzero without creating a success result.

This task reports response correctness only. It produces no request-rate, duration distribution, speedup or device-performance claim. It does not require another paper experiment.
