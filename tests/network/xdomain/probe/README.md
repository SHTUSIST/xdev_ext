# Startup data challenge contracts

The startup bind contract requires a completed control LOGIN to remain
insufficient for ordinary business bind. A bind before startup data validation
must return `-EAGAIN`, publish no endpoint, and stop before requester mapping.

`probe_gate_test.py` executes the existing complete production main, ring,
class, netfam, reference BPF and NHI ring composition. The only new boundary
code counts the existing requester mapping entry and reads raw link facts.
The test never sets `up`, calls a replacement bind, or fabricates a data
completion. Both endpoints and both business directions run independently.

```bash
python3 tests/network/xdomain/probe/probe_gate_test.py \
  --source-root /path/to/canonical/source \
  --keep-build /path/to/new/private/output
```

The runner accepts canonical `source-layout.json` inputs and makes ordinary
private copies at the legacy native include paths required by the existing
stack wrappers. Complete production source bodies are preserved. The upstream
NHI descriptor declaration comes from the repository's pinned fixture. Input
origins, hashes, compilation and runtime output are retained. Output directories
cannot be reused. A later GREEN run needs a different directory.

Exit `2` means setup/compilation/runtime infrastructure failure; it is never a
behavioral RED. Exit `1` means at least one executed requirement assertion failed.
Exit `0` means all four cases passed. No TAP skip is accepted.

`probe_wire_test.py` checks independent frozen READY/DONE/PING/PONG vectors and
codec negatives against the actual production header. An absent header is
blocked and returns `2`. `vectors/` contains complete independently generated
wire bytes with CRC32C check values; encoded production output is compared to
every frozen byte.

`probe_transport_test.py` includes the actual probe TU with the existing complete
main/ring/class/NHI stack. The native boundary extension tracks real coherent
allocations and copies only internal startup scratch at the external link
boundary. The actual NHI descriptors and ring work deliver callbacks. This
runner checks dual RX preposting before READY, 128/4096-byte data completion,
independent own TX retirement, peer DONE, malformed native data, remove and
UNKNOWN accounting, repeated stop and retry exhaustion.

```bash
python3 tests/network/xdomain/probe/probe_wire_test.py \
  --source-root /path/to/canonical/source --keep-build /path/to/new/wire/output
python3 tests/network/xdomain/probe/probe_transport_test.py \
  --source-root /path/to/canonical/source --keep-build /path/to/new/transport/output
```

These are controlled software contracts. No physical DMA, real device, kernel
execution, BPF verifier or performance evidence is produced. The scratch-only
link delivery boundary never reads business PEER payload addresses. Remaining
startup event permutations, allocation/post fault points and generation quota
cases are separate coverage; passing these runners alone does not certify every
case in the accepted design.
