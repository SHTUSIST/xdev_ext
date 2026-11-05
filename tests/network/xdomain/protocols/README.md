# Two independent XDOMAIN protocol programs

```sh
python3 tests/network/xdomain/protocols/run.py --source-root /path/to/product --output /path/to/new-output
```

The runner builds the actual host composition of
`tests/network/xdomain/early/run.py` (NHI ring, XDOMAIN transport and class,
network family, core pieces), with one change: the program bridge includes three
complete programs under private names, and a per-endpoint table picks the
program attached at each end.

- `examples/network/xdomain_peer.bpf.c`: the reference program. It chooses its
  protocol from the stage's mode fact.
- `examples/network/xdomain_rts_cts.bpf.c`: RTS/CTS. The sender announces a
  group by RTS, the receiver posts its buffers and answers CTS, then the sender
  posts. It declines pairing.
- `examples/network/xdomain_early.bpf.c`: early grant. The two endpoints pair,
  the receiver posts the next group and advertises it by CTS before the sender
  asks, and the sender posts on that grant. It never binds a group from an RTS.

Both new programs register the same struct_ops map name `xdomain_peer_ops`, so a
caller changes protocol by loading the other object file. Both run on a stage
bound with `XDEV_EXT_XDOMAIN_F_EARLY`, which selects the version-2 envelope;
the class does not choose the protocol.

Own cases (`cases.c`) compare every business control message on the link, in
order, with 128-byte golden messages. The test builds each golden field by field
from the wire layout and from protocol rules: a 32-group window starting at
group 1, four 4096-byte elements per 16384-byte group, the batch key as tag and
the cumulative element sequence. Only link incarnations, the session identity
and endpoint bind identities come from the environment, read before the
exchange. The cases also check that every sender post follows a CTS for its
group and every CTS follows the receiver's posts, run mismatched program pairs,
and force refused bindings (an RTS on a paired stage, an early post without a
grant).

`equivalence` compiles the three programs' decision functions together and
draws four million fact records from a fixed-seed generator. The RTS/CTS
program must return the reference program's result and verdict in mode 0 for
every version-1 event, and decline PAIR_DUE and HELLO. The early-grant program
must return the reference result and verdict in mode 1 for every event it can
receive; it refuses a version-1 CTS, and inputs with an announced sender slot
are skipped because only an RTS creates one. Neither program reads the mode
fact, and neither ever selects an action of the other protocol.

`early:<case>` runs each existing early contract case with the early-grant
program at its early endpoints (version-1 endpoints of the mixed cases run the
RTS/CTS program). The existing version-1 stack suite runs with the RTS/CTS
program through `stack_test.py --program rts-cts`, in the stack suite's own
environment. `--case NAME` (repeatable) selects cases.

Compilation or setup failures, signals and timeouts are not semantic RED. This
is deterministic host composition: kernel verifier acceptance, physical DMA,
IRQ concurrency and performance need separate evidence.
