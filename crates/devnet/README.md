# Quilibrium local test environment

A Docker-based development network harness that runs multiple Quilibrium nodes
locally and helps test consensus under controlled network partitions. 

It spins up 4 archive nodes + 1 client node via `docker compose`, fronted by a
proxy that intercepts gossip and gRPC traffic, applies network partitions at
specified consensus views, and reports the run's outcome (frame liveness,
safety, client enrollment) back to the orchestrator. If the test fails,
logs from each node are saved to disk.

## Prerequisites

- Rust toolchain (see `rust-toolchain.toml`)
- Docker (with `docker compose`)

## Quick start

```
# single run with one partition at view 1, stopping at frame 5
cargo run -p devnet -- single --verbose --stopframe=5 \
  --view-partitions='[{"view":1,"partition1":["archive-1","archive-2","archive-3"],"partition2":["archive-4"]}]'

```

Run `cargo run -p devnet -- --help` (and `single --help` / `exhaustive --help`)
for the full flag list.

### The partition schedule

The schedule is keyed on the **simplex consensus view**, and is a point trigger
with an implicit heal: an entry applies when its view is observed, and the first
observed view with *no* entry clears every partition.

A view is not a frame. Views advance on every consensus round, including the
nullified rounds a partition induces — which produce no frame at all. The proxy
reads views off the simplex vote and certificate channels (every `Notarize`,
`Nullify` and `Finalize` is broadcast to all peers) as well as off proposed
frames, so it sees a view as soon as the first vote for it crosses the wire,
rather than waiting for that round to produce a block.

Three consequences worth planning around:

- **A partition that leaves no quorum anywhere freezes the view.** Simplex
  advances a view on a notarization or a nullification *certificate*, and both
  need a quorum. Split 4 archives 2-and-2 and neither side can form one: every
  node re-broadcasts `Nullify` for the same view indefinitely, the view never
  moves, and the schedule never reaches its healing view. Such a run ends at
  `--global-timeout`. Keep a quorum on one side of the split (e.g. 3-and-1) if
  the schedule is meant to heal itself.
- **A stalled view costs ~30s of wall clock** (`consensusLeaderTimeoutSecs`,
  default 30). Budget `--global-timeout` accordingly for a schedule that stalls
  consensus for several views.
- **To hold a partition open, repeat the entry on consecutive views** — a single
  entry lasts exactly one view:

  ```
  --view-partitions='[
    {"view":3,"partition1":["archive-1","archive-2","archive-3"],"partition2":["archive-4"]},
    {"view":4,"partition1":["archive-1","archive-2","archive-3"],"partition2":["archive-4"]},
    {"view":5,"partition1":["archive-1","archive-2","archive-3"],"partition2":["archive-4"]}
  ]'
  ```

The schedule must heal before the stop frame, or the rejoin check can never
observe the isolated archive voting for the last frame. The orchestrator rejects
a schedule that heals too late up front rather than reporting a spurious failure.

## Development

Run `./test.sh` (or `./test.sh -short` to skip the Docker integration run) to test
changes.

## Architecture

Two binaries make up the harness:

- **`devnet`** — the host-side orchestrator: CLI, Docker compose orchestration,
  notification server, and log capture.
- **`devnet-proxy`** (`./proxy`) — the in-container gossip/gRPC proxy that 
  enforces a predefined partition schedule and verifies invariants:
  - All archive nodes reach a predefined stop frame.
  - All archive nodes participate in consensus after the network is healed.
  - The client node can sucessfully join as a prover.

## Common issues

If you get:

```
Error response from daemon: all predefined address pools have been fully subnetted
```

decrease the capacity of each bridge network so Docker can allocate more
networks, by adding to `/etc/docker/daemon.json`:

```json
{
  "default-address-pools" : [
    { "base" : "172.17.0.0/12", "size" : 20 },
    { "base" : "192.168.0.0/16", "size" : 24 }
  ]
}
```

then `sudo systemctl restart docker`. See
[this article](https://straz.to/2021-09-08-docker-address-pools/) for details.
