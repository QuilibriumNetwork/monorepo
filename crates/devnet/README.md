# Quilibrium local test environment

A Docker-based development network harness that runs multiple Quilibrium nodes
locally and helps test consensus under controlled network partitions. 

It spins up 4 archive nodes + 1 client node via `docker compose`, fronted by a
proxy that intercepts gossip and gRPC traffic, applies network partitions at
specified consensus ranks, and reports the run's outcome (frame liveness,
safety, client enrollment) back to the orchestrator. If the test fails,
logs from each node are saved to disk.

## Prerequisites

- Rust toolchain (see `rust-toolchain.toml`)
- Docker (with `docker compose`)

## Quick start

```
# single run with one partition at rank 1, stopping at frame 5
cargo run -p devnet -- single --verbose --stopframe=5 \
  --rank-partitions='[{"rank":1 ,"partition1":["archive-1","archive-2","archive-3"],"partition2":["archive-4"]}]'

```

Run `cargo run -p devnet -- --help` (and `single --help` / `exhaustive --help`)
for the full flag list.

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
