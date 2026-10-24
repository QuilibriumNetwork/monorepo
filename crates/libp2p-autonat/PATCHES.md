# Quilibrium patches

Vendored from `libp2p-autonat` 0.15.0 as published on crates.io (rust-libp2p). The published source, normalized manifest and original manifest are retained. Local changes are marked `QUILIBRIUM:`.

The package is a workspace member, so its unit tests run with the workspace tests. The integration tests in `tests/` need `libp2p-swarm-test`, which the published manifest drops; their targets and the dev-dependencies only they use are removed from `Cargo.toml` (the files are kept for reference), and a `libp2p-identity` dev-dependency with `rand` serves `PeerId::random` in the unit tests.

## Inbound dial-back racing a disconnect

`src/v1/behaviour/as_server.rs` (`resolve_inbound_request`): upstream `.expect`s the sender to be connected, but a dial-back request can arrive on a connection whose `ConnectionClosed` was already handled. The panic stopped the whole swarm task. The missing sender is answered with `DialRefused` instead, and the client retries with another server.

## Dial-back failures

`src/v1/behaviour/as_server.rs` (`dial_back_failure`, `start_dial_back`, `take_failed_dial_back`): upstream answered `DialError` to the client whenever any dial to it failed while its request was pending, including another behaviour's dial and a dial-back this server refused itself. The connection limits deny a connection to a peer that already holds the maximum (two on Quilibrium nodes), which is common between nodes that dial each other, so reachable clients saw most probes fail and AutoNAT held them private. The server now records each request under its dial-back's connection id, ignores failures of other dials, answers `DialRefused` (no change of the client's status) when it denied, aborted or skipped its own dial-back or has no transport for any of the addresses, and `DialError` only when the dial-back reached none of the addresses or another peer. The ongoing requests are a struct instead of a tuple, so the helpers can be tested without a response channel.

`ServerStats` and `Behaviour::take_server_stats` count what the server did (served, failed, refused by reason, failed exchanges) for an hourly operator line of the node.

## Short dial-back address list

`src/v1/behaviour/as_client.rs` (`probe_addresses`): a probe offers the listen addresses first, one per protocol stack after the IP (the server replaces the IP with the one it observes, so the port is what counts), then the external candidates, most recent first, at most 8 addresses, and never more than the server's 1024-byte frame limit (`src/v1/protocol.rs`, `MAX_MESSAGE_LEN`). Upstream sent every candidate ever observed, in hash order, ahead of the listen addresses. Peers behind address translation report many different ports for us; the server keeps the first 16 and dials them one at a time, so a reachable node's probes timed out on closed ports, and once the candidates outgrew the frame limit no server could read the request. Probe failures of that kind leave the NAT status unchanged, so a node that missed its first probes stayed unconfirmed until restart.

`src/v1/behaviour.rs`: the candidate set is insertion-ordered (a repeated candidate moves to the front) and keeps the 16 most recent (upstream: an unbounded hash set that never forgets an address). Two read-only accessors serve operator logging: `last_probe_addresses` (the latest request's list) and `eligible_servers` (the servers the next probe can choose from). Protocol, probe rate and server behaviour are unchanged.

Regression tests: `as_client::tests`, `as_server::test` and `behaviour::tests`.
