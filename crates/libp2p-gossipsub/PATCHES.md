# Quilibrium patches

Vendored from `libp2p-gossipsub` 0.49.4 as published on crates.io (rust-libp2p). The published source, normalized manifest and original manifest are retained. Local changes are marked `QUILIBRIUM:`; the workspace `Cargo.toml` summarises the earlier ones (per-message copies, caching of unsubscribed topics, IDONTWANT on the custom protocol id, the message cache's byte budget).

## Inbound RPC entry limits

`src/protocol.rs` (`GossipsubCodec::decode`, `scan_rpc`): upstream decodes every entry of an inbound RPC before it validates any. The codec now reads the length-prefixed frame itself and walks its protobuf encoding without allocating, counting entries, before decoding it, so that decoding stays proportional to the frame. An RPC with more than 128 published messages, 1024 subscription changes, 1024 control messages, 10,000 message ids or 1024 peer-exchange records, or one that is not strictly well-formed protobuf, is consumed undecoded. Honest peers send one message, subscription or control message per RPC and at most `max_ihave_length` (5000) ids, so they stay well within the limits. The frame size limit (`max_transmit_size`) is unchanged.

`src/handler.rs`: such an RPC is reported as `HandlerEvent::RpcRejected` and closes the inbound stream, like a decoding error; each new stream counts towards the handler's substream attempts.

`src/behaviour.rs`: the sender gets a behaviour penalty (P7) of 10, which at the default weight scores it below any usual graylist threshold until the penalty decays. `Behaviour::rejected_rpc_stats` counts the dropped RPCs and their bytes, with the latest sender and reason, for the node's operator log (the crate's own logs are capped at error in normal runs).

Regression tests: `protocol::tests` (`rpc_over_an_entry_limit_is_dropped_before_decoding`, `malformed_rpc_is_dropped_before_decoding`, `largest_legitimate_rpcs_are_decoded`) and `behaviour::tests::rejected_rpc_penalises_its_sender`.
