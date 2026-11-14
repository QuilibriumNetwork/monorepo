# Quilibrium patches

Vendored from `libp2p-gossipsub` 0.49.4 as published on crates.io (rust-libp2p). The published source, normalized manifest and original manifest are retained. Local changes are marked `QUILIBRIUM:`; the workspace `Cargo.toml` summarises the earlier ones (per-message copies, caching of unsubscribed topics, IDONTWANT on the custom protocol id, the message cache's byte budget).

## Inbound RPC entry limits

`src/protocol.rs` (`GossipsubCodec::decode`, `scan_rpc`): upstream decodes every entry of an inbound RPC before it validates any. The codec now reads the length-prefixed frame itself and walks its protobuf encoding without allocating, counting entries, before decoding it, so that decoding stays proportional to the frame. An RPC with more than 128 published messages, 1024 subscription changes, 1024 control messages, 10,000 message ids or 1024 peer-exchange records, or one that is not strictly well-formed protobuf, is consumed undecoded. Honest peers send one message, subscription or control message per RPC and at most `max_ihave_length` (5000) ids, so they stay well within the limits. The frame size limit (`max_transmit_size`) is unchanged.

`src/handler.rs`: such an RPC is reported as `HandlerEvent::RpcRejected` and closes the inbound stream, like a decoding error; each new stream counts towards the handler's substream attempts.

`src/behaviour.rs`: the sender gets a behaviour penalty (P7) of 10, which at the default weight scores it below any usual graylist threshold until the penalty decays. `Behaviour::rejected_rpc_stats` counts the dropped RPCs and their bytes, with the latest sender and reason, for the node's operator log (the crate's own logs are capped at error in normal runs).

Regression tests: `protocol::tests` (`rpc_over_an_entry_limit_is_dropped_before_decoding`, `malformed_rpc_is_dropped_before_decoding`, `largest_legitimate_rpcs_are_decoded`) and `behaviour::tests::rejected_rpc_penalises_its_sender`.

## IPv6 peers in the colocation penalty

`src/behaviour.rs` (`get_ip_addr`): upstream counts each connected peer under its exact remote IP for the IP-colocation penalty (P6). One IPv6 host or site typically holds a whole /64, so a single operator could connect any number of peers under distinct addresses without crossing the threshold. An IPv6 address now counts by its /64; IPv4 is unchanged. Regression test: `behaviour::colocation_ip_tests::an_ipv6_peer_counts_by_its_64_and_an_ipv4_peer_by_its_address`.

## Subscriptions after a peer restarts

`src/behaviour.rs` (`on_connection_closed`): upstream sends our subscriptions to a peer only when its first connection opens. A peer killed without a close (a QUIC peer's connection lingers until the idle timeout) and restarted under the same peer id within that window connects as our second connection, so the new process never learned our subscriptions and counted no subscribed peer on our topics. When a connection closes and others to the same peer remain, the behaviour now sends its subscriptions again; the closed connection can no longer take them from the shared send queue. A receiver that already knew them only records them again. Regression tests: `quil-p2p` `blossomsub_behaviour::restart_tests`.

## RPCs for peers that left

`src/behaviour.rs` (`send_message`): an RPC addressed to a peer that is no longer in the connected peer list was logged at `error` once per message (up to 681 lines an hour on one node). It is dropped for that peer alone, logged at `debug` and counted: `Behaviour::unsent_rpc_stats` gives the count and the latest peer, for the node's operator log.

## Message signature key types and repeated verification

`src/protocol.rs` (`GossipsubCodec::verify_signature`): upstream verifies each published entry with whatever key type it carries, and every copy of a message again, as the duplicate check runs in the behaviour after the codec. Only Falcon and Ed25519 keys are now accepted. The key type is read from the encoded key before anything is decoded; an entry with another type (Ed448 verification is slow reference arithmetic) is reported as `ValidationError::RefusedKeyType` without spending the stream's invalid-signature budget. Entries whose signatures verified are remembered (`VerifiedSignatures`: 16,384 digests of the signed bytes, signature and key, shared by the streams of a behaviour), so a copy is not verified again.

`src/behaviour.rs` (`on_connection_handler_event`): an entry refused for its key type releases the promises of its message id and costs its forwarder no penalty, as releases before this check forward such entries.

Regression tests: `protocol::tests` (`reproduces_ed448_signed_gossip_verified`, `refused_key_types_are_reported_without_spending_the_budget`, `verified_entries_are_shared_and_keyed_by_their_key`, `verified_signatures_are_bounded`, `encoded_key_type_reads_the_last_type_field`) and `behaviour::tests::refused_key_types_are_dropped_without_penalty`.

## IDONTWANT for refused copies

`src/behaviour.rs` (`handle_received_message`): upstream sends IDONTWANT for a large message before `message_is_valid`, so a copy the behaviour then refuses (from a blacklisted peer or author, or claiming the node's own origin) made mesh peers withhold the copies that follow. IDONTWANT now goes out only for a copy that passed. Regression test: `behaviour::tests::reproduces_idontwant_for_a_refused_copy`.

## Per-peer state: GRAFT topics, queued bytes, stalled peers

`src/behaviour.rs` (`handle_graft`): upstream records every topic a GRAFT names as a subscription of its sender, past the subscription filter. As upstream fixed it in 0.49.5 (GHSA-g3g5-x568-qvqx), a GRAFT records nothing, and one for a topic its sender has not subscribed to is dropped without a mesh link or a PRUNE; the backoff and score checks before it still apply.

`src/rpc.rs` (`Sender::send_message`): upstream bounds a peer's send queues by message count only, so a peer that stops reading holds thousands of messages of up to the frame size each until it disconnects. Published and forwarded messages queued for one peer are now limited to 64 MiB (`MAX_QUEUED_MESSAGE_BYTES`); a message is always queued when none is.

`src/behaviour.rs` (`heartbeat`): the connections of a peer whose messages failed at every heartbeat for 60 s (`SLOW_PEER_DISCONNECT_AFTER`), or whose priority queue holds more than 10,000 messages (`MAX_PRIORITY_QUEUE_LEN`), are closed; nothing else frees what is queued for it.

Regression tests: `behaviour::tests` (`reproduces_graft_topics_recorded_without_subscription`, `grafts_for_topics_the_peer_did_not_subscribe_to_are_dropped`, `stalled_peer_connections_are_closed`) and `rpc::tests` (`reproduces_unbounded_queued_message_bytes`, `queued_message_bytes_are_released_on_receipt`).

## PRUNE backoffs for topics the node has not joined

`src/behaviour.rs` (`handle_prune`): upstream stores the backoff a PRUNE asks for (up to an hour) for every topic it names, whether or not the node joined the topic, so one peer could fill the backoff storage without limit. A PRUNE for a topic outside the mesh is now ignored, as upstream fixed it in 0.50.1 (#6707, GHSA-vrx6-jcp8-vm7m). `handle_graft`: the PRUNEs that answer an explicit peer's GRAFT, each storing a backoff, now name only the joined topics. Regression tests: `behaviour::tests` (`reproduces_prune_backoff_for_unjoined_topics`, `explicit_peer_grafts_back_off_only_joined_topics`).

## Peer-score state of departed peers

`src/peer_score.rs` (`remove_ip`, `remove_ips_for_peer`, `remove_peer`): upstream kept an empty peer set for every IP (IPv6 /64) no peer uses any more, and retained a departed peer with no topic stats and no penalties for `retain_score`. Both are now dropped, as upstream does since #6710. Regression test: `peer_score::tests::departed_blank_peers_leave_no_score_state`.

## Answers under an older release's message id

`src/config.rs` (`ConfigBuilder::legacy_message_id_fn`), `src/behaviour.rs` (`handle_received_message`, `Behaviour::take_legacy_id_answers`): when a flag day changes the id of some messages, a peer on an older release advertises and answers IWANTs under the old id, so each side's promises to the other break and nothing names the cause. With the hook set, a message that answers our open IWANT to its sender for the old id, where the current id differs, is counted per sender (at most 1024 senders between two takes), for the node's operator log. Promises and scores are unchanged. Regression test: `behaviour::tests::iwant_answers_under_a_legacy_id_are_counted`.
