# Incremental Coin discovery

`NodeService.ListCoinChanges(domain, cursor, max_coins)` returns public encrypted
Coin outputs in this node's storage-arrival order. A late output from an older
frame therefore remains discoverable. `ConfidentialCoin.frame_number` retains
its original meaning and value; it is not the arrival cursor.

## Wallet protocol

1. Start `ListCoins` and retain its first page's `change_cursor`.
2. Page the same snapshot using its existing snapshot/address cursor. Deduplicate
   outputs by address across the snapshot and the change stream.
3. Follow `ListCoinChanges` from the change cursor, persisting processed outputs
   and `next_cursor` together. An empty output list can still advance the cursor;
   continue immediately while `has_more` is true.
4. On `reset`, start a new snapshot. A reset response carries neither outputs nor
   a replacement cursor. Do not substitute the current tip for a lost cursor.

For a snapshot that may outlast retained change history, follow and store changes
from the first snapshot page while address pagination continues. Discovery does
not decide ownership, consumption or spendability; those checks remain separate.

An empty `ListCoins.change_cursor` means incremental discovery is unavailable.
Older nodes return `UNIMPLEMENTED` for the new RPC. Both cases retain the existing
full-snapshot workflow. The AppShard peer service mirrors the new operation as
`ListShardCoinChanges`; forwarding retains the selected backend across restarts.

## Storage and limits

The journal joins the Coin row's final RocksDB batch, including execution-overlay
publication and sync writes. Discarded private execution produces no durable
events. Snapshot watermarks come from the same retained database snapshots as
their outputs. Multiple worker stores carry separate watermarks in one cursor;
source layout changes require a reset.

Bounded candidates may be omitted only when successful decoding proves there is
no possible Coin type marker. Undecodable rows and potentially malformed Coins
remain candidates so discovery preserves its existing error handling. Candidate
classification adds work at the final write barrier.

Each composite scan retains its source watermarks from the initial snapshots;
later pages never substitute a live tail, including for a source already fully
scanned. Without a Coin root, a bounded probe must establish that no Coin exists
before returning a complete empty snapshot. Finding a Coin, or exhausting the
probe budget, returns a retryable availability error instead of an empty result
with a watermark that could skip existing outputs. These Coin checks do not gate
the separate Escrow enumeration path.

- Retained event accounting is limited to 64 MiB per backing store, approximately
  four thousand ordinary encrypted outputs. Physical usage may exceed that while
  compaction or retained snapshots keep deleted records alive.
- A page examines at most 1,024 records and obeys the existing Coin entry/byte
  budgets: eight entries by default, at most 64. Public encrypted fields are the
  same as `ListCoins`; no wallet key or owner filter reaches the node.
- Cursors are opaque, node-local and limited to 64 KiB. Local vectors support
  at most 256 source ranges; larger snapshots return an empty change cursor.
- The proxy retains at most 256 trusted-origin handles. Evicted routes and
  origins that are no longer trusted require a reset; a known origin's outage
  remains retryable instead of switching to a different node's history.
  Registry initialization also remains retryable; an unloaded directory alone
  does not revoke a persisted route.

Rewind, wipe and snapshot replacement invalidate the local generation. Incomplete
multi-batch replacements fence new bootstrap snapshots. Normal MVCC pruning does
not continually reset discovery, and incoming snapshots exclude local journal
and routing records.
Failed snapshot installation retains its staging data for a safe retry. A missing
retry source does not count as successful completion of an active installation.
Maintenance retries clear only their own verified scope, and repeating completion
of an inactive scope does not reset otherwise valid change cursors.

Restart continuity assumes every writer supports the journal. After an older
binary or external raw database writer bypasses it, operators must explicitly
reset the journal and bootstrap wallets again. This change does not impose a
database-version migration or prevent binary rollback.

Journal records are outside forest roots and canonical application state. They
add local disk/WAL work without changing reward or Mint rules, Coin identities or
original frame numbers. Routing-cache writes use a separate declared keyspace so
wallet queries do not invalidate unrelated execution branches.
