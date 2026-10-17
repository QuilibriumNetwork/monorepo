# Quilibrium patches

Vendored from `commonware-consensus` 2026.7.0, published from Commonware commit `5950bf7179bb0650a57ed58b9e0478822944b335` (`consensus/`). The published source, normalized manifest and original manifest are retained; the upstream root license files accompany them.

The package is excluded from default workspace membership so its upstream development dependencies do not affect normal Quilibrium builds. Run its unit tests explicitly with its manifest and the upstream `mocks` feature:

```sh
cargo nextest run --manifest-path crates/commonware-consensus/Cargo.toml --features mocks --lib
```

## Lazy vote buffers

`src/simplex/types.rs` defers each `AttributableMap` allocation until its first in-bounds insertion. `src/simplex/actors/batcher/verifier.rs` defers each vote vector until its first add, reserving the original quorum capacity then and when verification first accumulates peer votes. Upstream APIs, signer ordering, duplicate/conflict evidence, certificates and unfinalized history retention are preserved. No wire or pruning changes. Local changes and regression tests are marked `QUILIBRIUM:`.

These changes reduce unused vote-phase capacity when views advance without finalization; they do not remove retained views or resolve the cause of stalled finalization. Related Quilibrium issue: #677.
