# Frame / message decoder fuzzing

cargo-fuzz (libFuzzer) harness for the **untrusted-input decoders**. These parse
attacker-controlled bytes *before* authentication:

- `decode_global_frame` — the gossip `GLOBAL_FRAME` entry: header
  (`commit_count`/`aux_count`/`req_count`) + every bundle. Runs on any mesh
  peer's bytes before the committee-cert / VDF gates. **Where finding F9 lived.**
- `decode_message_bundle`, `canonical_message_bundle`, `canonical_message_request`
  — the message-submission decode path (runs before signature checks).
- `decode_execution_dag`, `decode_timeout_certificate`, `decode_prover_join` —
  inner-op decoders whose count fields were allocation-bomb-hardened in the F9
  sweep.

The bug classes these catch: panics (slice OOB, `unwrap`), integer
overflow/underflow (debug-assertions + overflow-checks are ON in the fuzz
profile), and **allocation bombs** (a huge attacker count → `Vec::with_capacity`
→ OOM, caught by libFuzzer's `-rss_limit_mb`).

## Prerequisites
- Rust nightly (`rustup toolchain install nightly`)
- `cargo install cargo-fuzz`
- `FLINT_DIR` set (the crypto deps link FLINT/GMP)

## Run
From `crates/quil-engine`. Use the **default (address) sanitizer** — on macOS it
brings the compiler-rt coverage runtime and has no LeakSanitizer, so the external
FLINT/GMP C libs cause no leak false-positives. (Do NOT use `--sanitizer none` on
macOS: it emits SanitizerCoverage instrumentation without linking a runtime that
defines the `__sanitizer_cov_*` symbols, so some deps fail to link.)

```sh
# List targets
cargo +nightly fuzz list

# Run one (Ctrl-C to stop). The dictionary plants valid type prefixes so the
# fuzzer doesn't waste effort brute-forcing 4-byte magic values.
FLINT_DIR=/Users/caheart/src/flint \
  cargo +nightly fuzz run decode_global_frame -- \
  -dict=fuzz/canonical_types.dict -rss_limit_mb=2048

# Time-box a target (e.g. CI: 300s) and keep the corpus:
FLINT_DIR=/Users/caheart/src/flint \
  cargo +nightly fuzz run decode_global_frame -- \
  -dict=fuzz/canonical_types.dict -max_total_time=300
```

A crash writes `fuzz/artifacts/<target>/crash-<hash>`; reproduce with:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
```

## Seed corpus (real frames from the explorer)

`fuzz/seeds/` holds **real** frames/bundles (committed, unlike the gitignored
working `corpus/`). They were produced from the public explorer API — this
lifts initial coverage massively (seeded `decode_global_frame` INITs at
~cov 536 vs the unseeded run's *final* cov 333).

- `seeds/decode_global_frame/` — canonical `GlobalFrame`s (recent frames carry
  real request bundles up to ~35; plus a few historical/empty frames).
- `seeds/decode_message_bundle/` — real request-bundle canonical bytes. The
  `canonical_message_bundle` target takes the **same** format — point it at this
  same dir (no separate copy is committed).

One-time: copy the committed seeds into the (gitignored) working corpus, then
run normally — the fuzzer auto-uses `fuzz/corpus/<target>` and writes its own
discoveries there, leaving `fuzz/seeds/` pristine:

```sh
mkdir -p fuzz/corpus/decode_global_frame
cp fuzz/seeds/decode_global_frame/* fuzz/corpus/decode_global_frame/
FLINT_DIR=/Users/caheart/src/flint \
  cargo +nightly fuzz run decode_global_frame -- \
  -dict=fuzz/canonical_types.dict -rss_limit_mb=2048

# the two bundle targets share the SAME bundle seed dir:
mkdir -p fuzz/corpus/decode_message_bundle fuzz/corpus/canonical_message_bundle
cp fuzz/seeds/decode_message_bundle/* fuzz/corpus/decode_message_bundle/
cp fuzz/seeds/decode_message_bundle/* fuzz/corpus/canonical_message_bundle/
```

**Regenerate the seeds** (refetch live frames + reconvert) any time:

```sh
FLINT_DIR=/Users/caheart/src/flint fuzz/fetch_seed_frames.sh
```

It fetches protojson from `$EXPLORER_API` (default
`https://explorer-api.quilibrium.com`) and runs
`cargo run -p quil-engine --example frames_to_corpus` to transcode
protojson → prost (`protojson::from_protojson`) → canonical
(`encode_global_frame`), round-trip-checking that `decode_global_frame` accepts
each seed before writing it.

## Notes
- The default address sanitizer + our debug-assertions/overflow-checks +
  RSS-limit OOM detection covers the decoder bug classes: bounds-check panics,
  integer overflow/underflow, and allocation bombs.
- This is a **detached workspace** (`[workspace]` in `fuzz/Cargo.toml`) that
  mirrors the root `[patch.crates-io]`; it never affects the main build.
