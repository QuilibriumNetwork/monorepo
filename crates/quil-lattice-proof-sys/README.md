# Experimental native proof backend

This crate makes the current native reference experiment build from repository
sources, without `/tmp` checkouts, Python, downloads or an external shared
library. Enable `native-backend` explicitly. The default feature set builds no C
code. No wallet or execution crate currently uses this backend.

`SOURCE.json` records the pinned labrados/SIMDe revisions and exact source
snapshot. The labrados snapshot incorporates the staged arithmetic, canonical
reduction, commitment-key growth and defined statement-hash corrections from
the review recipe. The adapter includes the bounded QPF4 encoder/decoder and
separate public-only statement construction. Changes to these copies must be
reconciled with the recipe and source manifest before proof evidence is reused.

Local validation uses Darwin ARM64 with clang, C23, strict floating-point
contraction settings and enabled assertions. ARM64 compilation requires the
crypto extensions. Linux ARM64 native ABI and candidate tests also pass through the Taskfile.
Full Linux proving and x86-64 execution remain untested; the x86 configuration
uses SIMDe's portable path. Build configuration is not evidence of proving
support on those platforms.

The raw ABI is unsafe and uses process-global key state. Callers must serialize
all native contexts using `NATIVE_STATE` for their entire lifetime, including
cleanup. The opt-in `native-proof` adapter in `quil-lattice-ct`
holds this lock and frees contexts on submission errors. Native allocation/assertion failures can abort, private
buffers do not yet have complete erasure guarantees, reference logging remains,
and symbol isolation, sampling/timing/security bounds and production resource
limits require further work. This is not a production-approved verifier.

The root Apache license applies to the integration glue. The vendored labrados
copyright/license notice and LaZer notice are preserved in `vendor/labrados`;
SIMDe's MIT license and per-file notices are preserved in `vendor/simde`.

```sh
task test_lattice_proof_arm64_macos
task test_lattice_proof_arm64_linux
```

The Linux task reuses `Dockerfile.source`'s `rust-base` stage. It exercises the
native ABI, Rust context ownership/row translation and candidate Rust constraints;
it does not yet run full Linux token
proofs. The standard node/client release tasks remain the integration build
entry points once this backend is connected to their token paths.

The explicit full-proof tasks build the Rust driver, generate a fixed public
2-input/2-output fixture proof, and verify it in a separate process:

```sh
task test_lattice_full_proof_arm64_macos DEPTH=1 NATIVE_MIB=16384
task test_lattice_full_proof_arm64_linux DEPTH=1 NATIVE_MIB=16384
```

Supported fixture depths are 1, 8, 16 and 32. These tasks are expensive and
their existence does not establish a passing platform result. `NATIVE_MIB`
limits conservative native allocation accounting, not peak RSS. The macOS
task writes `/tmp/quil-native-task-proof.qpf` by default; `PROOF_PATH` overrides
that benchmark output. Linux retains `/opt/ceremonyclient/native-proof.qpf` in
the resulting test image. These are public test seeds, not wallet keys, and
reported proof lengths exclude transaction framing, memos and authorization.

Full-proof tasks now bind the fixed context `quil-native-task-context-v1`.
The driver accepts an optional final transaction-context string; omitting it
preserves the earlier unbound reference fixtures. This benchmark string is not
a complete transaction encoding or active protocol integration.

The QPF4 envelope binds native-public-statement/v4, whose public coefficients
use the same canonical zero/sparse/dense encoding introduced by QPF2. QPF4
retains QPF3's 18-bit lifting (8-bit fallback) and replaces canonical-residue
carry chains with exact proof-ring equations. Native parameters derive from
that new relation; polynomial payload layout is unchanged. QPF1–QPF3 proofs and their
fixture dumps are retired. The current independent codec is `tools/proof_codec.py`;
historical review artifacts retain their original versions.
