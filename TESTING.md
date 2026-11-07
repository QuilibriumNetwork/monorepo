# Testing

The workspace is Rust. Native dependencies (GMP, FLINT, MPFR and the EMP
libraries) are required; see the README.md file, or use the project image
built from `docker/Dockerfile.source`.

## Running the tests

CI runs the whole workspace with `cargo-nextest`:

    cargo check --workspace --locked --all-targets
    cargo nextest run --workspace --locked --no-fail-fast --config-file .nextest.toml

A single crate can be run with `-p <crate>`, for example:

    cargo nextest run -p quil-types --config-file .nextest.toml

The `quil-hypergraph` integration tests need `--features test-utils`.
