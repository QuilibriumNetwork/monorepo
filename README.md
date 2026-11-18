# Quilibrium - 2.1 - Bloom

## Quick Start

Running production nodes from source is no longer recommended given build
complexity. Please refer to our release information to obtain the latest
version.

## Running From Source

Ensure you have all required dependencies.

### Ubuntu Linux

`docker/Dockerfile.source` is the reference for these dependencies: its
`base` stage lists the Ubuntu packages, and its `gmp-builder`,
`flint-builder`, `emp-builder` and `rust-base` stages build the native
libraries and install the Rust toolchain. Run the same steps on the host,
or build inside that image.

### macOS

Because Mac varies in terms of dependency management, we recommend
installing Xcode for build toolchain, then use homebrew to install openssl.
Other dependencies via homebrew are the dynamically linked version of the
libraries, so we recommend manually fetching the required packages:

    curl https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz > /tmp/gmp.tar.xz
    pushd /tmp/
    tar xvf gmp.tar.xz
    pushd gmp-6.3.0
    ./configure
    make
    make check
    sudo make install
    popd
    git clone https://github.com/flintlib/flint.git
    pushd flint
    git checkout flint-3.0
    ./bootstrap.sh
    ./configure \
        --prefix=/usr/local \
        --with-gmp=/usr/local \
        --with-mpfr=/usr/local \
        --enable-static \
        --disable-shared \
        CFLAGS="-O3"
    make
    sudo make install
    popd
    popd

From there, you can trigger generation of all dependencies to build the node
with:

    task build_node_arm64_macos

## gRPC Support

If you want to enable gRPC, add the following entry to your config.yml:

    listenGrpcMultiaddr: <multiaddr> 

Please note: this interface, while read-only, is unauthenticated and not rate-
limited. It is recommended that you only enable if you are properly controlling
access via firewall or only query via localhost.

## Prometheus Metrics

Quilibrium nodes expose comprehensive Prometheus metrics for monitoring and observability. The metrics are organized across several subsystems:

### Disk Monitoring (`disk_monitor` namespace)
Tracks disk usage and space metrics for the node's data directory.

- `disk_monitor_usage_percentage` - Current disk usage percentage
- `disk_monitor_total_bytes` - Total disk space in bytes
- `disk_monitor_used_bytes` - Used disk space in bytes
- `disk_monitor_free_bytes` - Free disk space in bytes

### P2P Networking (`blossomsub` namespace)
Monitors the BlossomSub peer-to-peer protocol performance.

- `blossomsub_*_total` - Various operation counters (add_peer, remove_peer, join, leave, graft, prune, etc.)
- `blossomsub_*_messages` - Message count histograms for IHave, IWant, IDontWant messages

### Consensus Time Reel (`quilibrium.time_reel` subsystem)
Tracks consensus timing, fork choice, and blockchain tree operations.

- `frames_processed_total` - Total frames processed (by type and status)
- `equivocations_detected_total` - Equivocation detection counter
- `head_changes_total` - Blockchain head changes (advances vs reorganizations)
- `reorganization_depth` - Depth histogram of blockchain reorganizations
- `tree_depth` / `tree_node_count` - Current tree structure metrics
- `fork_choice_evaluations_total` - Fork choice algorithm executions

### Dynamic Fees (`quilibrium.dynamic_fees` subsystem)
Monitors fee voting and calculation based on sliding window averages.

- `fee_votes_added_total` / `fee_votes_dropped_total` - Fee vote tracking
- `current_fee_multiplier` - Current calculated fee multiplier
- `sliding_window_size` - Current number of votes in window
- `fee_vote_distribution` - Distribution histogram of fee votes

### Event Distribution (`quilibrium.event_distributor` subsystem)
Tracks internal event processing and distribution.

- `events_processed_total` - Events processed by type
- `subscribers_count` - Current active subscribers
- `broadcasts_total` - Event broadcast counter
- `uptime_seconds` - Distributor uptime

### Hypergraph State (`quilibrium.hypergraph` subsystem)
The most comprehensive metrics tracking the CRDT hypergraph operations.

#### Core Operations
- `add_vertex_total` / `remove_vertex_total` - Vertex operations
- `add_hyperedge_total` / `remove_hyperedge_total` - Hyperedge operations
- `*_duration_seconds` - Operation timing histograms

#### Lookups and Queries
- `lookup_vertex_total` / `lookup_hyperedge_total` - Lookup counters
- `get_vertex_total` / `get_hyperedge_total` - Get operation counters

#### Transactions
- `transaction_total` - Transaction counters by status
- `commit_total` / `commit_duration_seconds` - Commit metrics

#### Proofs
- `traversal_proof_create_total` / `traversal_proof_verify_total` - Proof operations
- `traversal_proof_duration_seconds` - Proof timing

### Execution Intrinsics (`quilibrium.intrinsics` subsystem)
Monitors the execution engine's intrinsic operations.

- `materialize_total` / `materialize_duration_seconds` - State materialization
- `invoke_step_total` / `invoke_step_errors_total` - Step execution
- `commit_total` / `commit_errors_total` - State commits
- `state_size_bytes` - Current state size by intrinsic type

### gRPC Metrics
Standard gRPC server and client metrics are automatically registered, including request duration, message sizes, and in-flight requests.

### App Consensus Engine (`quilibrium.app_consensus` subsystem)
Monitors shard-specific consensus operations for application shards.

- `frames_processed_total` - Total frames processed (by app_address and status)
- `frame_processing_duration_seconds` - Frame processing time
- `frame_validation_total` - Frame validation results
- `frame_proving_total` / `frame_proving_duration_seconds` - Frame proving metrics
- `frame_publishing_total` / `frame_publishing_duration_seconds` - Frame publishing metrics
- `transactions_collected_total` - Transactions collected for frames
- `pending_messages_count` - Current pending message count
- `executors_registered` - Current number of registered executors
- `engine_state` - Current engine state (0=stopped through 7=stopping)
- `current_difficulty` - Current mining difficulty
- `current_frame_number` - Current frame number being processed
- `time_since_last_proven_frame_seconds` - Time elapsed since last proven frame

### Global Consensus Engine (`quilibrium.global_consensus` subsystem)
Monitors global consensus operations across all shards.

- `frames_processed_total` - Total global frames processed (by status)
- `frame_processing_duration_seconds` - Global frame processing time
- `frame_validation_total` - Global frame validation results
- `frame_proving_total` / `frame_proving_duration_seconds` - Global frame proving metrics
- `frame_publishing_total` / `frame_publishing_duration_seconds` - Global frame publishing metrics
- `shard_commitments_collected` - Number of shard commitments collected
- `shard_commitment_collection_duration_seconds` - Time to collect shard commitments
- `executors_registered` - Current number of registered shard executors
- `engine_state` - Current engine state (0=stopped through 7=stopping)
- `current_difficulty` - Current global consensus difficulty
- `current_frame_number` - Current global frame number
- `time_since_last_proven_frame_seconds` - Time elapsed since last proven global frame
- `global_coordination_total` / `global_coordination_duration_seconds` - Global coordination metrics
- `state_summaries_aggregated` - Number of shard state summaries aggregated

## Experimental storage startup profiles

The persistent-storage readiness harness can rehearse eleven-, three- and
two-layer profiles against authenticated mainnet snapshots. These are local
experiments: the harness submits no capacity, registration or reward messages.
The default is eleven layers. The graph degrees remain 6/8 and certificates
retain 64 challenges in every profile.

With an optimized Rust node binary and a new scratch directory per run:

```sh
./target/devnet/quil-node --benchmark-storage /scratch/storage-three \
  --benchmark-storage-seats 9 --benchmark-storage-layers 3 \
  --benchmark-storage-regeneration-probe
./target/devnet/quil-node --benchmark-storage /scratch/storage-two \
  --benchmark-storage-seats 9 --benchmark-storage-layers 2 \
  --benchmark-storage-regeneration-probe
```

CPU concurrency follows the process's cores minus one, bounded by shared RAM
and disk admission. `--benchmark-storage-epoch EPOCH` selects a retained,
completed snapshot epoch explicitly; all checkpoint and snapshot-root checks
still apply. Reduced frame workloads and debug binaries cannot qualify a node.

Initial local setup has a hard **7,200-second** deadline starting before input
download, ending only when the whole allocation has certified capacity and its
first registration has been generated and verified. The monitor also cancels
input downloads at the deadline. `initial-setup.json` records that milestone;
later replay rounds and settlement measurements can continue afterward.
`assessment.cold_budget_seconds` is capped at 7,200 seconds. The final assessment
also reserves GLOBAL inclusion time and the configured headroom multiplier
(default 2), so local setup finishing within two hours alone does not imply GO.
GLOBAL inclusion is reserved by the model, not submitted or measured.

The optional regeneration probe runs after the measured rounds. It reconstructs
one sector from its identity/key, without reading secret labels, with its public
graph prepared outside the timer, and checks both roots against the certificate.
Its report covers one CPU lane; it does not assess partial-storage, GPU or ASIC
attacks and does not establish the security of reduced-layer parameters.

Mainnet activates the three-layer suite (`MAINNET_FAST_STORAGE_PROFILE`) with
persistent storage at epoch 1467 (`MAINNET_FAST_STORAGE_EPOCH` =
`MAINNET_PERSISTENT_STORAGE_EPOCH`), the epoch sealed storage also starts.
Its 32-epoch capacity warmup starts at epoch 1435 (frame 1,033,200): every
archive serving GLOBAL must run the release before then.
Benchmark flags cannot activate a suite on mainnet. Existing eleven-layer
encodings and proof transcripts are preserved. New registrations use `PS02`/`PS03`; capacity envelopes
use `PSC3`/`PSC4` with a tagged certificate. Cached labels and resumed sectors
carry their suite, while suite views share resource reservations.

Run the storage and proof regressions with:

```sh
python3 scripts/test-persistent-storage.py --offline --profile devnet
cargo +1.95.0 test -p quil-node --bin quil-node --profile devnet storage_readiness::
```

## Development

Please see the [CONTRIBUTING.md](CONTRIBUTING.md) file for more information on
how to contribute to this repository.

## License + Interpretation

Significant portions of Quilibrium's codebase depends on GPL-licensed code,
mandating a minimum license of GPL, however Quilibrium is licensed as AGPL to
accomodate the scenario in which a cloud provider may wish to coopt the network
software. The AGPL allows such providers to do so, provided they are willing
to contribute back the management code that interacts with the protocol and node
software. To provide clarity, our interpretation is with respect to node
provisioning and management tooling for deploying alternative networks, and not
applications which are deployed to the network, mainnet status monitors, or
container deployments of mainnet nodes from the public codebase.
