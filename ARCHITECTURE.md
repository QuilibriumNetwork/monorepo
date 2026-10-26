# Quilibrium Architecture

## Overview

Quilibrium is a distributed protocol that leverages advanced cryptographic
techniques including post-quantum signatures and key exchange for
privacy-preserving compute. The system operates on a sharded network
architecture where the master process runs global consensus while data workers
run app-level consensus for their assigned shards, each maintaining their own
hypergraph state and storage. Workers run as threads of the master process by
default, or as standalone processes (see Worker Modes below).

The node and client are a single Rust workspace (`Cargo.toml`, `crates/`).

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       Client Applications                       │
│                  (CLI, RPC Clients, Applications)               │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────┴─────────────────────────────────┐
│                           RPC Layer                             │
│            (gRPC services, explorer REST, DataIPC)              │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────┴─────────────────────────────────┐
│                       Master Process (Core 0)                   │
│   ┌──────────────┐  ┌─────────────┐  ┌─────────────────────┐    │
│   │    Global    │  │   Global    │  │    P2P Network      │    │
│   │  Consensus   │  │  Execution  │  │   (BlossomSub)      │    │
│   │   Engine     │  │   Engine    │  │                     │    │
│   └──────────────┘  └─────────────┘  └─────────────────────┘    │
│   ┌──────────────┐  ┌─────────────┐  ┌─────────────────────┐    │
│   │   Storage    │  │   Crypto    │  │  Global Hypergraph  │    │
│   │  (RocksDB)   │  │   Crates    │  │       State         │    │
│   └──────────────┘  └─────────────┘  └─────────────────────┘    │
└───────────────────────────────┬─────────────────────────────────┘
                                │ DataIPC (gRPC) or in-process channels
┌───────────────────────────────┴─────────────────────────────────┐
│                      Data Worker (Core 1+)                      │
│   ┌──────────────┐  ┌─────────────┐  ┌─────────────────────┐    │
│   │     App      │  │Token/Hyper- │  │    P2P Network      │    │
│   │  Consensus   │  │graph/Compute│  │ (master or proxied) │    │
│   │   Engine     │  │  Execution  │  │                     │    │
│   └──────────────┘  └─────────────┘  └─────────────────────┘    │
│   ┌──────────────┐  ┌─────────────┐  ┌─────────────────────┐    │
│   │   Storage    │  │   Crypto    │  │  Shard Hypergraph   │    │
│   │  (RocksDB)   │  │   Crates    │  │       State         │    │
│   └──────────────┘  └─────────────┘  └─────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                                │
                    [Repeat for Core 2, 3, ...]
```

### Core Components

#### 1. Node (`crates/quil-node/`)

The main entry point (`src/main.rs`) containing the node binary. The master
runs the global stack; each data worker owns its own consensus engine,
execution engines and store.

**Process Types:**

##### Master Process (Core 0)
Runs the global consensus and coordination (`src/master_node/`):
- **Global Consensus**: System-wide consensus and coordination
- **Global Execution Engine**: System-level operations
- **P2P Networking**: Full BlossomSub stack for global communication
- **Storage (RocksDB)**: Persistent storage for global state
- **Cryptography**: Access to the cryptographic crates
- **Global Hypergraph State**: System-wide state management

##### Data Workers (Cores 1+)
Each worker manages specific shards:
- **App Consensus Engine**: Shard-level consensus
- **Execution Engines**: Token, Hypergraph, and Compute engines
- **P2P Networking**: The master's BlossomSub stack, shared in-process or
  reached through the master's pubsub proxy; a standalone worker can also run
  its own stack
- **Storage (RocksDB)**: Persistent storage for shard state in the worker's
  own store directory
- **Cryptography**: Access to the cryptographic crates
- **Shard Hypergraph State**: Shard-specific state management

##### Worker Modes
- **Thread mode (default)**: `ThreadWorkerManager`
  (`crates/quil-engine/src/thread_worker.rs`) runs each worker as a core-pinned
  thread of the master process with its own single-threaded runtime;
  the master talks to it over in-process channels.
- **Standalone mode**: when `engine.dataWorkerStreamMultiaddrs` is configured,
  `RemoteWorkerManager` (`crates/quil-engine/src/remote_worker.rs`) assigns
  shards by `Respawn(filter)` RPC to separate `quil-node --core=N` processes
  (`crates/quil-node/src/worker_node.rs`,
  `crates/quil-engine/src/worker_node.rs`), which may run on other machines.

**Application Layer**:
- `master_node` (`crates/quil-node/src/master_node/`): Main node
  implementation (runs in master process)
- `worker_node` (`crates/quil-node/src/worker_node.rs`): Standalone worker
  implementation (runs in worker processes)

**Key Subsystems:**

##### Consensus Engines (`crates/quil-engine/`, `crates/quil-cw-consensus/`, `crates/quil-consensus/`)

Two distinct consensus levels run on commonware simplex with Falcon-512
signatures (`quil-cw-consensus`), driven by seams in `quil-engine`. The
generic `quil-consensus` crate keeps the shared models, leader-provider trait
and bitmask helpers.

**Global Consensus** (`cw_global_seams.rs`, `global_finalization.rs`) - Master
Process:
- System-wide coordination
- Cross-shard transaction ordering
- Global state transitions
- Network-wide fork choice

**App Consensus** (`app_engine.rs`, `cw_app_seams.rs`) - Workers:
- Shard-specific consensus
- Local transaction ordering
- Shard state transitions
- Integration with global consensus

**Shared Components**:
- `DifficultyAdjuster` (`difficulty.rs`): Dynamic difficulty adjustment
- `DynamicFeeManager` (`fees.rs`): Dynamic Fee Market management
- `ProverRegistry` (`crates/quil-execution/src/prover_registry.rs`): Enrolled
  prover registry
- `SignerRegistry` (`crates/quil-p2p/src/signer_registry.rs`): Block signer
  registry
- Time Reels (`time_reel.rs`): VDF-based time consensus

##### Execution Engines (`crates/quil-execution/`)

Created by `ExecutionEngineManager` (`src/manager.rs`). Distribution across
processes:

**Global Execution Engine** (`global_engine.rs`) - Master Process:
- System-wide operations
- Cross-shard coordination
- Global state updates

**App Execution Engines** - Workers:
- **Token Engine** (`token_engine.rs`): QUIL token operations within shards
- **Hypergraph Engine** (`hypergraph_engine.rs`): CRDT-based state management
  for shards
- **Compute Engine** (`compute_engine.rs`): Compute deployment and execution
  operations; the circuit compiler it needs is not yet wired in the node (a
  no-op stub is used)

##### P2P Networking (`crates/quil-p2p/`, `crates/blossomsub/`)

- **BlossomSub**: Custom pub/sub protocol (`crates/blossomsub`, a fork of
  libp2p-gossipsub, bridged by `quil-p2p/src/blossomsub_behaviour.rs`)
- **Peer Management**: Discovery and connections
- **Public Channels**: Point to point authenticated message routing
- **Private Channels**: Onion-routing authenticated message channels
  (`quil-p2p/src/onion/`)
- **DHT Integration**: Distributed peer discovery (`crates/libp2p-kad`,
  `quil-node/src/dht_node.rs`)

Master process handles global bitmask, workers handle shard-specific bitmasks.

##### Storage Layer (`crates/quil-store/`)

Each store (the master's and each worker's) is a separate RocksDB instance:
- **Clock Store**: Frame-based ordering
- **Token Store**: Locally managed token state
- **Key Store**: Key records
- **Hypergraph Store**: Hypergraph state persistence
- **Shards and Worker Stores**: Shard metadata and worker bindings

Storage is partitioned by process responsibility (global vs shard).

##### Hypergraph (`crates/quil-hypergraph/`, `crates/quil-forest/`)

Distributed graph structure:
- **Global Hypergraph**: Maintained by master process
- **Shard Hypergraphs**: Maintained by respective workers
- **CRDT Semantics**: Conflict-free updates
- **Components**:
  - `HypergraphCrdt` (`quil-hypergraph/src/crdt.rs`): Core graph structure
  - Vertex and hyperedge add/remove operations
    (`quil-execution/src/hypergraph_intrinsic/types.rs`)
  - `quil-forest`: Authenticated Merkle forest holding the committed state

##### Cryptographic Layer (`crates/quil-crypto/`, `crates/quil-tries/`)

Shared across all processes:
- **Crypto adapters**: `quil-crypto` wraps the cryptographic crates behind the
  `quil-types` traits
- **Proof Trees**: Vector commitment trees (`quil-tries`)
- **Channel Crypto**: Secure E2EE communication (`crates/channel`)

#### 2. Client (`crates/quil-client/`)

Command-line interface (`qclient`) for user interactions:
- **Node Management**: Install, update, service control
- **Token Operations**: Balance, transfer, mint operations
- **Hypergraph Operations**: Deploy, store, update, query operations
- **Compute Operations**: Deploy, execute, commit operations
- **Prover Operations**: Join, merge, manage provers
- **Configuration**: Network and RPC settings

#### 3. Rust Crates (`crates/`)

Libraries used by all processes:

**Core Cryptography**:
- **bls48581**: BLS signatures
- **bulletproofs**: Bulletproofs over Ed448
- **vdf**: Verifiable Delay Functions for time consensus
- **verenc**: Verifiable encryption schemes
- **quil-lattice-ct**: Lattice-based confidential token commitments and proofs

**MPC Components**:
- **ferret**: Oblivious transfer protocols
- **channel**: Secure communication protocols
- **rpm**: Randomized Permutation Matrices
- **dkls23**: Threshold ECDSA

**Supporting**:
- **classgroup**: Class group VDF implementation
- **quil-compiler**: QCL circuit compiler
- WASM bindings for various libraries (`*-wasm`)

#### 4. Supporting Libraries

**MPC and Privacy**:
- `emp-ot`, `emp-tool`: Efficient MPC primitives (C++, built by
  `install-emp.sh`)

**Networking**:
- `crates/blossomsub`: Custom gossip for sharding
- `crates/libp2p-kad`: DHT implementation
- `crates/libp2p-*`: Forked libp2p components

**Storage**:
- `rocksdb`: High-performance key-value store (`quil-store`)
- `protobufs`: Protocol definitions (`.proto`, compiled by
  `crates/quil-types/build.rs`)

#### 5. Interfaces (`crates/quil-types/`)

**Interfaces**:
- `src/consensus.rs`: Consensus-oriented interfaces:
  - **DifficultyAdjuster**: Manages the next difficulty following the prior
      frame
  - **EventDistributor**: The central nervous system to internal event control
      flows, connects time reel events, consensus engine events, and emits
      ordered control events. Manages halts, resumes, and state rewind/replay
      events.
  - **DynamicFeeManager**: Tracks and calculates dynamic fee market multipliers
  - **RewardIssuance**: The issuance policy of the network
  - **ProverRegistry**: Tracks prover information from ongoing hypergraph state
      transitions
  - **SignerRegistry**: Tracks general signer information, including private
      messaging channel keys
  - **AppFrameValidator**: Validator path for app shard frames
  - **GlobalFrameValidator**: Validator path for global frames
- `src/crypto.rs`:
  - **BlsAggregateOutput**: Output of aggregate signature handling
  - **BulletproofProver**: Provides construction and verification of outputs
      related to bulletproofs
  - **FrameProver**: Methods for generating proofs on frames
  - **InclusionProver**: Methods for generating KZG proofs
  - **Multiproof**: Methods for multiproofs
  - **BlsConstructor**: Methods for creating BLS keys
  - **DecafConstructor**: Methods for creating Decaf 448 keys
  - **DecafAgreement**: Methods specific to key agreement with Decaf 448 keys
  - **Signer**: Generic signer interface to unify all managed key types
  - **KeyManager**: Key management interface
- `src/execution.rs`: Execution engine encapsulation
  - **ShardExecutionEngine**: Shard-specific execution container methods
  - **CircuitCompiler**: Circuit compilation for compute deployments
- `crates/quil-execution/src/intrinsics.rs`: Intrinsic interface
  - **Intrinsic**: Methods for managing intrinsics
- `src/p2p.rs`: PubSub related interfaces
- `src/store.rs`: KVDB and store related interfaces (`ClockStore`,
  `TokenStore`, `HypergraphStore`, ...)

**Test Doubles**:
Stubs for tests live in `testing` modules next to the code they stand in for
(e.g. `crates/quil-execution/src/testing.rs`,
`crates/quil-hypergraph/src/testing.rs`, `crates/quil-store/src/testing.rs`).

**Tries**:
All trie related constructions are contained within `quil-tries`.

### Architectural Patterns

#### 1. Shared-Nothing Worker Architecture

Each worker is self-contained with its own:
- Consensus engine (global or app)
- Execution engine(s)
- Storage layer

and uses the cryptographic crates and (directly or via the master) the P2P
stack. A worker runs as a thread by default or as a standalone process.

Benefits:
- Worker independence
- Failure isolation (process-level when standalone)
- Horizontal scalability

#### 2. Sharded State Management

State is partitioned across the master and its workers:
- Master process: Global state and coordination
- Workers: Shard-specific state
- CRDT hypergraph for convergence

#### 3. Multi-Party Computation (MPC)

Privacy-preserving computation (the building blocks are in the workspace; the
node does not yet execute MPC compute):
- Circuit compilation via `quil-compiler`
- Oblivious transfer via `ferret`
- General-purpose privacy beyond just transactions

#### 4. Layered Consensus

Two-tier consensus system:
- Global consensus for system-wide coordination
- App consensus for shard-level operations
- Time Reel VDF for temporal ordering

#### 5. Master-Worker Communication

Master-worker communication design:
- Structured message passing (in-process channels, or the `DataIPCService`
  gRPC service for standalone workers)
- Minimal shared state

### Security Architecture

#### 1. Privacy Layers

**Transaction Privacy**:
- Lattice-based confidential token commitments and proofs (`quil-lattice-ct`)

**Computation Privacy**:
- MPC building blocks (`quil-compiler`, `ferret`); not yet wired into the node

**Data Privacy**:
- Post-quantum commit-and-encrypt for confidential hypergraph vertex fields
  (`quil-execution/src/hypergraph_intrinsic/confidential.rs`)

#### 2. Process Isolation

- Separate store per worker
- Standalone workers: independent process spaces and a limited gRPC surface

#### 3. Network Security

- Peer reputation scoring (`crates/blossomsub/src/peer_score.rs`)
- Post-quantum authenticated transports (`quil-p2p/src/pqnoise.rs`)
- Shard-aware routing

#### 4. Binary Verification

- Multi-signature verification of release digests against the signatories
  (`quil-node/src/release_check.rs`, `signers/`)

### System Boundaries

#### Process Boundaries
- Master process: Global operations
- Workers: Shard operations
- Clear interfaces between master and workers

#### Consensus Boundaries
- Global consensus: Cross-shard coordination
- App consensus: Intra-shard operations
- Well-defined interaction protocols

#### State Boundaries
- Global state in master process
- Shard state in workers
- CRDT merge protocols for synchronization

#### Network Boundaries
- Topic-based message routing
- Shard-aware peer connections

### Build and Deployment

#### Build System
- Rust workspace built with Cargo, linking the native GMP/FLINT/MPFR/EMP
  libraries (`node/build.sh`, `Taskfile.yaml`, `docker/`)
- Platform-specific optimizations
- Static linking for distribution

#### Configuration
- Per-process configuration
- YAML configuration files (`quil-config`)

#### Monitoring
- Prometheus metrics per process
- Grafana dashboards
- Structured logging

## Design Rationale

### 1. Independent Worker Stacks
- **Decision**: Each worker has its own engines and store
- **Rationale**: Isolation, independent scaling, failure resilience

### 2. Two-Tier Consensus
- **Decision**: Separate global and app consensus
- **Rationale**: Scalability through sharding while maintaining global
    coordination

### 3. MPC for General Privacy
- **Decision**: MPC beyond just transactions
- **Rationale**: Flexible privacy for arbitrary computations

### 4. CRDT Hypergraph
- **Decision**: CRDT-based state model
- **Rationale**: Natural convergence in distributed sharded system

### 5. Rust Throughout
- **Decision**: Rust for the node, client and cryptography
- **Rationale**: Performance and memory safety for critical operations

## Development Guidelines

### Architecture Principles
- Maintain worker independence
- Respect consensus boundaries
- Minimize cross-shard communication
- Preserve privacy guarantees

### Code Organization
- Clear separation by crate
- Shared interfaces and types (`quil-types`)
- Process-specific implementations

### Testing Strategy
- Unit tests per component
- Integration tests per crate (`crates/*/tests/`)
- Docker-based network harness (`crates/devnet`)
- CI runs `cargo nextest` (`.nextest.toml`)

## Frequently Asked Questions (FAQ) with Code References

### Getting Started

**Q: Where is the main entry point?**
- Main entry: `crates/quil-node/src/main.rs`
- The `main()` function handles initialization, and manages the lifecycle

**Q: How does the multi-process architecture work?**
- Worker management: `crates/quil-node/src/master_node/worker_manager.rs`
- Master process runs on core 0 and starts the global consensus stack with a
  worker manager
- By default `ThreadWorkerManager` starts a pinned worker thread per core
  (`crates/quil-engine/src/thread_worker.rs`)
- With `engine.dataWorkerStreamMultiaddrs` set, `RemoteWorkerManager`
  (`crates/quil-engine/src/remote_worker.rs`) drives standalone
  `quil-node --core=N --parent-process <master pid>` processes you start
  yourself (`scripts/localnet.sh` shows a local setup)
- Each worker receives the `--core` parameter to identify its role

**Q: How do I run the node?**
- Build: `./node/build.sh` (builds `crates/quil-node`, statically linked)
- Run: the built `node/build/<platform>/node` binary (starts the master
  process, which starts its workers)
- Configuration: `config.yml` in the config directory

### Architecture & Design

**Q: How do processes communicate (IPC)?**
- Thread workers use in-process channels
- Standalone workers use the `DataIPCService` gRPC service
  (`protobufs/node.proto`) and the master's pubsub proxy
  (`crates/quil-rpc/src/pubsub_proxy.rs`)
- Master process acts as coordinator

**Q: Where is consensus implemented?**
- App Consensus (workers): `crates/quil-engine/src/app_engine.rs`
  (`AppConsensusEngine`), `cw_app_seams.rs`
- Global Consensus (master): `crates/quil-engine/src/cw_global_seams.rs`,
  `crates/quil-node/src/cw_consensus_bridge.rs`
- Simplex backend: `crates/quil-cw-consensus/`
- Consensus interfaces: `crates/quil-types/src/consensus.rs`,
  `crates/quil-consensus/src/leader_provider.rs`

**Q: Where is the hypergraph implementation?**
- Main structure: `crates/quil-hypergraph/src/crdt.rs` (`HypergraphCrdt`)
- Core components:
  - Addressing: `crates/quil-hypergraph/src/addressing.rs`
  - Snapshots: `crates/quil-hypergraph/src/snapshot.rs`
  - Vertex and hyperedge operations:
    `crates/quil-execution/src/hypergraph_intrinsic/types.rs`
  - Persistence: `crates/quil-store/src/hypergraph.rs`

### Networking & P2P

**Q: How is P2P networking initialized?**
- BlossomSub: `crates/quil-p2p/src/blossomsub_behaviour.rs`, node setup in
  `crates/quil-p2p/src/node.rs`
- Worker P2P ports start at `engine.dataWorkerBaseP2PPort`
- A standalone worker runs its own stack or, with `engine.enableMasterProxy`,
  uses the master's

**Q: How does cross-shard communication work?**
- Through master process coordination via P2P
- Topic-based routing in BlossomSub
- Shard-aware peer connections
- Majority of cross-shard communication requires only proof data, keeping shards
    conflict-free

### Execution & State

**Q: Where are execution engines created?**
- Factory: `crates/quil-execution/src/manager.rs`
  (`ExecutionEngineManager::new`)
- Engine types: Global, Compute, Token, Hypergraph
  (`crates/quil-execution/src/engines.rs`)

**Q: How is state stored?**
- RocksDB wrapper: `crates/quil-store/src/rocksdb_store.rs`
- Clock store: `crates/quil-store/src/clock.rs`
- Localized token store: `crates/quil-store/src/token.rs`
- The master and each worker have their own DB instance

### Cryptography & Privacy

**Q: Where is MPC/garbled circuits used?**
- Circuit compiler: `crates/quil-compiler/` (a port of the former `bedlam`
  compiler); not yet wired into the node, which uses a no-op compiler
- Compute intrinsic: `crates/quil-execution/src/compute_intrinsic/`
- Oblivious transfer: `crates/ferret/`

**Q: Where are the cryptographic libraries?**
- Rust crates: `crates/` directory
  - BLS: `crates/bls48581/`
  - Bulletproofs: `crates/bulletproofs/`
  - VDF: `crates/vdf/`
- Node-facing adapters: `crates/quil-crypto/`

**Q: How are bulletproofs integrated?**
- Rust implementation: `crates/bulletproofs/`
- Adapter: `crates/quil-crypto/src/bulletproof_adapter.rs`
- The node's confidential token path is now lattice-based
  (`crates/quil-lattice-ct/`); the decaf448 bulletproof providers are retired
  from it

### Configuration & Operations

**Q: How do I configure the node?**
- Main config: `crates/quil-config/src/config.rs` (`Config` struct)
- Engine config: `crates/quil-config/src/engine.rs`
- Data worker config
- Load with a YAML file

**Q: What are the RPC/API endpoints?**
- Node RPC: `crates/quil-rpc/src/node_service.rs`
- Global and diagnostics services: `crates/quil-rpc/src/global_service.rs`,
  `crates/quil-rpc/src/diagnostics_service.rs`
- gRPC definitions: `protobufs/node.proto`
- Explorer REST API: `crates/quil-explorer/`

**Q: How do I monitor the node?**
- Prometheus metrics throughout codebase (`crates/quil-node/src/rpc_metrics.rs`;
  `quil-node --metrics` fetches them from a running node)
- Grafana dashboards: `dashboards/grafana/`
- Structured logging with configurable levels

### Development

**Q: How is the project built?**
- Node build: `node/build.sh` (static linking, platform detection)
- Client build: `Taskfile.yaml` `build_qclient_*` tasks (`crates/quil-client`)
- Docker: `docker/Dockerfile.source`, `docker/Dockerfile.sourceavx512`,
  `docker/Dockerfile.release`

**Q: What happens when a worker crashes?**
- The master keeps a connection to each standalone worker and re-sends any
  owed `Respawn` (`RemoteWorkerManager::reconcile_respawns`)
- A standalone worker exits when its parent process is gone
  (`monitor_parent_process`)
- Process isolation prevents cascade failures between standalone workers

**Q: How do I add a new execution engine?**
- Implement `ShardExecutionEngine` (`crates/quil-types/src/execution.rs`) in
  `crates/quil-execution/`
- Add to `ExecutionEngineManager` in `crates/quil-execution/src/manager.rs`
- Register intrinsics as needed

### Common Code Paths

**Transaction Flow:**
1. RPC endpoint receives transaction
2. Routed to appropriate shard via worker
3. App consensus orders transaction
4. Execution engine processes
5. State updated in hypergraph
6. Proof generated and stored

**Consensus Flow:**
1. Time reel provides ordering
2. App consensus in workers for shards
3. Global consensus coordinates cross-shard
4. Fork choice based on VDF proofs

**P2P Message Flow:**
1. BlossomSub receives message
2. Topic routing to appropriate handler
3. Shard-specific messages to workers
4. Global messages to master process
