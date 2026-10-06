# Shard operations: arithmetic and sequence testing

Shard policy spans reward ranking, lifecycle decisions, authenticated execution,
registry observation and worker reconciliation. Isolated decision tests remain
useful, but cannot establish correctness of these interactions over time.

## Shared reward arithmetic

`quil_execution::pricing::allocation_ring_reward` defines allocation arithmetic.
It retains issuance's 53-bit square-root precision, fused division, final
truncation and legacy ring clamp. Issuance consumes the ring amount;
`allocation_prover_reward` divides that amount among eight prover slots.
The proposer and shard RPC estimates use the latter. qclient consumes the RPC
estimate and independently formats it and applies its projected-total policy.

Callers still select inputs: a holding uses its confirmed ring, whereas a
prospective join uses the predicted ring, including contention policy. Different
inputs can correctly yield different estimates. Metadata freshness and worker
eligibility are not arithmetic concerns. Do not turn a projected reward into an
authenticated entitlement or alter consensus validation to match a projection.

Characterization retains the previous issuance calculation as an independent
oracle. Fixed vectors include non-square counts and a rounding boundary that
failed under the previous proposer implementation. API parity tests complement,
rather than replace, those independent expectations.

## Deterministic scenario suite

`src/provers/lifecycle_scenarios.rs` runs the real evaluator and allocator against
controlled registry/worker observations. It records event traces and verifies
unique bindings after every tick. Its coverage includes:

| History or matrix | Checks |
| --- | --- |
| Join → confirm → deferred activation → renewal → leave notice → departure | Boundary timing, retained bindings and eventual release, with restart |
| Rejected leave → delayed/successful/failed renewal | Retain or rebind through one rejection epoch; no orphan leave during recovery; bounded failure cleanup |
| Delayed join observation before/after worker timeout | Timeout does not prove rejection; late observations restore a worker |
| Small allocation-state/worker matrix | Joining, Active, Paused, Leaving, Rejected and Kicked; storage epochs; idle/bound and manual/automatic workers; boundary neighbors |
| Replacement submission → observation → confirmation → departure | No extra leave wave funds the same demand; capacity becomes joinable after notice |
| 64 fixed-seed recovery histories | Varied frame increments, observation delays and restarts; independent binding expectations and replayable traces |

Run in the project Docker image:

```sh
cargo test --locked -p quil-execution --lib pricing:: -- --test-threads=1
cargo test --locked -p quil-engine --lib reward -- --test-threads=1
cargo test --locked -p quil-engine --lib provers:: -- --test-threads=1
cargo test --locked -p quil-engine --lib worker_allocator:: -- --test-threads=1
cargo test --locked -p quil-engine --test e2e_epoch_confirm -- --test-threads=1
```

The scenario registry is an observation boundary, not an implementation of
signature verification or execution. Signed encoding, materialization and
store-backed registry behavior remain covered by the execution and existing
end-to-end suites. A restart recreates policy state, not the entire distributed
network. The suite does not claim to enumerate every possible execution.

## Further coverage

Extend the harness with observed counterexamples and independent expectations.
Add multiple-node contention histories, split/merge and committee handoff
sequences, loss/reordering of signed messages, and independently lagging registry
views. Couple those histories to real signed materialization where practical;
keep fast policy tests separate from expensive cryptographic integration tests.
Replace process-global test epoch settings with instance-scoped configuration
before introducing concurrently simulated networks with different epoch lengths.
Counterfactual controls must fail when an important guard is removed. Preserve
release optimization settings and never relax authentication to make a test pass.
