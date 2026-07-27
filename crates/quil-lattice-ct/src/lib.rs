//! Post-quantum confidential transactions.
//!
//! This crate replaces the decaf448 privacy stack (`bulletproofs` + `verenc` +
//! `DecafAgreement`), all of which rest on discrete-log hardness and are Shor-
//! broken. The build order is:
//!
//! 1. **Homomorphic commitment** (this module) — the Pedersen replacement.
//! 2. Range proof (LNP framework).
//! 3. Balance proof (Σin = Σout + fee), riding on #1.
//! 4. Linkable ring signature (Raptor / NTRU) — spend auth + key-image.
//! 5. Stealth / one-time keys — `DecafAgreement` → sntrup761 KEM.
//! 6. Verifiable encryption (LNP) — the `verenc` analogue.
//!
//! # Structure
//!
//! Standard BDLOP / Ajtai module-lattice commitments. The production proof
//! systems run over the ring form `R_q = Z_q[X]/(X^d+1)` (the `*_rq` modules) at
//! the parameters in [`params`], whose M-SIS/M-LWE levels are set from a
//! core-SVP / lattice-estimator analysis. The plain-`Z_q` reference modules
//! (`sigma`/`binary`/`range`/`ring`/`linear`, [`CommitParams`]) use illustrative
//! parameters for clarity and are superseded by their `_rq` counterparts.

pub mod accumulator;
pub mod arith;
pub mod binary;
pub mod binary_rq;
pub mod commitment;
pub mod limb_balance;
pub mod linear;
pub mod linear_rq;
pub mod membership;
pub mod memo;
pub mod module;
pub mod params;
pub mod range;
pub mod range_rq;
pub mod ring;
pub mod ring_rq;
pub mod rq;
pub mod shortness;
pub mod sigma;
pub mod sigma_rq;
pub mod stealth;
pub mod value_link;
pub mod wire;

pub use binary::{prove_bit, verify_bit, BinaryProof};
pub use linear::{prove_linear, verify_linear};
pub use range::{prove_range, verify_range, RangeKey, RangeProof};
pub use ring::{linked, sign, verify, LinkableRingSig, RingParams};
pub use commitment::{CommitKey, CommitParams, Commitment, Opening};
pub use sigma::{prove_short_opening, verify_short_opening, ShortOpeningProof, SigmaParams};
