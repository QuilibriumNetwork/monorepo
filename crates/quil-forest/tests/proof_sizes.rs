//! Empirical JMT inclusion-proof sizes across realistic tree sizes.
//!
//! A JMT `SparseMerkleProof` is `leaf (opt) + Vec<SparseMerkleNode> siblings`,
//! siblings ordered bottom→root, ~33 bytes each (32-byte hash + 1 tag). The
//! count is ~log2(N) because empty subtrees collapse. This test borsh-encodes
//! real proofs (exact wire size) at several N so the KZG-constant-size vs
//! JMT-log(N) tradeoff rests on numbers, not hand-waving.
//!
//! Run: `cargo test -p quil-forest --test proof_sizes -- --nocapture`

use jmt::{KeyHash, Sha256Jmt};
use quil_forest::MemTreeStore;
use sha2::{Digest, Sha256};

fn build(n: usize) -> MemTreeStore {
    let store = MemTreeStore::default();
    let tree = Sha256Jmt::new(&store);
    let entries = (0..n).map(|i| {
        let key = Sha256::digest((i as u64).to_be_bytes());
        let value = Sha256::digest([&b"v"[..], &key[..]].concat()).to_vec();
        (KeyHash::with::<Sha256>(key), Some(value))
    });
    let (_root, batch) = tree.put_value_set(entries, 0).unwrap();
    use jmt::storage::TreeWriter;
    store.write_node_batch(&batch.node_batch).unwrap();
    store
}

#[test]
fn jmt_proof_sizes_by_tree_size() {
    println!("\n  N        proof bytes (min/med/max)     ~siblings (med)   proof+value(~med)");
    println!("  -------  ---------------------------   ---------------   -----------------");
    // ~33 bytes/sibling; subtract a small fixed leaf+len overhead to back out count.
    const PER_SIBLING: usize = 33;
    const OVERHEAD: usize = 1 /*leaf opt tag*/ + 64 /*leaf key+valhash*/ + 4 /*vec len*/;
    const VALUE_BYTES: usize = 48; // a typical L2/L3 leaf value (root32+counts)

    for &n in &[64usize, 512, 4096, 65_536] {
        let store = build(n);
        let tree = Sha256Jmt::new(&store);
        let sample = (n / 200).max(1);
        let mut sizes: Vec<usize> = Vec::new();
        let mut i = 0usize;
        while i < n {
            let key = Sha256::digest((i as u64).to_be_bytes());
            let (val, proof) = tree
                .get_with_proof(KeyHash::with::<Sha256>(key), 0)
                .unwrap();
            assert!(val.is_some());
            sizes.push(borsh::to_vec(&proof).unwrap().len());
            i += sample;
        }
        sizes.sort_unstable();
        let min = *sizes.first().unwrap();
        let med = sizes[sizes.len() / 2];
        let max = *sizes.last().unwrap();
        let sib_med = med.saturating_sub(OVERHEAD) / PER_SIBLING;
        println!(
            "  {:>7}  {:>6} / {:>6} / {:>6} bytes       ~{:>3}              {:>6} bytes",
            n,
            min,
            med,
            max,
            sib_med,
            med + VALUE_BYTES
        );
    }
    println!();
}
