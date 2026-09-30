//! Decoder robustness over the hand-written wire codecs: every byte string,
//! random or a mutation of a valid encoding, must come back as `Err` or a
//! value, never a panic; every valid encoding must round-trip. Deterministic
//! (a fixed seed), so a failure names the bytes that caused it. Bounded to
//! keep the component suite fast; `QUIL_FUZZ_ITERATIONS` raises the count.

use crate::global_intrinsic::handoff::{CertificateSubmission, DesiredCommittee, Request, Target};
use crate::token_intrinsic::{
    accumulator_header, roots::BlockSummary, settlement_record, shard_accumulator, spend_relay,
    summary_tree::TreeNode,
};
use quil_cw_consensus::handoff::{Checkpoint, Seal, Session};
use quil_lattice_ct::confidential::relation::membership::{Node, NODE_BYTES};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
    /// `lo ..= lo + span - 1` bytes.
    fn bytes_between(&mut self, lo: usize, span: usize) -> Vec<u8> {
        let len = lo + self.below(span);
        self.bytes(len)
    }
    fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for byte in &mut out {
            *byte = self.next() as u8;
        }
        out
    }
    /// One of: flip a bit, overwrite a byte, truncate, extend, insert, delete.
    fn mutate(&mut self, valid: &[u8]) -> Vec<u8> {
        let mut bytes = valid.to_vec();
        for _ in 0..1 + self.below(3) {
            if bytes.is_empty() {
                bytes = self.bytes_between(1, 8);
                continue;
            }
            match self.below(6) {
                0 => {
                    let i = self.below(bytes.len());
                    bytes[i] ^= 1 << self.below(8);
                }
                1 => {
                    let i = self.below(bytes.len());
                    bytes[i] = self.next() as u8;
                }
                2 => bytes.truncate(self.below(bytes.len())),
                3 => { let extra = self.bytes_between(1, 16); bytes.extend(extra) }
                4 => {
                    let i = self.below(bytes.len() + 1);
                    bytes.insert(i, self.next() as u8);
                }
                _ => {
                    let i = self.below(bytes.len());
                    bytes.remove(i);
                }
            }
        }
        bytes
    }
}

fn iterations() -> usize {
    std::env::var("QUIL_FUZZ_ITERATIONS").ok().and_then(|v| v.parse().ok()).unwrap_or(4_000)
}

/// Run `decode` over random and mutated inputs. A panic is reported with the
/// seed, the iteration and the input; a `Result` of either kind is fine.
fn survives(name: &str, valid: &[Vec<u8>], decode: impl Fn(&[u8]) + std::panic::RefUnwindSafe) {
    let seed = 0x5eed_0000_0000_0001u64 ^ name.len() as u64;
    let mut rng = Rng(seed);
    for i in 0..iterations() {
        let input = if valid.is_empty() || i % 2 == 0 {
            rng.bytes_between(0, 512)
        } else {
            let base = &valid[rng.below(valid.len())];
            rng.mutate(base)
        };
        let outcome = std::panic::catch_unwind(|| decode(&input));
        assert!(
            outcome.is_ok(),
            "{name} panicked at iteration {i} (seed {seed:#x}) on {} bytes: {}",
            input.len(),
            hex::encode(&input)
        );
    }
}

fn session(rng: &mut Rng, members: usize) -> Session {
    let mut keys: Vec<Vec<u8>> = (0..members).map(|_| rng.bytes(897)).collect();
    keys.sort();
    keys.dedup();
    Session {
        chain_id: rng.array(),
        filter: shard_filter(rng),
        generation: rng.next() % 1_000,
        genesis: rng.array(),
        base_frame: rng.next() % 1_000_000,
        authorization: rng.array(),
        members: keys,
    }
}

/// A bare application address or a bit-path shard filter under it.
fn shard_filter(rng: &mut Rng) -> Vec<u8> {
    let app: [u8; 32] = rng.array();
    let depth = rng.below(5);
    if depth == 0 {
        return app.to_vec();
    }
    let bits: Vec<bool> = (0..depth).map(|_| rng.below(2) == 1).collect();
    quil_forest::encode_shard_bit_path(&app, &bits)
}

fn checkpoint(rng: &mut Rng) -> Checkpoint {
    Checkpoint {
        frame: rng.next() % 1_000_000,
        view: rng.next() % 1_000_000,
        digest: rng.array(),
        state_roots: [rng.array(), rng.array(), rng.array(), rng.array()],
        history_root: rng.array(),
    }
}

#[test]
fn committee_session_and_seal_codecs_survive_arbitrary_bytes_and_round_trip() {
    let mut rng = Rng(11);
    let mut sessions = Vec::new();
    let mut seals = Vec::new();
    for _ in 0..16 {
        let members = 1 + rng.below(6);
        let session = session(&mut rng, members);
        let encoded = session.encode().unwrap();
        assert_eq!(Session::decode(&encoded).unwrap(), session, "session round trip");
        sessions.push(encoded);
        let seal = Seal { request: rng.array(), session: rng.array(), view: rng.next(), checkpoint: checkpoint(&mut rng) };
        let encoded = seal.encode();
        assert!(Seal::is_encoding(&encoded));
        assert_eq!(Seal::decode(&encoded).unwrap(), seal, "seal round trip");
        seals.push(encoded);
    }
    survives("session", &sessions, |bytes| { let _ = Session::decode(bytes); });
    survives("seal", &seals, |bytes| { let _ = Seal::decode(bytes); let _ = Seal::is_encoding(bytes); });
}

#[test]
fn handoff_request_and_submission_codecs_survive_arbitrary_bytes_and_round_trip() {
    let mut rng = Rng(23);
    let mut requests = Vec::new();
    let mut submissions = Vec::new();
    for _ in 0..16 {
        // A split of a whole application into its two leaves, or the merge
        // back: the request's partition rules hold either way.
        let chain: [u8; 32] = rng.array();
        let app: [u8; 32] = rng.array();
        let root = app.to_vec();
        let leaf0 = quil_forest::encode_shard_bit_path(&app, &[false]);
        let leaf1 = quil_forest::encode_shard_bit_path(&app, &[true]);
        let mut member_session = |filter: &Vec<u8>, rng: &mut Rng| {
            let m = 1 + rng.below(4);
            let mut s = session(rng, m);
            s.chain_id = chain;
            s.filter = filter.clone();
            s
        };
        let members = |rng: &mut Rng| { let mut m: Vec<Vec<u8>> = (0..1 + rng.below(3)).map(|_| rng.bytes(897)).collect(); m.sort(); m.dedup(); m };
        let target = |filter: &Vec<u8>, rng: &mut Rng| Target {
            committee: DesiredCommittee { filter: filter.clone(), members: members(rng) },
            generation: 1 + rng.next() % 100,
            previous: if rng.below(2) == 0 { None } else { Some(rng.array()) },
        };
        let (sources, targets) = if rng.below(2) == 0 {
            (vec![member_session(&root, &mut rng)], vec![target(&leaf0, &mut rng), target(&leaf1, &mut rng)])
        } else {
            (vec![member_session(&leaf0, &mut rng), member_session(&leaf1, &mut rng)], vec![target(&root, &mut rng)])
        };
        let request = Request { frame: 1 + rng.next() % 1_000_000, sources, vacant: Vec::new(), targets };
        let encoded = request.encode().unwrap();
        assert_eq!(Request::decode(&encoded).unwrap(), request, "request round trip");
        requests.push(encoded);
        let submission = CertificateSubmission {
            seal: Seal { request: rng.array(), session: rng.array(), view: rng.next(), checkpoint: checkpoint(&mut rng) },
            certificate: rng.bytes_between(0, 600),
        };
        let encoded = submission.to_canonical_bytes().unwrap();
        assert_eq!(CertificateSubmission::from_canonical_bytes(&encoded).unwrap(), submission, "submission round trip");
        submissions.push(encoded);
    }
    survives("request", &requests, |bytes| { let _ = Request::decode(bytes); });
    survives("submission", &submissions, |bytes| { let _ = CertificateSubmission::from_canonical_bytes(bytes); });
}

#[test]
fn relay_and_accumulator_codecs_survive_arbitrary_bytes_and_round_trip() {
    let mut rng = Rng(37);
    let entry = |rng: &mut Rng| {
        let paid = rng.below(2) == 0;
        let funded = rng.below(2) == 0;
        settlement_record::SettlementEntry {
            receipt: rng.array(), parameter_context: rng.array(), destination: rng.array(),
            context: if funded { rng.array() } else { [0; 32] },
            settlement: 1 + rng.next() as u128,
            payment_address: if paid { rng.array() } else { [0; 32] },
            payment: if paid { 1 + rng.next() as u128 } else { 0 },
            claimant: if funded { [0; 32] } else { rng.array() },
        }
    };
    let mut settlements = Vec::new();
    let mut settlement_relays = Vec::new();
    let mut spends = Vec::new();
    let mut spend_relays = Vec::new();
    let mut reports = Vec::new();
    let mut summaries = Vec::new();
    let mut tree_nodes: Vec<(u8, Vec<u8>)> = Vec::new();
    for _ in 0..16 {
        let entries: Vec<_> = (0..rng.below(4)).map(|_| entry(&mut rng)).collect();
        let sorted = settlement_record::canonical_frame_entries(&entries).unwrap();
        let encoded = settlement_record::encode_entries(&sorted).unwrap();
        assert_eq!(settlement_record::decode_entries(&encoded).unwrap(), sorted);
        settlements.push(encoded);
        let header_frame = 40 + rng.next() % 1_000;
        let mut frames: Vec<(u64, Vec<settlement_record::SettlementEntry>)> = Vec::new();
        for frame in settlement_record::relay_window(header_frame) {
            if rng.below(4) == 0 {
                let e = entry(&mut rng);
                frames.push((frame, settlement_record::canonical_frame_entries(&[e]).unwrap()));
            }
        }
        let encoded = settlement_record::encode_relay(&frames).unwrap();
        assert_eq!(settlement_record::decode_relay(header_frame, &encoded).unwrap(), frames);
        settlement_relays.push(encoded);

        let spend_entries: Vec<Vec<u8>> = (0..rng.below(4)).map(|_| rng.bytes(32)).collect();
        let encoded = spend_relay::encode_frame_entries(&spend_entries).unwrap();
        assert_eq!(spend_relay::decode_frame_entries(&encoded).unwrap(), spend_entries);
        spends.push(encoded);
        let mut frames: Vec<(u64, Vec<Vec<u8>>)> = Vec::new();
        for frame in spend_relay::relay_window(header_frame) {
            if rng.below(3) == 0 {
                frames.push((frame, vec![rng.bytes(32)]));
            }
        }
        let encoded = spend_relay::encode_relay(&frames).unwrap();
        assert_eq!(spend_relay::decode_relay(header_frame, &encoded).unwrap(), frames);
        spend_relays.push(encoded);

        let node = |rng: &mut Rng| Node::from_bytes(&Node::zero().to_bytes()).unwrap_or_else(|_| {
            let _ = rng.next();
            Node::zero()
        });
        let report = shard_accumulator::ShardReport {
            context: rng.array(),
            subtrees: (1..=1 + rng.below(3) as u8)
                .map(|i| shard_accumulator::SubtreeReport { width: 6 + i, coins: 1 + rng.next() % 1_000, root: node(&mut rng) })
                .collect(),
            attestations: Vec::new(),
        };
        let encoded = report.encode().unwrap();
        assert_eq!(shard_accumulator::ShardReport::decode(&encoded).unwrap(), report);
        assert_eq!(accumulator_header::report_digest(&encoded).len(), 32);
        reports.push(encoded);

        let mut summary = BlockSummary::default();
        for block in 0..rng.below(5) as u64 {
            summary.put(64 + block, 1 + rng.next() % 100, Node::zero()).unwrap();
        }
        let encoded = summary.encode();
        let decoded = BlockSummary::decode(&encoded).unwrap();
        assert_eq!(decoded.blocks.len(), summary.blocks.len());
        summaries.push(encoded);

        let level = rng.below(17) as u8;
        let blocks = 1 + rng.next() % (1u64 << level);
        let tree_node = TreeNode { coins: blocks + rng.next() % 1_000, blocks, node: node(&mut rng) };
        let encoded = tree_node.encode();
        assert_eq!(TreeNode::decode(&encoded, level).unwrap(), Some(tree_node));
        tree_nodes.push((level, encoded));
    }
    survives("settlement entries", &settlements, |bytes| { let _ = settlement_record::decode_entries(bytes); });
    survives("settlement relay", &settlement_relays, |bytes| { let _ = settlement_record::decode_relay(500, bytes); });
    survives("spend entries", &spends, |bytes| { let _ = spend_relay::decode_frame_entries(bytes); });
    survives("spend relay", &spend_relays, |bytes| { let _ = spend_relay::decode_relay(500, bytes); });
    survives("shard report", &reports, |bytes| {
        let _ = shard_accumulator::ShardReport::decode(bytes);
        let _ = accumulator_header::report_digest(bytes);
    });
    survives("block summary", &summaries, |bytes| { let _ = BlockSummary::decode(bytes); });
    for level in [0u8, 5, 16] {
        let encodings: Vec<Vec<u8>> = tree_nodes.iter().map(|(_, bytes)| bytes.clone()).collect();
        survives("summary tree node", &encodings, |bytes| { let _ = TreeNode::decode(bytes, level); });
    }
    let _ = NODE_BYTES;
}
