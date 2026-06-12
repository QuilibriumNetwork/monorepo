//! Consensus-layer canonical-bytes: AltShardUpdate (0x0319),
//! GlobalProposal (0x0317), AppShardProposal (0x0318),
//! QuorumCertificate (0x030D), TimeoutState (0x031C),
//! TimeoutCertificate (0x031D).

use quil_types::error::Result;
use crate::canonical_cursor::{
    put_u32, put_u64, put_lp, read_u32, read_u64, read_lp, expect_tp as expect,
};

pub const TYPE_ALT_SHARD_UPDATE: u32 = 0x0319;
pub const TYPE_GLOBAL_PROPOSAL: u32 = 0x0317;
pub const TYPE_APP_SHARD_PROPOSAL: u32 = 0x0318;
pub const TYPE_QUORUM_CERTIFICATE: u32 = 0x030D;
pub const TYPE_TIMEOUT_STATE: u32 = 0x031C;
pub const TYPE_TIMEOUT_CERTIFICATE: u32 = 0x031D;

// -- AltShardUpdate --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AltShardUpdate {
    pub public_key: Vec<u8>,
    pub frame_number: u64,
    pub vertex_adds_root: Vec<u8>,
    pub vertex_removes_root: Vec<u8>,
    pub hyperedge_adds_root: Vec<u8>,
    pub hyperedge_removes_root: Vec<u8>,
    pub signature: Vec<u8>,
}

impl AltShardUpdate {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_ALT_SHARD_UPDATE);
        put_lp(&mut out, &self.public_key);
        put_u64(&mut out, self.frame_number);
        put_lp(&mut out, &self.vertex_adds_root);
        put_lp(&mut out, &self.vertex_removes_root);
        put_lp(&mut out, &self.hyperedge_adds_root);
        put_lp(&mut out, &self.hyperedge_removes_root);
        put_lp(&mut out, &self.signature);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect(read_u32(data, &mut c)?, TYPE_ALT_SHARD_UPDATE, "AltShardUpdate")?;
        Ok(Self { public_key: read_lp(data, &mut c)?, frame_number: read_u64(data, &mut c)?, vertex_adds_root: read_lp(data, &mut c)?, vertex_removes_root: read_lp(data, &mut c)?, hyperedge_adds_root: read_lp(data, &mut c)?, hyperedge_removes_root: read_lp(data, &mut c)?, signature: read_lp(data, &mut c)? })
    }
}

// -- GlobalProposal --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GlobalProposal {
    pub state: Vec<u8>,
    pub parent_quorum_certificate: Vec<u8>,
    pub prior_rank_timeout_certificate: Vec<u8>,
    pub vote: Vec<u8>,
}

impl GlobalProposal {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_GLOBAL_PROPOSAL);
        put_lp(&mut out, &self.state);
        put_lp(&mut out, &self.parent_quorum_certificate);
        put_lp(&mut out, &self.prior_rank_timeout_certificate);
        put_lp(&mut out, &self.vote);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect(read_u32(data, &mut c)?, TYPE_GLOBAL_PROPOSAL, "GlobalProposal")?;
        Ok(Self { state: read_lp(data, &mut c)?, parent_quorum_certificate: read_lp(data, &mut c)?, prior_rank_timeout_certificate: read_lp(data, &mut c)?, vote: read_lp(data, &mut c)? })
    }
}

// -- AppShardProposal --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AppShardProposal {
    pub state: Vec<u8>,
    pub parent_quorum_certificate: Vec<u8>,
    pub prior_rank_timeout_certificate: Vec<u8>,
    pub vote: Vec<u8>,
}

impl AppShardProposal {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_APP_SHARD_PROPOSAL);
        put_lp(&mut out, &self.state);
        put_lp(&mut out, &self.parent_quorum_certificate);
        put_lp(&mut out, &self.prior_rank_timeout_certificate);
        put_lp(&mut out, &self.vote);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect(read_u32(data, &mut c)?, TYPE_APP_SHARD_PROPOSAL, "AppShardProposal")?;
        Ok(Self { state: read_lp(data, &mut c)?, parent_quorum_certificate: read_lp(data, &mut c)?, prior_rank_timeout_certificate: read_lp(data, &mut c)?, vote: read_lp(data, &mut c)? })
    }
}

// -- QuorumCertificate --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QuorumCertificate {
    pub filter: Vec<u8>,
    pub rank: u64,
    pub frame_number: u64,
    pub selector: Vec<u8>,
    pub timestamp: u64,
    pub aggregate_signature: Vec<u8>,
}

impl QuorumCertificate {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_QUORUM_CERTIFICATE);
        put_lp(&mut out, &self.filter);
        put_u64(&mut out, self.rank);
        put_u64(&mut out, self.frame_number);
        put_lp(&mut out, &self.selector);
        put_u64(&mut out, self.timestamp);
        put_lp(&mut out, &self.aggregate_signature);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect(read_u32(data, &mut c)?, TYPE_QUORUM_CERTIFICATE, "QuorumCertificate")?;
        Ok(Self { filter: read_lp(data, &mut c)?, rank: read_u64(data, &mut c)?, frame_number: read_u64(data, &mut c)?, selector: read_lp(data, &mut c)?, timestamp: read_u64(data, &mut c)?, aggregate_signature: read_lp(data, &mut c)? })
    }
}

// -- TimeoutState --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TimeoutState {
    pub latest_quorum_certificate: Vec<u8>,
    pub prior_rank_timeout_certificate: Vec<u8>,
    pub vote: Vec<u8>,
    pub timeout_tick: u64,
    pub timestamp: u64,
}

impl TimeoutState {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_TIMEOUT_STATE);
        put_lp(&mut out, &self.latest_quorum_certificate);
        put_lp(&mut out, &self.prior_rank_timeout_certificate);
        put_lp(&mut out, &self.vote);
        put_u64(&mut out, self.timeout_tick);
        put_u64(&mut out, self.timestamp);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect(read_u32(data, &mut c)?, TYPE_TIMEOUT_STATE, "TimeoutState")?;
        Ok(Self { latest_quorum_certificate: read_lp(data, &mut c)?, prior_rank_timeout_certificate: read_lp(data, &mut c)?, vote: read_lp(data, &mut c)?, timeout_tick: read_u64(data, &mut c)?, timestamp: read_u64(data, &mut c)? })
    }
}

// -- TimeoutCertificate --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TimeoutCertificate {
    pub filter: Vec<u8>,
    pub rank: u64,
    pub latest_ranks: Vec<u64>,
    pub latest_quorum_certificate: Vec<u8>,
    pub timestamp: u64,
    pub aggregate_signature: Vec<u8>,
}

impl TimeoutCertificate {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_TIMEOUT_CERTIFICATE);
        put_lp(&mut out, &self.filter);
        put_u64(&mut out, self.rank);
        put_u32(&mut out, self.latest_ranks.len() as u32);
        for &r in &self.latest_ranks { put_u64(&mut out, r); }
        put_lp(&mut out, &self.latest_quorum_certificate);
        put_u64(&mut out, self.timestamp);
        put_lp(&mut out, &self.aggregate_signature);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect(read_u32(data, &mut c)?, TYPE_TIMEOUT_CERTIFICATE, "TimeoutCertificate")?;
        let filter = read_lp(data, &mut c)?;
        let rank = read_u64(data, &mut c)?;
        let n = read_u32(data, &mut c)? as usize;
        let mut latest_ranks = Vec::with_capacity(n);
        for _ in 0..n { latest_ranks.push(read_u64(data, &mut c)?); }
        Ok(Self { filter, rank, latest_ranks, latest_quorum_certificate: read_lp(data, &mut c)?, timestamp: read_u64(data, &mut c)?, aggregate_signature: read_lp(data, &mut c)? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn alt_shard_update_round_trip() {
        let a = AltShardUpdate { public_key: vec![0xAAu8; 585], frame_number: 100, vertex_adds_root: vec![1u8; 64], vertex_removes_root: vec![2u8; 64], hyperedge_adds_root: vec![3u8; 64], hyperedge_removes_root: vec![4u8; 64], signature: vec![5u8; 74] };
        let b = a.to_canonical_bytes().unwrap();
        assert_eq!(AltShardUpdate::from_canonical_bytes(&b).unwrap(), a);
    }
    #[test] fn global_proposal_round_trip() {
        let p = GlobalProposal { state: vec![1u8; 100], parent_quorum_certificate: vec![2u8; 200], prior_rank_timeout_certificate: vec![], vote: vec![3u8; 74] };
        let b = p.to_canonical_bytes().unwrap();
        assert_eq!(GlobalProposal::from_canonical_bytes(&b).unwrap(), p);
    }
    #[test] fn app_shard_proposal_round_trip() {
        let p = AppShardProposal { state: vec![1u8; 50], parent_quorum_certificate: vec![2u8; 100], prior_rank_timeout_certificate: vec![3u8; 50], vote: vec![4u8; 74] };
        let b = p.to_canonical_bytes().unwrap();
        assert_eq!(AppShardProposal::from_canonical_bytes(&b).unwrap(), p);
    }
    #[test] fn quorum_certificate_round_trip() {
        let q = QuorumCertificate { filter: vec![0xAAu8; 32], rank: 5, frame_number: 100, selector: vec![0xBBu8; 32], timestamp: 9999, aggregate_signature: vec![0xCCu8; 74] };
        let b = q.to_canonical_bytes().unwrap();
        assert_eq!(QuorumCertificate::from_canonical_bytes(&b).unwrap(), q);
    }
    #[test] fn timeout_state_round_trip() {
        let t = TimeoutState { latest_quorum_certificate: vec![1u8; 100], prior_rank_timeout_certificate: vec![], vote: vec![2u8; 74], timeout_tick: 42, timestamp: 1234 };
        let b = t.to_canonical_bytes().unwrap();
        assert_eq!(TimeoutState::from_canonical_bytes(&b).unwrap(), t);
    }
    #[test] fn timeout_certificate_round_trip() {
        let t = TimeoutCertificate { filter: vec![0xAAu8; 32], rank: 3, latest_ranks: vec![1, 2, 3], latest_quorum_certificate: vec![0xBBu8; 100], timestamp: 5678, aggregate_signature: vec![0xCCu8; 74] };
        let b = t.to_canonical_bytes().unwrap();
        assert_eq!(TimeoutCertificate::from_canonical_bytes(&b).unwrap(), t);
    }
    #[test] fn all_empty_defaults_round_trip() {
        AltShardUpdate::from_canonical_bytes(&AltShardUpdate::default().to_canonical_bytes().unwrap()).unwrap();
        GlobalProposal::from_canonical_bytes(&GlobalProposal::default().to_canonical_bytes().unwrap()).unwrap();
        QuorumCertificate::from_canonical_bytes(&QuorumCertificate::default().to_canonical_bytes().unwrap()).unwrap();
        TimeoutState::from_canonical_bytes(&TimeoutState::default().to_canonical_bytes().unwrap()).unwrap();
        TimeoutCertificate::from_canonical_bytes(&TimeoutCertificate::default().to_canonical_bytes().unwrap()).unwrap();
    }
    #[test] fn type_prefixes_all_distinct() {
        use std::collections::HashSet;
        let ids: HashSet<u32> = [TYPE_ALT_SHARD_UPDATE, TYPE_GLOBAL_PROPOSAL, TYPE_APP_SHARD_PROPOSAL, TYPE_QUORUM_CERTIFICATE, TYPE_TIMEOUT_STATE, TYPE_TIMEOUT_CERTIFICATE].into_iter().collect();
        assert_eq!(ids.len(), 6);
    }
}
