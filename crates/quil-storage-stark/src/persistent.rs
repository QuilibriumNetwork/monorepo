//! One-time final-label certification using the existing seal AIR.
//! Zero data makes the certified replica root a commitment to the final layer.
use quil_crypto::{
    persistent_storage as persistent,
    storage_proof::{SealProof, SealStatement},
};

pub fn prove(
    member: &[u8],
    leaf: &[u8],
    epoch: u64,
    n: u64,
    root: &persistent::Registration,
    beacon: &[u8],
    plain: &SealProof,
) -> Result<Vec<u8>, String> {
    let registered = root
        .certificate(n)
        .registered()
        .ok_or("invalid sector certificate")?;
    let beacon = persistent::certificate_beacon(member, leaf, epoch, n, root, beacon);
    let statement = SealStatement {
        member,
        leaf_id: &root.sector,
        epoch,
        n,
        registered,
        beacon: &beacon,
    };
    if quil_crypto::sdr::replica_key(member, &root.sector, epoch)
        != quil_crypto::sdr::stable_replica_key(member, &root.sector)
    {
        return Err("sector certification requires stable replica keys".into());
    }
    crate::seal::prove(
        &statement,
        &quil_crypto::sdr::SdrParams::for_profile(root.profile),
        persistent::CHALLENGES,
        plain,
    )
}

pub fn verify(
    member: &[u8],
    leaf: &[u8],
    epoch: u64,
    n: u64,
    root: &persistent::Registration,
    beacon: &[u8],
    bytes: &[u8],
) -> Result<(), String> {
    let registered = root
        .certificate(n)
        .registered()
        .ok_or("invalid sector certificate")?;
    let beacon = persistent::certificate_beacon(member, leaf, epoch, n, root, beacon);
    let statement = SealStatement {
        member,
        leaf_id: &root.sector,
        epoch,
        n,
        registered,
        beacon: &beacon,
    };
    if quil_crypto::sdr::replica_key(member, &root.sector, epoch)
        != quil_crypto::sdr::stable_replica_key(member, &root.sector)
    {
        return Err("sector certification requires stable replica keys".into());
    }
    crate::seal::verify(
        &statement,
        &quil_crypto::sdr::SdrParams::for_profile(root.profile),
        persistent::CHALLENGES,
        bytes,
    )
}
