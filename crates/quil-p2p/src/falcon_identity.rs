//! Falcon (FN-DSA-512) peer-identity derivation.
//!
//! The Rust-only network uses Falcon (libp2p `KeyType=5`) for the network
//! peer identity (the prover `q-prover-key`). Peer IDs are derived exactly as
//! libp2p does:
//! `PeerId = multihash(SHA2-256, protobuf(PublicKey{Type:5, Data:pubkey}))`,
//! because the 897-byte Falcon pubkey far exceeds the 42-byte inline threshold.
//!
//! This mirrors [`crate::ed448_identity::peer_id_from_ed448_pubkey`] for the
//! remote-peer case, where we hold a peer's Falcon public key (from its signed
//! `PeerInfo` / KeyRegistry entry) and must reproduce the peer-id the libp2p
//! transport presents. The `derives_the_same_peer_id_as_libp2p` test pins this
//! against libp2p's own `PublicKey::to_peer_id()`.
//!
//! The Ed448 key is retained separately as the seniority root; it no longer
//! derives the network peer-id.

use sha2::{Digest, Sha256};

/// libp2p `KeyType` wire value for Falcon (see `libp2p-identity` keys_proto).
const KEY_TYPE_FALCON: u8 = 5;

/// Falcon-512 public key length (bytes).
pub const FALCON_PUBLIC_KEY_LEN: usize = 897;

/// Append `value` to `out` as a protobuf base-128 varint.
fn push_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Derive the libp2p peer-id bytes (SHA2-256 multihash) from a Falcon public
/// key. Byte-identical to `Keypair::falcon_from_bytes(sk).public().to_peer_id()`.
pub fn peer_id_from_falcon_pubkey(public_key: &[u8]) -> Vec<u8> {
    // Protobuf-encode PublicKey{ Type(field 1)=5, Data(field 2)=pubkey }, in
    // field-number order (matches libp2p's quick-protobuf output).
    let mut proto = Vec::with_capacity(public_key.len() + 8);
    proto.push(0x08); // field 1 (Type), varint
    proto.push(KEY_TYPE_FALCON);
    proto.push(0x12); // field 2 (Data), length-delimited
    push_varint(public_key.len() as u64, &mut proto);
    proto.extend_from_slice(public_key);

    // SHA2-256 → multihash (code 0x12, length 0x20).
    let hash = Sha256::digest(&proto);
    let mut multihash = Vec::with_capacity(34);
    multihash.push(0x12); // SHA2-256 multihash code
    multihash.push(0x20); // digest length (32)
    multihash.extend_from_slice(&hash);
    multihash
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    #[test]
    fn derives_the_same_peer_id_as_libp2p() {
        // Generate a real Falcon keypair, take libp2p's own peer-id, and the
        // 897-byte pubkey (the trailing bytes of the protobuf encoding), then
        // confirm our independent derivation matches libp2p byte-for-byte.
        let kp = Keypair::generate_falcon();
        let libp2p_pid = kp.public().to_peer_id().to_bytes();

        let proto = kp.public().encode_protobuf();
        assert!(proto.len() > FALCON_PUBLIC_KEY_LEN);
        let pubkey = &proto[proto.len() - FALCON_PUBLIC_KEY_LEN..];

        assert_eq!(peer_id_from_falcon_pubkey(pubkey), libp2p_pid);
    }

    #[test]
    fn genesis_archive_peer_id_matches_offline_computation() {
        // Cross-check the offline (Python) peer-id derivation used to re-cut the
        // genesis archive_peers against the real Rust function, for one archive.
        let pub_hex = "0946ec03a6a56416954cd7542ba42d03c896d45f087c6498a4c35ac27434c89e43b7a2197aa5b8797c0c7e7ddc9b66aea695b1281d151aa4e30cc81048709bd19db6d1bba5a9b51a90edb6edcf1307c434d4fba4ed6b3c0e355b5d14a3a83bd1e317bba37452a4dcae76b7b858338966af2eb5d330c82a0f6e5411e561653a06c5472295dc1abee934174d15d942be762bdd5dc209ea2092162ddf11adb12b45a9d3935421baa1c2f5a3ac2f17d568b7bbaa2bb180ef1a318976caa7d828452cd6d51fd54bb079d1583829727e286490b11353045c84207258184f18e04242cda035b25a81a3838a08e8e6478b6f6b4c1a99c6e3a327ab6a7a91ce96f81a8df645d441645820f392842991adc1a1a9a056e549d636637897107c1d91c31bceec26449f12d2ec975a11a618c2c74cbbe49e906dd9e4b561c7e13160ff2ca5f3959d68112e75241aa5e84eac4c2f2525024720052a463e4b62035ecbb050c1947fc28d8952caef16c5b261125fca19048226fe59ac1342f0da3546dd99ded8133c205f2a82edc463c5875136f443e202c1b45e3c114a8679777c8e362d45d743ec5446db0c1c2e9d1985d61009582af36ba42f986ad17c923f981a014812d975462e70fd7e12c2c3126d70cf1443e4141b50ec448946741edeec2496d60580094c00459d8f3df13e52f4a14fa8fe9a818c8a8f9bbc68651fa42b787dd7e0fc64750a2932a123cce723293e36761c485f9c6280bfa1cc8f8aafc387d1c6bdc079b372817477985c0588eaaf507c2c808fd539a96178b5159eae3534c6c79258047609dc2a936cee25e9955bec000f1699ef5164e0dd01d4265bc4aa57b11435fa8b2481527ea1e75d8c013f5c1b98e0853f25455e74a68df6b2698d534b6178ac38db8487d0d39058b7935a0d2d0a9015e23961d023c9c36278497388015a40beaf12a0fcc08b3dc008a26c644361a42569e01dd687e19ab3a87ae0f1c3ca54f02f753ce36d59497999f7cc5006365d635a440e9cec0dc0812512b91982aa6d97ce847abbf5535e2e6ed2752018192f9f8aa69bfa12a450c9f4f79c519d35dc47b8ca06d853a40df7a5963e86f59515b542c49bfed2386106146ed01fd211cd8f2ed21ef78813d025508437e62a1a9c24042be109ed0960e1713aa5a332cd423151adc5885af454b2ac2f8b6c2f1958871391b8acb81a80df68b5571205955c4a003fba8984d772be6c9b6a9017bdb6d4020ede1abfd88951d99f4c39aa8f8408d367";
        let pub_bytes = hex::decode(pub_hex).unwrap();
        let pid = peer_id_from_falcon_pubkey(&pub_bytes);
        assert_eq!(
            bs58::encode(pid).into_string(),
            "QmRECrGL6yDoMgSydFDN5bhnnpJLAByKVuieAbwmmAiodC"
        );
    }

    #[test]
    fn varint_encodes_897() {
        let mut v = Vec::new();
        push_varint(897, &mut v);
        assert_eq!(v, vec![0x81, 0x07]);
    }
}
