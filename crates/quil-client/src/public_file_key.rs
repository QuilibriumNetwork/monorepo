//! The public file key: one published sntrup761 keypair for files anyone
//! may read, such as collectible images (`qclient deploy file --public`).
//!
//! A vertex only validates sealed fields, so a public file is sealed like
//! any other (commitment, KEM ciphertext, AEAD ciphertext) and costs the
//! same; it is sealed to this key instead of the uploader's, and the secret
//! is published beside it, so every client opens it (`qclient deploy get`
//! tries it after the caller's own read key). The collectible "public read
//! key" in the token documentation is the retired verifiable-encryption
//! key, which sntrup761 sealing cannot use; this pair replaces it.

use quil_crypto::sntrup761::{SNTRUP761_PUBLIC_KEY_LEN, SNTRUP761_SECRET_KEY_LEN};

const PUBLIC_HEX: &str = include_str!("public_file_key.pk.hex");
const SECRET_HEX: &str = include_str!("public_file_key.sk.hex");

/// The public file key's sntrup761 public key (1158 bytes): seal to it.
pub fn public_key() -> anyhow::Result<Vec<u8>> {
    decode(PUBLIC_HEX, SNTRUP761_PUBLIC_KEY_LEN, "public")
}

/// The public file key's published sntrup761 secret key (1763 bytes): open
/// with it.
pub fn secret_key() -> anyhow::Result<Vec<u8>> {
    decode(SECRET_HEX, SNTRUP761_SECRET_KEY_LEN, "secret")
}

fn decode(text: &str, len: usize, which: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = hex::decode(text.trim_end())
        .map_err(|e| anyhow::anyhow!("public file key: {which} key is not hex: {e}"))?;
    if bytes.len() != len {
        anyhow::bail!(
            "public file key: {which} key has {} bytes, expected {len}",
            bytes.len()
        );
    }
    Ok(bytes)
}

#[cfg(test)]
pub(crate) mod tests {
    use quil_execution::hypergraph_intrinsic::confidential::{encode, seal};
    use quil_execution::hypergraph_intrinsic::vertex_ops::{
        encrypted_to_vertex_tree, vertex_tree_to_plaintext,
    };
    use sha2::{Digest, Sha256};

    use super::*;

    /// A serialized vertex tree (`GetVertexData{full_data}` form) of
    /// `parts`, each sealed to `reader_pk` as `deploy file` does.
    pub(crate) fn sealed_tree(reader_pk: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let chunks: Vec<Vec<u8>> = parts
            .iter()
            .enumerate()
            .map(|(i, p)| encode(&seal(p, reader_pk, &[i as u8; 32], &[i as u8; 12]).unwrap()))
            .collect();
        let mut tree = encrypted_to_vertex_tree(&chunks).unwrap();
        let _ = tree.commit(&quil_tries::ShaInclusionProver);
        quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()
    }

    /// The published pair, pinned: a changed byte would strand every public
    /// file already deployed.
    #[test]
    fn the_public_file_key_is_the_published_pair() {
        let public = public_key().unwrap();
        let secret = secret_key().unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&public)),
            "8f154930219f80e4511bfd5bfe79422760c09b11c0ef9ef3cbe33e1eda136db2",
            "public file key: public key is not the published one"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&secret)),
            "e2bf27604ecb7c71362486d15d06a3201b1abce354c36114544b0e91b30bb310",
            "public file key: secret key is not the published one"
        );
    }

    /// What is sealed to the public key opens with the published secret.
    #[test]
    fn the_public_file_key_opens_what_it_seals() {
        let public = public_key().unwrap();
        let secret = secret_key().unwrap();
        assert_eq!(public.len(), 1158);
        assert_eq!(secret.len(), 1763);
        let raw = sealed_tree(&public, &[b"public ", b"collectible"]);
        let opened = vertex_tree_to_plaintext(&raw, &secret);
        assert_eq!(
            opened.ok().as_deref(),
            Some(&b"public collectible"[..]),
            "public file key: the published secret does not open what the public key seals"
        );
    }

    #[test]
    fn a_malformed_key_is_refused_with_its_length() {
        let err = decode("00ff", SNTRUP761_PUBLIC_KEY_LEN, "public").unwrap_err();
        assert_eq!(
            err.to_string(),
            "public file key: public key has 2 bytes, expected 1158"
        );
        assert!(decode("zz", 1, "secret").is_err());
    }
}
