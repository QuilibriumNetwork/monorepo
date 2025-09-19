use std::collections::HashMap;
use sha2::Sha512;
use hkdf::Hkdf;
use ed448_goldilocks_plus::{subtle, CompressedEdwardsY, EdwardsPoint, Scalar};
use lazy_static::lazy_static;

lazy_static! {
    static ref DOMAIN_SEPARATORS: HashMap<&'static str, Vec<u8>> = {
        let mut m = HashMap::new();
        m.insert("ed448", vec![
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF,
        ]);
        m
    };
}

pub fn sender_x3dh(
    sending_identity_private_key: &Scalar,
    sending_ephemeral_private_key: &Scalar,
    receiving_identity_key: &EdwardsPoint,
    receiving_signed_pre_key: &EdwardsPoint,
    session_key_length: u64,
) -> Option<Vec<u8>> {
    let xdh1 = (receiving_signed_pre_key * sending_identity_private_key).compress().to_bytes().to_vec();
    let xdh2 = (receiving_identity_key * sending_ephemeral_private_key).compress().to_bytes().to_vec();
    let xdh3 = (receiving_signed_pre_key * sending_ephemeral_private_key).compress().to_bytes().to_vec();

    let salt = vec![0u8; session_key_length as usize];
    let info = b"quilibrium-x3dh";

    let domain_separator = DOMAIN_SEPARATORS.get("ed448")
        .expect("Unsupported curve");

    let mut ikm = Vec::<u8>::new();
    ikm.extend(domain_separator);
    ikm.extend(xdh1);
    ikm.extend(xdh2);
    ikm.extend(xdh3);

    let hk = Hkdf::<Sha512>::new(Some(&salt), &ikm);
    let mut session_key = vec![0u8; session_key_length as usize];
    hk.expand(info, &mut session_key).ok()?;

    Some(session_key)
}

pub fn receiver_x3dh(
    sending_identity_private_key: &Scalar,
    sending_signed_pre_private_key: &Scalar,
    receiving_identity_key: &EdwardsPoint,
    receiving_ephemeral_key: &EdwardsPoint,
    session_key_length: u64,
) -> Option<Vec<u8>> {
    let xdh1 = (receiving_identity_key * sending_signed_pre_private_key).compress().to_bytes().to_vec();
    let xdh2 = (receiving_ephemeral_key * sending_identity_private_key).compress().to_bytes().to_vec();
    let xdh3 = (receiving_ephemeral_key * sending_signed_pre_private_key).compress().to_bytes().to_vec();

    let salt = vec![0u8; session_key_length as usize];
    let info = b"quilibrium-x3dh";

    let domain_separator = DOMAIN_SEPARATORS.get("ed448")
        .expect("Unsupported curve");

    let mut ikm = Vec::<u8>::new();
    ikm.extend(domain_separator);
    ikm.extend(xdh1);
    ikm.extend(xdh2);
    ikm.extend(xdh3);

    let hk = Hkdf::<Sha512>::new(Some(&salt), &ikm);
    let mut session_key = vec![0u8; session_key_length as usize];
    hk.expand(info, &mut session_key).ok()?;

    Some(session_key)
}