//! Known-answer vectors. Every byte in `data/` except `draft-kat.hex` was frozen
//! once from `pqcrypto-ntruprime` 0.1.6 alone, before this crate existed:
//!
//! - `tuples.hex`: `seed pk sk ct ss`, the first 32 entries of the scheme's NIST
//!   KAT sequence (master entropy 0..47), each from a CTR-DRBG on its seed.
//! - `rejection.hex`: `label ct ss`, tampered ciphertexts against tuple 0's key.
//! - `malformed.hex`: `label ct ss`, non-canonical keys of the right length.
//! - `draft-kat.hex`: `seed pk sk ct ss`, KAT0 and KAT1 of
//!   draft-josefsson-ntruprime-streamlined-00, copied from the draft: independent
//!   of the backend, and reproduced here to the byte.
//! - `continuity.hex`: read by the application tests of the crates using the KEM.
//!
//! This binary defines `PQCRYPTO_RUST_randombytes` itself, so the linker never
//! pulls the backend's definition: every draw the C makes here comes from the
//! seeded DRBG below, which pins keygen and encapsulation to the byte.

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes256;
use pqcrypto_ntruprime::ffi;
use quil_sntrup761::{
    decapsulate, encapsulate, keypair, Ciphertext, Error, PublicKey, SecretKey, CIPHERTEXT_LEN,
    PUBLIC_KEY_LEN, SECRET_KEY_LEN, SHARED_SECRET_LEN,
};
use sha2::{Digest, Sha256, Sha512};
use std::ffi::c_int;
use std::sync::{Mutex, MutexGuard};

const TUPLES: &str = include_str!("data/tuples.hex");
const REJECTION: &str = include_str!("data/rejection.hex");
const MALFORMED: &str = include_str!("data/malformed.hex");
const DRAFT: &str = include_str!("data/draft-kat.hex");

/// `nistkat-sha256` from the backend's `META.yml`.
const NISTKAT_SHA256: &str = "afc42c3a5b10f4ef69654250097ebda9b9564570f4086744b24a6daf2bd1f89a";
/// The seed `malformed.hex` encapsulates from.
const MALFORMED_SEED: [u8; 48] = [0x77; 48];

/// The AES-256 CTR-DRBG of NIST's KAT generator, without derivation function.
struct Drbg {
    key: [u8; 32],
    v: [u8; 16],
}

impl Drbg {
    fn new(seed: &[u8]) -> Self {
        let mut drbg = Drbg {
            key: [0; 32],
            v: [0; 16],
        };
        drbg.update(Some(seed));
        drbg
    }

    fn block(&mut self) -> [u8; 16] {
        for byte in self.v.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        let mut out = GenericArray::default();
        Aes256::new(GenericArray::from_slice(&self.key))
            .encrypt_block_b2b(GenericArray::from_slice(&self.v), &mut out);
        out.into()
    }

    fn update(&mut self, data: Option<&[u8]>) {
        let mut tmp = [0; 48];
        for chunk in tmp.chunks_exact_mut(16) {
            chunk.copy_from_slice(&self.block());
        }
        if let Some(data) = data {
            tmp.iter_mut().zip(data).for_each(|(t, d)| *t ^= d);
        }
        self.key.copy_from_slice(&tmp[..32]);
        self.v.copy_from_slice(&tmp[32..]);
    }

    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(16) {
            chunk.copy_from_slice(&self.block()[..chunk.len()]);
        }
        self.update(None);
    }
}

/// The seeded state behind the interposed randomness.
struct Rng {
    drbg: Drbg,
    /// The draft's reference code draws each word of a `4 * p` buffer in its own
    /// call, and every DRBG call reseeds; the C here draws the buffer at once.
    word_by_word: bool,
}

/// `4 * p`, the buffer behind `Short_random` and `Small_random` in `kem.c`.
const WORD_BUFFER_LEN: usize = 4 * 761;

static RNG: Mutex<Option<Rng>> = Mutex::new(None);
/// Held for one seeded sequence: test threads must not interleave draws.
static SEQUENCE: Mutex<()> = Mutex::new(());

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Replaces the backend's system randomness in this test binary.
///
/// # Safety
/// `buf` must be valid for `len` bytes, as the C callers guarantee.
#[no_mangle]
pub unsafe extern "C" fn PQCRYPTO_RUST_randombytes(buf: *mut u8, len: usize) -> c_int {
    let out = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    let mut guard = lock(&RNG);
    let rng = guard
        .as_mut()
        .expect("an unseeded draw in the known-answer binary");
    if rng.word_by_word && len == WORD_BUFFER_LEN {
        out.chunks_mut(4).for_each(|word| rng.drbg.fill(word));
    } else {
        rng.drbg.fill(out);
    }
    0
}

fn with_rng<T>(seed: &[u8], word_by_word: bool, run: impl FnOnce() -> T) -> T {
    let _sequence = lock(&SEQUENCE);
    *lock(&RNG) = Some(Rng {
        drbg: Drbg::new(seed),
        word_by_word,
    });
    run()
}

fn with_seed<T>(seed: &[u8], run: impl FnOnce() -> T) -> T {
    with_rng(seed, false, run)
}

/// One way into the scheme: the seam (AVX2 chosen at run time) or a C path.
struct Path {
    name: &'static str,
    keypair: fn() -> (Vec<u8>, Vec<u8>),
    /// Returns `(ct, ss)`.
    encapsulate: fn(&[u8]) -> (Vec<u8>, Vec<u8>),
    /// Takes `(ct, sk)`.
    decapsulate: fn(&[u8], &[u8]) -> Vec<u8>,
}

macro_rules! c_path {
    ($name:literal, $keypair:ident, $enc:ident, $dec:ident) => {
        Path {
            name: $name,
            keypair: || {
                let (mut pk, mut sk) = (vec![0; PUBLIC_KEY_LEN], vec![0; SECRET_KEY_LEN]);
                let rc = unsafe { ffi::$keypair(pk.as_mut_ptr(), sk.as_mut_ptr()) };
                assert_eq!(rc, 0);
                (pk, sk)
            },
            encapsulate: |pk| {
                assert_eq!(pk.len(), PUBLIC_KEY_LEN);
                let (mut ct, mut ss) = (vec![0; CIPHERTEXT_LEN], vec![0; SHARED_SECRET_LEN]);
                let rc = unsafe { ffi::$enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr()) };
                assert_eq!(rc, 0);
                (ct, ss)
            },
            decapsulate: |ct, sk| {
                assert_eq!((ct.len(), sk.len()), (CIPHERTEXT_LEN, SECRET_KEY_LEN));
                let mut ss = vec![0; SHARED_SECRET_LEN];
                let rc = unsafe { ffi::$dec(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr()) };
                assert_eq!(rc, 0);
                ss
            },
        }
    };
}

fn paths() -> Vec<Path> {
    let mut paths = vec![
        Path {
            name: "seam",
            keypair: || {
                let (pk, sk) = keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            },
            encapsulate: |pk| {
                let (ss, ct) = encapsulate(&PublicKey::from_bytes(pk).unwrap());
                (ct.as_bytes().to_vec(), ss.as_bytes().to_vec())
            },
            decapsulate: |ct, sk| {
                decapsulate(
                    &Ciphertext::from_bytes(ct).unwrap(),
                    &SecretKey::from_bytes(sk).unwrap(),
                )
                .as_bytes()
                .to_vec()
            },
        },
        c_path!(
            "clean",
            PQCLEAN_SNTRUP761_CLEAN_crypto_kem_keypair,
            PQCLEAN_SNTRUP761_CLEAN_crypto_kem_enc,
            PQCLEAN_SNTRUP761_CLEAN_crypto_kem_dec
        ),
    ];
    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        paths.push(c_path!(
            "avx2",
            PQCLEAN_SNTRUP761_AVX2_crypto_kem_keypair,
            PQCLEAN_SNTRUP761_AVX2_crypto_kem_enc,
            PQCLEAN_SNTRUP761_AVX2_crypto_kem_dec
        ));
    }
    paths
}

/// Decodes one line of hex fields; `-` is an empty field.
fn fields(line: &str) -> Vec<Vec<u8>> {
    line.split(' ')
        .map(|field| match field {
            "-" => Vec::new(),
            hex_field => hex::decode(hex_field).unwrap(),
        })
        .collect()
}

/// Lines of `label hex hex`.
fn labelled(table: &'static str) -> Vec<(&'static str, Vec<u8>, Vec<u8>)> {
    table
        .lines()
        .map(|line| {
            let (label, rest) = line.split_once(' ').unwrap();
            let mut row = fields(rest);
            let ss = row.pop().unwrap();
            (label, row.pop().unwrap(), ss)
        })
        .collect()
}

struct Tuple {
    seed: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<u8>,
    ct: Vec<u8>,
    ss: Vec<u8>,
}

fn tuples(table: &str) -> Vec<Tuple> {
    table
        .lines()
        .map(|line| {
            let mut row = fields(line).into_iter();
            let mut next = || row.next().unwrap();
            Tuple {
                seed: next(),
                pk: next(),
                sk: next(),
                ct: next(),
                ss: next(),
            }
        })
        .collect()
}

fn reproduce(tuple: &Tuple, path: &Path, word_by_word: bool, what: &str) {
    let (pk, sk, ct, ss) = with_rng(&tuple.seed, word_by_word, || {
        let (pk, sk) = (path.keypair)();
        let (ct, ss) = (path.encapsulate)(&pk);
        (pk, sk, ct, ss)
    });
    assert_eq!(pk, tuple.pk, "{what} {}: public key", path.name);
    assert_eq!(sk, tuple.sk, "{what} {}: secret key", path.name);
    assert_eq!(ct, tuple.ct, "{what} {}: ciphertext", path.name);
    assert_eq!(ss, tuple.ss, "{what} {}: shared secret", path.name);
}

/// Vector 1: what the old backend sealed still opens, on every path.
#[test]
fn old_tuples_decapsulate_on_every_path() {
    let tuples = tuples(TUPLES);
    assert_eq!(tuples.len(), 32);
    for (i, tuple) in tuples.iter().enumerate() {
        for path in paths() {
            assert_eq!(
                (path.decapsulate)(&tuple.ct, &tuple.sk),
                tuple.ss,
                "tuple {i} on {}",
                path.name
            );
        }
    }
}

/// From a fixed seed keygen and encapsulation give the old backend's bytes.
#[test]
fn seeded_keygen_and_encapsulation_reproduce_old_tuples() {
    for (i, tuple) in tuples(TUPLES).iter().enumerate() {
        for path in paths() {
            reproduce(tuple, &path, false, &format!("tuple {i}"));
        }
    }
}

/// Vector 3: a tampered ciphertext gives the frozen unrelated secret.
#[test]
fn implicit_rejection_outputs_are_frozen() {
    let tuples = tuples(TUPLES);
    let genuine = &tuples[0];
    let cases = labelled(REJECTION);
    assert_eq!(cases.len(), 6);
    for (label, ct, ss) in cases {
        assert_ne!(ss, genuine.ss, "{label}: must not be the sender's secret");
        for path in paths() {
            assert_eq!(
                (path.decapsulate)(&ct, &genuine.sk),
                ss,
                "{label} on {}",
                path.name
            );
        }
    }
}

/// Vector 4: non-canonical keys of the right length are not errors or panics,
/// and their outputs are frozen too.
#[test]
fn non_canonical_keys_give_the_frozen_outputs() {
    let tuples = tuples(TUPLES);
    let mut seen = 0;
    for (label, ct, ss) in labelled(MALFORMED) {
        let fill = if label.ends_with("all_ff") { 0xff } else { 0 };
        for path in paths() {
            if label.starts_with("pk") {
                let pk = vec![fill; PUBLIC_KEY_LEN];
                let (got_ct, got_ss) = with_seed(&MALFORMED_SEED, || (path.encapsulate)(&pk));
                assert_eq!(got_ct, ct, "{label} on {}", path.name);
                assert_eq!(got_ss, ss, "{label} on {}", path.name);
            } else {
                let sk = vec![fill; SECRET_KEY_LEN];
                assert_eq!(
                    (path.decapsulate)(&tuples[0].ct, &sk),
                    ss,
                    "{label} on {}",
                    path.name
                );
            }
        }
        seen += 1;
    }
    assert_eq!(seen, 4);
}

/// Vector 4: wrong lengths are errors naming the input, never panics.
#[test]
fn wrong_lengths_are_errors() {
    let bad = |name, actual, expected| {
        Some(Error::BadLength {
            name,
            actual,
            expected,
        })
    };
    for actual in [0, PUBLIC_KEY_LEN - 1, PUBLIC_KEY_LEN + 1] {
        assert_eq!(
            PublicKey::from_bytes(&vec![0; actual]).err(),
            bad("PublicKey", actual, PUBLIC_KEY_LEN)
        );
    }
    for actual in [0, SECRET_KEY_LEN - 1, SECRET_KEY_LEN + 1] {
        assert_eq!(
            SecretKey::from_bytes(&vec![0; actual]).err(),
            bad("SecretKey", actual, SECRET_KEY_LEN)
        );
    }
    for actual in [0, CIPHERTEXT_LEN - 1, CIPHERTEXT_LEN + 1] {
        assert_eq!(
            Ciphertext::from_bytes(&vec![0; actual]).err(),
            bad("Ciphertext", actual, CIPHERTEXT_LEN)
        );
    }
    assert!(PublicKey::from_bytes(&[0; PUBLIC_KEY_LEN]).is_ok());
    assert!(SecretKey::from_bytes(&[0; SECRET_KEY_LEN]).is_ok());
    assert!(Ciphertext::from_bytes(&[0; CIPHERTEXT_LEN]).is_ok());
}

/// Vector 5: the secret key embeds the public key and its hash, per `kem.c`.
#[test]
fn secret_key_layout_holds() {
    let mut keys: Vec<(Vec<u8>, Vec<u8>)> = tuples(TUPLES)
        .into_iter()
        .map(|tuple| (tuple.pk, tuple.sk))
        .collect();
    for path in paths() {
        keys.push(with_seed(&[0x5a; 48], path.keypair));
    }
    for (i, (pk, sk)) in keys.iter().enumerate() {
        assert_eq!(&sk[382..1540], &pk[..], "key {i}: embedded public key");
        let mut hash = Sha512::new();
        hash.update([4]);
        hash.update(pk);
        assert_eq!(
            &sk[1731..],
            &hash.finalize()[..32],
            "key {i}: public-key hash"
        );
    }
}

/// Vector 6: the draft's published vectors, on every path.
#[test]
fn draft_vectors_reproduce() {
    let tuples = tuples(DRAFT);
    assert_eq!(tuples.len(), 2);
    for (i, tuple) in tuples.iter().enumerate() {
        for path in paths() {
            reproduce(tuple, &path, true, &format!("KAT{i}"));
            assert_eq!((path.decapsulate)(&tuple.ct, &tuple.sk), tuple.ss);
        }
    }
    // The published sequence, not only its entries: tuple i's seed is the
    // master DRBG's i-th 48 bytes.
    let entropy: Vec<u8> = (0..48).collect();
    let mut master = Drbg::new(&entropy);
    for tuple in &tuples {
        let mut seed = [0; 48];
        master.fill(&mut seed);
        assert_eq!(seed[..], tuple.seed[..]);
    }
}

/// Vector 6: the digest PQClean publishes over its one-entry KAT transcript.
#[test]
fn nistkat_digest_matches_published() {
    let entropy: Vec<u8> = (0..48).collect();
    let mut seed = [0; 48];
    Drbg::new(&entropy).fill(&mut seed);
    for path in paths() {
        let (pk, sk, ct, ss) = with_seed(&seed, || {
            let (pk, sk) = (path.keypair)();
            let (ct, ss) = (path.encapsulate)(&pk);
            (pk, sk, ct, ss)
        });
        let transcript = format!(
            "count = 0\nseed = {}\npk = {}\nsk = {}\nct = {}\nss = {}\n",
            hex::encode_upper(seed),
            hex::encode_upper(&pk),
            hex::encode_upper(&sk),
            hex::encode_upper(&ct),
            hex::encode_upper(&ss),
        );
        assert_eq!(
            hex::encode(Sha256::digest(transcript)),
            NISTKAT_SHA256,
            "{}",
            path.name
        );
    }
}
