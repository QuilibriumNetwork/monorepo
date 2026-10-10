use base64::prelude::*;
use std::{collections::HashMap, io::Read};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use ed448_goldilocks_plus::{elliptic_curve::{group::GroupEncoding, Field, Group}, subtle::ConstantTimeEq, EdwardsPoint, Scalar};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FeldmanError {
    #[error("Wrong round for Feldman operation")]
    WrongRound,
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("Crypto error: {0}")]
    CryptoError(String),
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum FeldmanRound {
    Uninitialized,
    Initialized,
    Committed,
    Revealed,
    Reconstructed,
}

#[derive(Debug, Clone)]
pub struct Feldman {
    threshold: usize,
    total: usize,
    id: usize,
    frags_for_counterparties: HashMap<usize, Vec<u8>>,
    frags_from_counterparties: HashMap<usize, Scalar>,
    zkpok: Option<Scalar>,
    secret: Scalar,
    scalar: Option<Scalar>,
    generator: EdwardsPoint,
    public_key: EdwardsPoint,
    point: EdwardsPoint,
    random_commitment_point: Option<EdwardsPoint>,
    round: FeldmanRound,
    zkcommits_from_counterparties: HashMap<usize, Vec<u8>>,
    points_from_counterparties: HashMap<usize, EdwardsPoint>,
    /// Our polynomial's Feldman coefficient commitments `C_j = generator * a_j`
    /// (j = 0..threshold), published alongside each fragment so a receiver can
    /// verify the fragment lies on our committed polynomial. Public (not secret).
    commitments: Vec<EdwardsPoint>,
    /// Each counterparty's published coefficient commitments, used to verify the
    /// fragment they send us against their committed polynomial.
    commitments_from_counterparties: HashMap<usize, Vec<EdwardsPoint>>,
}

#[derive(Serialize, Deserialize)]
pub struct FeldmanJson {
    threshold: usize,
    total: usize,
    id: usize,
    frags_for_counterparties: HashMap<usize, String>,
    frags_from_counterparties: HashMap<usize, String>,
    zkpok: Option<String>,
    secret: String,
    scalar: Option<String>,
    generator: String,
    public_key: String,
    point: String,
    random_commitment_point: Option<String>,
    round: usize,
    zkcommits_from_counterparties: HashMap<usize, String>,
    points_from_counterparties: HashMap<usize, String>,
    #[serde(default)]
    commitments: Vec<String>,
    #[serde(default)]
    commitments_from_counterparties: HashMap<usize, Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct FeldmanReveal {
    point: Vec<u8>,
    random_commitment_point: Vec<u8>,
    zk_pok: Vec<u8>,
}

/// Wire payload for one peer's polynomial fragment: the scalar share plus the
/// dealer's Feldman coefficient commitments, so the receiver can verify the
/// share lies on the dealer's committed polynomial (Feldman VSS check).
#[derive(Serialize, Deserialize)]
pub struct FeldmanFrag {
    pub frag: Vec<u8>,
    pub commitments: Vec<Vec<u8>>,
}

pub fn vec_to_array<const N: usize>(v: Vec<u8>) -> Result<[u8; N], Box<dyn std::error::Error>> {
  if v.len() != N {
      return Err(format!("Invalid length: expected {}, got {}", N, v.len()).into());
  }
  
  let mut arr: [u8; N] = [0u8; N];
  arr.copy_from_slice(&v);
  Ok(arr)
}

/// Wipe the secret share and intermediate scalars on drop. The public
/// points / commitments are not secret and are left alone.
impl Drop for Feldman {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
        if let Some(s) = self.scalar.as_mut() { s.zeroize(); }
        if let Some(z) = self.zkpok.as_mut() { z.zeroize(); }
        for v in self.frags_for_counterparties.values_mut() { v.zeroize(); }
        for s in self.frags_from_counterparties.values_mut() { s.zeroize(); }
    }
}

impl Feldman {
    pub fn new(
        threshold: usize,
        total: usize,
        id: usize,
        secret: Scalar,
        generator: EdwardsPoint,
    ) -> Self {
        Feldman {
            threshold,
            total,
            id,
            frags_for_counterparties: HashMap::new(),
            frags_from_counterparties: HashMap::new(),
            zkpok: None,
            secret,
            scalar: None,
            generator,
            public_key: EdwardsPoint::generator(),
            point: EdwardsPoint::generator(),
            random_commitment_point: None,
            round: FeldmanRound::Uninitialized,
            zkcommits_from_counterparties: HashMap::new(),
            points_from_counterparties: HashMap::new(),
            commitments: Vec::new(),
            commitments_from_counterparties: HashMap::new(),
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let feldman_json = FeldmanJson {
            threshold: self.threshold,
            total: self.total,
            id: self.id,
            frags_for_counterparties: self.frags_for_counterparties.iter()
                .map(|(&k, v)| (k, BASE64_STANDARD.encode(v)))
                .collect(),
            frags_from_counterparties: self.frags_from_counterparties.iter()
                .map(|(&k, v)| (k, BASE64_STANDARD.encode(v.to_bytes())))
                .collect(),
            zkpok: self.zkpok.as_ref().map(|s| BASE64_STANDARD.encode(s.to_bytes())),
            secret: BASE64_STANDARD.encode(self.secret.to_bytes()),
            scalar: self.scalar.as_ref().map(|s| BASE64_STANDARD.encode(s.to_bytes())),
            generator: BASE64_STANDARD.encode(self.generator.compress().to_bytes()),
            public_key: BASE64_STANDARD.encode(self.public_key.compress().to_bytes()),
            point: BASE64_STANDARD.encode(self.point.compress().to_bytes()),
            random_commitment_point: self.random_commitment_point.as_ref()
                .map(|p| BASE64_STANDARD.encode(p.compress().to_bytes())),
            round: self.round as usize,
            zkcommits_from_counterparties: self.zkcommits_from_counterparties.iter()
                .map(|(&k, v)| (k, BASE64_STANDARD.encode(v)))
                .collect(),
            points_from_counterparties: self.points_from_counterparties.iter()
                .map(|(&k, v)| (k, BASE64_STANDARD.encode(v.compress().to_bytes())))
                .collect(),
            commitments: self.commitments.iter()
                .map(|c| BASE64_STANDARD.encode(c.compress().to_bytes()))
                .collect(),
            commitments_from_counterparties: self.commitments_from_counterparties.iter()
                .map(|(&k, v)| (k, v.iter().map(|c| BASE64_STANDARD.encode(c.compress().to_bytes())).collect()))
                .collect(),
        };

        serde_json::to_string(&feldman_json)
    }

    pub fn from_json(json: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let feldman_json: FeldmanJson = serde_json::from_str(json)?;

        let frags_for_counterparties = feldman_json.frags_for_counterparties.into_iter()
            .map(|(k, v)| Ok((k, BASE64_STANDARD.decode(v)?)))
            .collect::<Result<HashMap<_, _>, Box<dyn std::error::Error>>>()?;

        let frags_from_counterparties = feldman_json.frags_from_counterparties.into_iter()
            .map(|(k, v)| {
                let bytes = BASE64_STANDARD.decode(v)?;
                Ok((k, Scalar::from_bytes(&vec_to_array::<56>(bytes)?)))
            })
            .collect::<Result<HashMap<_, _>, Box<dyn std::error::Error>>>()?;

        let mut zkpok: Option<Scalar> = None;
        if feldman_json.zkpok.is_some() {
            let bytes = BASE64_STANDARD.decode(feldman_json.zkpok.unwrap())?;
            zkpok = Some(Scalar::from_bytes(&vec_to_array::<56>(bytes)?));
        }

        let secret_bytes = BASE64_STANDARD.decode(feldman_json.secret)?;
        let secret = Scalar::from_bytes(&vec_to_array::<56>(secret_bytes)?);

        let mut scalar: Option<Scalar> = None;
        if feldman_json.scalar.is_some() {
            let bytes = BASE64_STANDARD.decode(feldman_json.scalar.unwrap())?;
            scalar = Some(Scalar::from_bytes(&vec_to_array::<56>(bytes)?));
        }

        let generator_bytes = BASE64_STANDARD.decode(feldman_json.generator)?;
        let generator = EdwardsPoint::from_bytes(&vec_to_array::<57>(generator_bytes)?.into()).into_option().ok_or_else(|| FeldmanError::InvalidData("invalid data".into()))?;

        let public_key_bytes = BASE64_STANDARD.decode(feldman_json.public_key)?;
        let public_key = EdwardsPoint::from_bytes(&vec_to_array::<57>(public_key_bytes)?.into()).into_option().ok_or_else(|| FeldmanError::InvalidData("invalid data".into()))?;

        let point_bytes = BASE64_STANDARD.decode(feldman_json.point)?;
        let point = EdwardsPoint::from_bytes(&vec_to_array::<57>(point_bytes)?.into()).into_option().ok_or_else(|| FeldmanError::InvalidData("invalid data".into()))?;

        let mut random_commitment_point: Option<EdwardsPoint> = None;
        if feldman_json.random_commitment_point.is_some() {
            let bytes = BASE64_STANDARD.decode(feldman_json.random_commitment_point.unwrap())?;
            random_commitment_point = Some(EdwardsPoint::from_bytes(&vec_to_array::<57>(bytes)?.into()).into_option().ok_or_else(|| FeldmanError::InvalidData("invalid data".into()))?);
        }

        let zkcommits_from_counterparties = feldman_json.zkcommits_from_counterparties.into_iter()
            .map(|(k, v)| Ok((k, BASE64_STANDARD.decode(v)?)))
            .collect::<Result<HashMap<_, _>, Box<dyn std::error::Error>>>()?;

        let points_from_counterparties = feldman_json.points_from_counterparties.into_iter()
            .map(|(k, v)| {
                Ok((k, EdwardsPoint::from_bytes(&vec_to_array::<57>(BASE64_STANDARD.decode(v)?)?.into()).into_option().ok_or_else(|| FeldmanError::InvalidData("invalid data".into()))?))
            })
            .collect::<Result<HashMap<_, _>, Box<dyn std::error::Error>>>()?;

        Ok(Feldman {
            threshold: feldman_json.threshold,
            total: feldman_json.total,
            id: feldman_json.id,
            frags_for_counterparties,
            frags_from_counterparties,
            zkpok,
            secret,
            scalar,
            generator,
            public_key,
            point,
            random_commitment_point,
            round: match feldman_json.round {
              0 => FeldmanRound::Uninitialized,
              1 => FeldmanRound::Initialized,
              2 => FeldmanRound::Committed,
              3 => FeldmanRound::Revealed,
              4 => FeldmanRound::Reconstructed,
              _ => FeldmanRound::Uninitialized,
            },
            zkcommits_from_counterparties,
            points_from_counterparties,
            commitments: feldman_json.commitments.into_iter()
                .map(|c| {
                    EdwardsPoint::from_bytes(&vec_to_array::<57>(BASE64_STANDARD.decode(c)?)?.into())
                        .into_option()
                        .ok_or_else(|| FeldmanError::InvalidData("invalid commitment".into()).into())
                })
                .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?,
            commitments_from_counterparties: feldman_json.commitments_from_counterparties.into_iter()
                .map(|(k, v)| {
                    let pts = v.into_iter()
                        .map(|c| {
                            EdwardsPoint::from_bytes(&vec_to_array::<57>(BASE64_STANDARD.decode(c)?)?.into())
                                .into_option()
                                .ok_or_else(|| FeldmanError::InvalidData("invalid commitment".into()).into())
                        })
                        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
                    Ok((k, pts))
                })
                .collect::<Result<HashMap<_, _>, Box<dyn std::error::Error>>>()?,
        })
    }

    pub fn set_id(&mut self, id: usize) {
      self.id = id;
    }

    pub fn sample_polynomial<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<(), FeldmanError> {
        if self.round != FeldmanRound::Uninitialized {
            return Err(FeldmanError::WrongRound);
        }

        let (samples, coeffs) =
            Feldman::construct_polynomial_samples(rng, self.secret, self.threshold, self.total);

        // Feldman commitments to each coefficient: C_j = generator * a_j.
        // Published with our fragments so receivers can verify their share lies
        // on this committed polynomial.
        self.commitments = coeffs.iter().map(|a| self.generator * a).collect();

        for i in 1..=self.total {
            if i == self.id {
                self.scalar = Some(samples[i-1]);
            } else {
                self.frags_for_counterparties.insert(i, samples[i-1].to_bytes().to_vec());
            }
        }

        self.round = FeldmanRound::Initialized;
        Ok(())
    }

    fn construct_polynomial_samples<R: RngCore + CryptoRng>(rng: &mut R, secret: Scalar, threshold: usize, total: usize) -> (Vec<Scalar>, Vec<Scalar>) {
        let mut coeffs = vec![secret];

        for _ in 1..threshold {
            coeffs.push(Scalar::random(rng));
        }

        let mut samples = Vec::<Scalar>::new();
        for i in 1..=total {
            let mut result = coeffs[0];
            let _x = Scalar::from(i as u32);

            for j in 1..threshold {
                let term = coeffs[j] * Scalar::from(i.pow(j as u32) as u32);
                result += term;
            }

            samples.push(result);
        }

        (samples, coeffs)
    }

    /// Our published Feldman coefficient commitments (compressed Edwards point
    /// bytes), to be broadcast with each fragment. Available once the polynomial
    /// has been sampled.
    pub fn get_commitments(&self) -> Result<Vec<Vec<u8>>, FeldmanError> {
        if self.round == FeldmanRound::Uninitialized {
            return Err(FeldmanError::WrongRound);
        }
        Ok(self.commitments.iter().map(|c| c.compress().to_bytes().to_vec()).collect())
    }

    /// Verify a counterparty fragment `f(self.id)` lies on the polynomial the
    /// counterparty committed to: `generator * frag == Σ_j (self.id^j * C_j)`.
    /// This is the Feldman VSS share check — without it a malicious dealer can
    /// hand out a share inconsistent with its commitments and silently bias the
    /// shared secret. `commitments` are the dealer's `get_commitments()` bytes.
    fn verify_frag_against_commitments(
        &self,
        frag: &Scalar,
        commitments: &[EdwardsPoint],
    ) -> bool {
        if commitments.len() != self.threshold {
            return false;
        }
        // Σ_j C_j * (self.id)^j, with the exponent computed exactly as the
        // dealer did in `construct_polynomial_samples` (i.pow(j) as u32).
        let mut expected = commitments[0];
        for j in 1..commitments.len() {
            let exp = Scalar::from(self.id.pow(j as u32) as u32);
            expected += commitments[j] * exp;
        }
        let lhs = self.generator * frag;
        lhs.ct_eq(&expected).into()
    }
    
    pub fn scalar(&self) -> Option<&Scalar> {
        self.scalar.as_ref()
    }

    pub fn get_poly_frags(&self) -> Result<&HashMap<usize, Vec<u8>>, FeldmanError> {
        if self.round != FeldmanRound::Initialized {
            return Err(FeldmanError::WrongRound);
        }
        Ok(&self.frags_for_counterparties)
    }

    pub fn set_poly_frag_for_party(
        &mut self,
        id: usize,
        frag: &[u8],
        commitments: &[Vec<u8>],
    ) -> Result<Option<Vec<u8>>, FeldmanError> {
        if self.round != FeldmanRound::Initialized {
            return Err(FeldmanError::WrongRound);
        }

        let frag_arr: [u8; 56] = frag.try_into()
            .map_err(|_| FeldmanError::InvalidData("fragment must be 56 bytes".into()))?;
        let scalar = Scalar::from_bytes(&frag_arr);

        // Feldman VSS share check: the fragment must lie on the dealer's
        // committed polynomial. Reject an inconsistent share rather than fold it
        // into our combined secret (a malicious dealer would otherwise bias the
        // group key). Decode + retain the dealer's commitments for the record.
        let decoded: Vec<EdwardsPoint> = commitments.iter()
            .map(|c| {
                let arr = vec_to_array::<57>(c.clone())
                    .map_err(|_| FeldmanError::InvalidData("commitment must be 57 bytes".into()))?;
                EdwardsPoint::from_bytes(&arr.into())
                    .into_option()
                    .ok_or_else(|| FeldmanError::InvalidData("invalid commitment point".into()))
            })
            .collect::<Result<Vec<_>, FeldmanError>>()?;
        if !self.verify_frag_against_commitments(&scalar, &decoded) {
            return Err(FeldmanError::InvalidData(
                "fragment inconsistent with dealer commitments (Feldman VSS check failed)".into(),
            ));
        }
        self.commitments_from_counterparties.insert(id, decoded);

        self.frags_from_counterparties.insert(id, scalar);

        if self.frags_from_counterparties.len() == self.total - 1 {
            let mut combined_scalar = self.scalar.unwrap_or_else(|| Scalar::ZERO);
            for scalar in self.frags_from_counterparties.values() {
                combined_scalar += *scalar;
            }
            self.scalar = Some(combined_scalar);

            self.point = self.generator * combined_scalar;

            let rand_commitment = Scalar::random(&mut rand::thread_rng());
            self.random_commitment_point = Some(self.generator * rand_commitment);

            let random_commitment_point_bytes = self.random_commitment_point.unwrap().compress().to_bytes();
            let public_point_bytes = self.point.compress().to_bytes();

            let mut hasher = Sha512::new();
            hasher.update(&public_point_bytes);
            hasher.update(&random_commitment_point_bytes);
            let challenge = hasher.finalize();

            let challenge_scalar = Scalar::from_bytes(challenge[..56].try_into().unwrap());

            self.zkpok = Some(combined_scalar * challenge_scalar + rand_commitment);

            let zkpok_bytes = self.zkpok.unwrap().to_bytes();
            let mut hasher = Sha512::new();
            hasher.update(&random_commitment_point_bytes);
            hasher.update(&zkpok_bytes);
            let zkcommit = hasher.finalize();

            self.round = FeldmanRound::Committed;
            return Ok(Some(zkcommit[..56].to_vec()));
        }

        Ok(None)
    }

    pub fn receive_commitments(&mut self, id: usize, zkcommit: &[u8]) -> Result<Option<FeldmanReveal>, FeldmanError> {
        if self.round != FeldmanRound::Committed {
            return Err(FeldmanError::WrongRound);
        }

        self.zkcommits_from_counterparties.insert(id, zkcommit.to_vec());

        if self.zkcommits_from_counterparties.len() == self.total - 1 {
            let public_point_bytes = self.point.compress().to_bytes();
            let random_commitment_point_bytes = self.random_commitment_point.unwrap().compress().to_bytes();
            self.round = FeldmanRound::Revealed;
            let zkpok_bytes = self.zkpok.unwrap().to_bytes();

            return Ok(Some(FeldmanReveal {
                point: public_point_bytes.to_vec(),
                random_commitment_point: random_commitment_point_bytes.to_vec(),
                zk_pok: zkpok_bytes.to_vec(),
            }));
        }

        Ok(None)
    }

    pub fn recombine(&mut self, id: usize, reveal: &FeldmanReveal) -> Result<bool, FeldmanError> {
        if self.round != FeldmanRound::Revealed {
            return Err(FeldmanError::WrongRound);
        }

        let counterparty_point = EdwardsPoint::from_bytes(reveal.point.as_slice().into()).unwrap();

        if counterparty_point.eq(&EdwardsPoint::generator()).into() || counterparty_point == self.generator {
            return Err(FeldmanError::InvalidData("Counterparty sent generator".into()));
        }

        let counterparty_random_commitment_point = EdwardsPoint::from_bytes(reveal.random_commitment_point.as_slice().into()).unwrap();

        if counterparty_random_commitment_point.eq(&EdwardsPoint::generator()).into() || counterparty_random_commitment_point == self.generator {
            return Err(FeldmanError::InvalidData("Counterparty sent generator".into()));
        }

        let counterparty_zkpok = Scalar::from_bytes(reveal.zk_pok.as_slice().try_into().unwrap());

        let counterparty_zkcommit = self.zkcommits_from_counterparties.get(&id)
            .ok_or_else(|| FeldmanError::InvalidData("Missing ZK commit for counterparty".into()))?;

        let mut hasher = Sha512::new();
        hasher.update(&reveal.point);
        hasher.update(&reveal.random_commitment_point);
        let challenge = hasher.finalize();

        let challenge_scalar = Scalar::from_bytes(challenge[..56].try_into().unwrap());

        let proof = self.generator * counterparty_zkpok;
        let expected_proof = counterparty_random_commitment_point + (counterparty_point * challenge_scalar);

        if proof != expected_proof {
            return Err(FeldmanError::InvalidData(format!("Invalid proof from {}", id)));
        }

        let mut hasher = Sha512::new();
        hasher.update(&reveal.random_commitment_point);
        hasher.update(&reveal.zk_pok);
        let verifier = hasher.finalize();

        if &verifier[..56] != counterparty_zkcommit {
            return Err(FeldmanError::InvalidData(format!("{} changed zkpok after commit", id)));
        }

        self.points_from_counterparties.insert(id, counterparty_point);

        if self.points_from_counterparties.len() == self.total - 1 {
            self.points_from_counterparties.insert(self.id, self.point);

            for i in 1..=self.total - self.threshold + 1 {
                let mut reconstructed_sum = EdwardsPoint::generator();

                for j in i..self.threshold + i {
                    let mut num = Scalar::ONE;
                    let mut den = Scalar::ONE;

                    for k in i..self.threshold + i {
                        if j != k {
                            let j_scalar = Scalar::from(j as u32);
                            let k_scalar = Scalar::from(k as u32);

                            num *= k_scalar;
                            den *= k_scalar - j_scalar;
                        }
                    }

                    let den_inv = den.invert();
                    let reconstructed_fragment = self.points_from_counterparties[&j] * (num * den_inv);
                    reconstructed_sum += reconstructed_fragment;
                }

                if self.public_key == EdwardsPoint::generator() || self.public_key == self.generator {
                    self.public_key = reconstructed_sum;
                } else if self.public_key != reconstructed_sum {
                    return Err(FeldmanError::InvalidData("Recombination mismatch".into()));
                }
            }
            self.round = FeldmanRound::Reconstructed;
        }

        Ok(self.round == FeldmanRound::Reconstructed)
    }

    pub fn mul_share(&self, pubkey: &[u8]) -> Result<Vec<u8>, FeldmanError> {
        if self.scalar.is_none() {
            return Err(FeldmanError::WrongRound);
        }

        let point = EdwardsPoint::from_bytes(pubkey.into());
        if point.is_none().into() {
            return Err(FeldmanError::InvalidData("invalid pubkey".to_string()));
        }

        let result = self.scalar.unwrap() * point.unwrap();
        if result.is_identity().into() {
            return Err(FeldmanError::InvalidData("invalid pubkey".to_string()));
        }

        return Ok(result.compress().to_bytes().to_vec());
    }

    pub fn combine_mul_share(&mut self, shares: Vec<&[u8]>, ids: &[usize]) -> Result<Vec<u8>, FeldmanError> {
        if shares.len() != ids.len() {
            return Err(FeldmanError::InvalidData("mismatch of shares and ids len".to_string()));
        }

        let mut points = HashMap::<usize, EdwardsPoint>::new();
        for (i, share) in shares.iter().enumerate() {
            let point = EdwardsPoint::from_bytes((*share).into());
            if point.is_none().into() {
                return Err(FeldmanError::InvalidData(format!("invalid pubkey for {}", ids[i]).to_string()));
            }

            points.insert(ids[i], point.unwrap());
        }
      
        let mut reconstructed_sum = EdwardsPoint::generator();

        for j in ids {
            let mut num = Scalar::ONE;
            let mut den = Scalar::ONE;

            for k in ids {
                if j != k {
                    let j_scalar = Scalar::from(*j as u32);
                    let k_scalar = Scalar::from(*k as u32);

                    num *= k_scalar;
                    den *= k_scalar - j_scalar;
                }
            }

            let den_inv = den.invert();
            let reconstructed_fragment = points[&j] * (num * den_inv);
            reconstructed_sum += reconstructed_fragment;
        }

        self.public_key = reconstructed_sum;

        return Ok(reconstructed_sum.compress().to_bytes().to_vec());
    }

    pub fn public_key(&self) -> &EdwardsPoint {
        &self.public_key
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes().to_vec()
    }

    pub fn redistribute<R: RngCore + CryptoRng>(rng: &mut R, shares: Vec<Vec<u8>>, ids: &[usize], threshold: usize, total: usize) -> Result<Vec<Vec<u8>>, FeldmanError> {
        if shares.len() != ids.len() {
            return Err(FeldmanError::InvalidData("mismatch of shares and ids len".to_string()));
        }

        let mut points = HashMap::<usize, Scalar>::new();
        for (i, share) in shares.iter().enumerate() {
            let point = Scalar::from_bytes(&(*share).clone().try_into().unwrap());
            if point.is_zero().into() {
                return Err(FeldmanError::InvalidData(format!("invalid pubkey for {}", ids[i]).to_string()));
            }

            points.insert(ids[i], point);
        }
      
        let mut reconstructed_sum = Scalar::ZERO;

        for j in ids {
            let mut num = Scalar::ONE;
            let mut den = Scalar::ONE;

            for k in ids {
                if j != k {
                    let j_scalar = Scalar::from(*j as u32);
                    let k_scalar = Scalar::from(*k as u32);

                    num *= k_scalar;
                    den *= k_scalar - j_scalar;
                }
            }

            let den_inv = den.invert();
            let reconstructed_fragment = points[&j] * (num * den_inv);
            reconstructed_sum += reconstructed_fragment;
        }

        return Ok(Feldman::construct_polynomial_samples(rng, reconstructed_sum, threshold, total).0.iter().map(|s| s.to_bytes().to_vec()).collect())
    }

    pub fn get_scalar(&self) -> Scalar {
      return self.scalar.unwrap();
    }

    pub fn get_id(&self) -> usize {
      return self.id;
    }
}

#[cfg(test)]
mod feldman_vss_tests {
    use super::*;
    use ed448_goldilocks_plus::{EdwardsPoint, Scalar};
    use rand::rngs::OsRng;

    // A receiver must accept a fragment that lies on the dealer's committed
    // polynomial and REJECT one that does not (the Feldman VSS share check),
    // closing the door on a malicious dealer biasing the shared secret.
    #[test]
    fn feldman_share_check_accepts_honest_and_rejects_inconsistent() {
        let gen = EdwardsPoint::generator();
        let (threshold, total) = (2usize, 3usize);

        // Dealer = party 1. Sample its polynomial + publish commitments.
        let mut dealer = Feldman::new(threshold, total, 1, Scalar::random(&mut OsRng), gen);
        dealer.sample_polynomial(&mut OsRng).unwrap();
        let commitments = dealer.get_commitments().unwrap();
        assert_eq!(commitments.len(), threshold, "one commitment per coefficient");
        let honest = dealer.get_poly_frags().unwrap().get(&2).unwrap().clone();

        // Honest fragment for party 2 verifies.
        let mut recv = Feldman::new(threshold, total, 2, Scalar::random(&mut OsRng), gen);
        recv.sample_polynomial(&mut OsRng).unwrap();
        assert!(
            recv.set_poly_frag_for_party(1, &honest, &commitments).is_ok(),
            "honest fragment on the committed polynomial must verify",
        );

        // A tampered fragment is rejected.
        let mut recv2 = Feldman::new(threshold, total, 2, Scalar::random(&mut OsRng), gen);
        recv2.sample_polynomial(&mut OsRng).unwrap();
        let mut tampered = honest.clone();
        tampered[0] ^= 0x01;
        assert!(
            recv2.set_poly_frag_for_party(1, &tampered, &commitments).is_err(),
            "a share off the committed polynomial must be rejected",
        );

        // The honest fragment checked against a DIFFERENT dealer's commitments
        // is also rejected (a swapped/forged commitment set can't pass).
        let mut other = Feldman::new(threshold, total, 1, Scalar::random(&mut OsRng), gen);
        other.sample_polynomial(&mut OsRng).unwrap();
        let wrong = other.get_commitments().unwrap();
        let mut recv3 = Feldman::new(threshold, total, 2, Scalar::random(&mut OsRng), gen);
        recv3.sample_polynomial(&mut OsRng).unwrap();
        assert!(
            recv3.set_poly_frag_for_party(1, &honest, &wrong).is_err(),
            "fragment must not verify against another dealer's commitments",
        );
    }
}
