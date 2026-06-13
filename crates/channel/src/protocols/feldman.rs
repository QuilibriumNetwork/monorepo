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
}

#[derive(Serialize, Deserialize)]
pub struct FeldmanReveal {
    point: Vec<u8>,
    random_commitment_point: Vec<u8>,
    zk_pok: Vec<u8>,
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
        })
    }

    pub fn set_id(&mut self, id: usize) {
      self.id = id;
    }

    pub fn sample_polynomial<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<(), FeldmanError> {
        if self.round != FeldmanRound::Uninitialized {
            return Err(FeldmanError::WrongRound);
        }

        let samples = Feldman::construct_polynomial_samples(rng, self.secret, self.threshold, self.total);

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

    fn construct_polynomial_samples<R: RngCore + CryptoRng>(rng: &mut R, secret: Scalar, threshold: usize, total: usize) -> Vec<Scalar> {
        let mut coeffs = vec![secret];
    
        for _ in 1..threshold {
            coeffs.push(Scalar::random(rng));
        }
    
        let mut samples = Vec::<Scalar>::new();
        for i in 1..=total {
            let mut result = coeffs[0];
            let x = Scalar::from(i as u32);
    
            for j in 1..threshold {
                let term = coeffs[j] * Scalar::from(i.pow(j as u32) as u32);
                result += term;
            }

            samples.push(result);
        }

        return samples;
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

    pub fn set_poly_frag_for_party(&mut self, id: usize, frag: &[u8]) -> Result<Option<Vec<u8>>, FeldmanError> {
        if self.round != FeldmanRound::Initialized {
            return Err(FeldmanError::WrongRound);
        }

        let scalar = Scalar::from_bytes(frag.try_into().unwrap());
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

        return Ok(Feldman::construct_polynomial_samples(rng, reconstructed_sum, threshold, total).iter().map(|s| s.to_bytes().to_vec()).collect())
    }

    pub fn get_scalar(&self) -> Scalar {
      return self.scalar.unwrap();
    }

    pub fn get_id(&self) -> usize {
      return self.id;
    }
}
