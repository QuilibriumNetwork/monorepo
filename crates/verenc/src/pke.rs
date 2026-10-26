/* Hashed Elgamal implementation */
#![allow(dead_code)]
#![allow(non_snake_case)]

use crate::utils::*;

use ed448_goldilocks_plus::elliptic_curve::Group;
use ed448_goldilocks_plus::EdwardsPoint as GGA;
use ed448_goldilocks_plus::Scalar as FF;
use rand::rngs::OsRng;

const WINDOW_SIZE: usize = 7;

#[derive(Clone)]
pub struct Elgamal {
    pub(crate) params: CurveParams,
    pub(crate) G: GGA,
}

#[derive(Copy, Clone, Default, Debug)]
pub struct PKECipherText {
    pub(crate) c1: GGA,
    pub(crate) c2: FF,
}

#[derive(Clone)]
pub struct PKEPublicKey {
    pub(crate) ek: GGA,
}

impl PKECipherText {
    pub fn zero() -> Self {
        PKECipherText {
            c1: GGA::IDENTITY,
            c2: FF::ZERO,
        }
    }
}

impl PKECipherText {
    pub fn to_bytes(&self) -> Vec<u8> {
        let c1_bytes = self.c1.compress().to_bytes().to_vec();
        let c2_bytes = self.c2.to_bytes().to_vec();
        [c1_bytes, c2_bytes].concat()
    }
}

impl Elgamal {
    pub fn setup(params: &CurveParams) -> Self {
        // we skip a lot of precomputation utilizing edwards curves
        let precomp_G = GGA::generator();

        Elgamal {
            params: params.clone(),
            G: precomp_G,
        }
    }

    pub fn kgen(&self) -> (PKEPublicKey, FF) {
        let x = FF::random(&mut OsRng);
        let Y = self.mul_G(x);

        let pk = PKEPublicKey { ek: Y };

        return (pk, x);
    }

    pub fn encrypt(&self, ek: &PKEPublicKey, msg: &FF) -> PKECipherText {
        self.encrypt_given_r(ek, msg, &FF::random(&mut OsRng))
    }

    fn mul_G(&self, scalar: FF) -> GGA {
        self.G * scalar
    }
    fn mul_ek(ek: &GGA, scalar: FF) -> GGA {
        ek * scalar
    }

    pub fn encrypt_given_r(&self, ek: &PKEPublicKey, msg: &FF, r: &FF) -> PKECipherText {
        let c1 = self.mul_G(*r);
        self.encrypt_given_c1(ek, msg, r, c1)
    }

    // Encryption where c1 = G^r is given
    pub fn encrypt_given_c1(&self, ek: &PKEPublicKey, msg: &FF, r: &FF, c1: GGA) -> PKECipherText {
        let keyseed = Self::mul_ek(&ek.ek, *r);
        let hash = hash_to_FF(&keyseed);
        let c2 = hash + msg;
        PKECipherText { c1, c2 }
    }

    pub fn decrypt(&self, dk: &FF, ct: &PKECipherText) -> FF {
        let pt = ct.c1 * dk;
        let hash = hash_to_FF(&pt);
        ct.c2 - hash
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_pke_kgen() {
        let params = CurveParams::init(GGA::generator());
        let pke = Elgamal::setup(&params);
        let (ek, dk) = pke.kgen();
        assert_eq!(params.G * dk, ek.ek);
    }

    #[test]
    fn test_pke_enc_dec() {
        let params = CurveParams::init(GGA::generator());
        let pke = Elgamal::setup(&params);
        let (ek, dk) = pke.kgen();
        let m = FF::random(&mut OsRng);
        let ct = pke.encrypt(&ek, &m);
        let pt = pke.decrypt(&dk, &ct);
        assert_eq!(m, pt);
    }
}
