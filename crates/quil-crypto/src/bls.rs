use quil_types::crypto::{BlsAggregateOutput, BlsConstructor, KeyType, Signer};
use quil_types::error::Result;

/// BLS48-581 signer wrapping the bls48581 crate.
pub struct Bls48581Signer {
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl Signer for Bls48581Signer {
    fn key_type(&self) -> KeyType {
        KeyType::Bls48581G2
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn private_key(&self) -> &[u8] {
        &self.secret_key
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(bls48581::bls_sign(&self.secret_key, message, &[]))
    }

    fn sign_with_domain(&self, message: &[u8], domain: &[u8]) -> Result<Vec<u8>> {
        Ok(bls48581::bls_sign(&self.secret_key, message, domain))
    }
}

/// Constructor for BLS48-581 keys.
pub struct Bls48581KeyConstructor;

impl BlsConstructor for Bls48581KeyConstructor {
    fn new_key(&self) -> Result<(Box<dyn Signer>, Vec<u8>)> {
        let output = bls48581::bls_keygen();
        let public_key = output.public_key.clone();
        let signer = Bls48581Signer {
            secret_key: output.secret_key,
            public_key: output.public_key,
        };
        Ok((Box::new(signer), public_key))
    }

    fn from_bytes(&self, private_key: &[u8], public_key: &[u8]) -> Result<Box<dyn Signer>> {
        Ok(Box::new(Bls48581Signer {
            secret_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
        }))
    }

    fn verify_signature_raw(
        &self,
        public_key_g2: &[u8],
        signature_g1: &[u8],
        message: &[u8],
        context: &[u8],
    ) -> bool {
        bls48581::bls_verify(public_key_g2, signature_g1, message, context)
    }

    fn verify_multi_message_signature_raw(
        &self,
        public_key_g2: &[u8],
        signature_g1: &[u8],
        messages: &[&[u8]],
        context: &[u8],
    ) -> bool {
        let msgs: Vec<Vec<u8>> = messages.iter().map(|m| m.to_vec()).collect();
        bls48581::bls_verify_msig_mmsg(
            &vec![public_key_g2.to_vec()],
            signature_g1,
            &msgs,
            context,
        )
    }

    fn aggregate(
        &self,
        public_keys: &[&[u8]],
        signatures: &[&[u8]],
    ) -> Result<BlsAggregateOutput> {
        let pks: Vec<Vec<u8>> = public_keys.iter().map(|k| k.to_vec()).collect();
        let sigs: Vec<Vec<u8>> = signatures.iter().map(|s| s.to_vec()).collect();
        let output = bls48581::bls_aggregate(&pks, &sigs);
        Ok(BlsAggregateOutput {
            signature: output.aggregate_signature,
            public_key: output.aggregate_public_key,
        })
    }
}
