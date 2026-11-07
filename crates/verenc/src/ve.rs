pub trait VerEnc {
    type SystemParams;
    type Statement;
    type Witness;
    type PKE;
    type EncKey;
    type DecKey;
    type VEParams;
    type VEProof;
    type VECipherText;

    fn setup(params: &Self::SystemParams, vparams: &Self::VEParams, pke: Self::PKE) -> Self;

    fn set_ek(&mut self, ek: Self::EncKey);

    fn kgen(&mut self) -> Self::DecKey;

    fn get_public_key(&self) -> &Self::EncKey;

    fn igen(&self, w: &[u8; 56]) -> (Self::Statement, Self::Witness);

    fn prove(&self, stm: &Self::Statement, wit: &Self::Witness) -> Self::VEProof;

    fn verify(&self, stm: &Self::Statement, pi: &Self::VEProof) -> bool;

    fn compress(&self, stm: &Self::Statement, pi: &Self::VEProof) -> Self::VECipherText;

    fn recover(
        &self,
        stm: &Self::Statement,
        dk: &Self::DecKey,
        ve_ct: &Self::VECipherText,
    ) -> Self::Witness;
}
