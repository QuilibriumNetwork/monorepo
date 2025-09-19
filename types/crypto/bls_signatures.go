package crypto

type BlsAggregateOutput interface {
	GetAggregatePublicKey() []byte
	GetAggregateSignature() []byte
	Verify(msg []byte, domain []byte) bool
}

type BlsKeygenOutput interface {
	GetPublicKey() []byte
	GetPrivateKey() []byte
	GetProofOfPossession() []byte
}
