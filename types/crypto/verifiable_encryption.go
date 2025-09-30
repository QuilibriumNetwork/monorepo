package crypto

type VerEnc interface {
	ToBytes() []byte
	GetStatement() []byte
	Verify(proof []byte) bool
}

type VerEncProof interface {
	ToBytes() []byte
	Compress() VerEnc
	VerifyStatement(input []byte) bool
	GetStatement() []byte
	GetEncryptionKey() []byte
	Verify() bool
}

type VerifiableEncryptor interface {
	Encrypt(
		data []byte,
		publicKey []byte,
	) []VerEncProof
	Decrypt(
		encrypted []VerEnc,
		decryptionKey []byte,
	) []byte
	EncryptAndCompress(
		data []byte,
		publicKey []byte,
	) []VerEnc
	ProofFromBytes(data []byte) VerEncProof
	FromBytes(data []byte) VerEnc
}
