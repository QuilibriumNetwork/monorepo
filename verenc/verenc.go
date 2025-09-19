package verenc

import (
	generated "source.quilibrium.com/quilibrium/monorepo/verenc/generated/verenc"
)

//go:generate ./generate.sh

func NewVerencProof(data []byte) generated.VerencProofAndBlindingKey {
	return generated.NewVerencProof(data)
}

func NewVerencProofEncryptOnly(data []byte, encryptionKey []byte) generated.VerencProofAndBlindingKey {
	return generated.NewVerencProofEncryptOnly(data, encryptionKey)
}

func VerencVerify(proof generated.VerencProof) bool {
	return generated.VerencVerify(proof)
}

func VerencCompress(proof generated.VerencProof) generated.CompressedCiphertext {
	return generated.VerencCompress(proof)
}

func VerencVerifyStatement(input []byte, blindingPubkey []byte, statement []byte) bool {
	return generated.VerencVerifyStatement(input, blindingPubkey, statement)
}

func VerencRecover(recovery generated.VerencDecrypt) []byte {
	return generated.VerencRecover(recovery)
}

func ChunkDataForVerenc(data []byte) [][]byte {
	return generated.ChunkDataForVerenc(data)
}

func CombineChunkedData(chunks [][]byte) []byte {
	return generated.CombineChunkedData(chunks)
}
