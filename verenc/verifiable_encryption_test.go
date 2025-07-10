package verenc_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
)

func TestVerifiableEncryptionCoinSegmentCount(t *testing.T) {
	// Create a new MPCitHVerifiableEncryptor
	encryptor := verenc.NewMPCitHVerifiableEncryptor(4) // 4 parallel workers

	// Create a Coin with some test data
	coin := &protobufs.Coin{
		Amount: []byte{
			0x20, 0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19,
			0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
			0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09,
			0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
		},
		Intersection: make([]byte, 1024), // 1024-byte intersection
		Owner: &protobufs.AccountRef{
			Account: &protobufs.AccountRef_ImplicitAccount{
				ImplicitAccount: &protobufs.ImplicitAccount{
					Address: make([]byte, 32),
				},
			},
		},
	}

	// Generate some random values for the coin
	rand.Read(coin.Intersection)
	rand.Read(coin.Owner.GetImplicitAccount().Address)

	// Get chunked representation for a specific frame number
	frameNumber := uint64(12345)
	chunkedData := coin.ToChunkedRepresentation(frameNumber)

	privkey := curves.ED448().Scalar.Random(rand.Reader)
	pubKey := curves.ED448().NewGeneratorPoint().Mul(privkey)
	fmt.Printf("%x\n", chunkedData)
	// Encrypt the chunked data
	proofs := encryptor.Encrypt(chunkedData, pubKey.ToAffineCompressed())

	// Verify there are exactly 23 VerEncProof entries
	assert.Equal(t, 23, len(proofs), "Expected 23 VerEncProof entries, got %d", len(proofs))

	compressed := []crypto.VerEnc{}
	// Verify each proof is of the correct type
	for i, proof := range proofs {
		_, ok := proof.(verenc.MPCitHVerEncProof)
		assert.True(t, ok, "Proof at index %d is not of type MPCitHVerEncProof", i)
		compressed = append(compressed, proof.Compress())
	}

	// Verify the output size of elements by compressing a proof
	if len(proofs) > 0 {
		compressed := proofs[0].Compress()
		verenc, ok := compressed.(verenc.MPCitHVerEnc)
		assert.True(t, ok, "Compressed proof is not of type MPCitHVerEnc")

		// Verify expected fields are present
		assert.NotEmpty(t, verenc.BlindingPubkey, "BlindingPubkey is empty")
		assert.NotEmpty(t, verenc.Statement, "Statement is empty")
		assert.NotEmpty(t, verenc.Ctexts, "Ctexts is empty")
	}
	amt := slices.Clone(coin.Amount)
	slices.Reverse(amt)
	a, _ := curves.ED448().NewScalar().SetBytes(slices.Concat(amt, make([]byte, 24)))
	amtc := slices.Clone(chunkedData[55:110])
	ac, _ := curves.ED448().NewScalar().SetBytes(append(amtc, 0))
	fmt.Printf("%x\n", a.Bytes())
	fmt.Printf("%x\n", ac.Bytes())
	for i := range compressed {
		s, _ := curves.ED448().NewGeneratorPoint().FromAffineCompressed(compressed[i].(verenc.MPCitHVerEnc).BlindingPubkey)
		fmt.Printf("%x\n", s.Mul(a).ToAffineCompressed())
		fmt.Printf("%x\n", compressed[i].GetStatement())

		b, _ := curves.ED448().NewScalar().SetBytes(proofs[i].(verenc.MPCitHVerEncProof).BlindingKey)
		bp := curves.ED448().NewGeneratorPoint().Mul(b)
		fmt.Printf("%x\n", bp.ToAffineCompressed())
		fmt.Printf("%x\n", compressed[i].(verenc.MPCitHVerEnc).BlindingPubkey)
		fmt.Printf("%x\n", s.ToAffineCompressed())
	}
	out := encryptor.Decrypt(compressed, privkey.Bytes())
	fmt.Printf("%x\n", out)

	s, _ := curves.ED448().NewGeneratorPoint().FromAffineCompressed(compressed[1].(verenc.MPCitHVerEnc).BlindingPubkey)

	assert.True(t, bytes.Equal(s.Mul(a).ToAffineCompressed(), compressed[1].GetStatement()))
}
