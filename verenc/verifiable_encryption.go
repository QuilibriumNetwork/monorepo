package verenc

import (
	"encoding/binary"
	"slices"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	generated "source.quilibrium.com/quilibrium/monorepo/verenc/generated/verenc"
)

var _ crypto.VerifiableEncryptor = (*MPCitHVerifiableEncryptor)(nil)

type MPCitHVerEncProof struct {
	generated.VerencProofAndBlindingKey
}

type MPCitHVerEnc struct {
	generated.CompressedCiphertext
	BlindingPubkey []uint8
	Statement      []uint8
}

func MPCitHVerEncProofFromBytes(data []byte) MPCitHVerEncProof {
	if len(data) != 9268 {
		return MPCitHVerEncProof{}
	}

	polycom := [][]byte{}
	for i := 0; i < 23; i++ {
		polycom = append(polycom, data[235+(i*57):292+(i*57)])
	}

	ctexts := []generated.VerencCiphertext{}
	srs := []generated.VerencShare{}

	for i := 0; i < 42; i++ {
		ctexts = append(ctexts, generated.VerencCiphertext{
			C1: data[1546+(i*(57+56+8)) : 1603+(i*(57+56+8))],
			C2: data[1603+(i*(57+56+8)) : 1659+(i*(57+56+8))],
			I:  binary.BigEndian.Uint64(data[1659+(i*(57+56+8)) : 1667+(i*(57+56+8))]),
		})
	}

	for i := 0; i < 22; i++ {
		srs = append(srs, generated.VerencShare{
			S1: data[6628+(i*(56+56+8)) : 6684+(i*(56+56+8))],
			S2: data[6684+(i*(56+56+8)) : 6740+(i*(56+56+8))],
			I:  binary.BigEndian.Uint64(data[6740+(i*(56+56+8)) : 6748+(i*(56+56+8))]),
		})
	}

	return MPCitHVerEncProof{
		generated.VerencProofAndBlindingKey{
			BlindingPubkey: data[:57],
			EncryptionKey:  data[57:114],
			Statement:      data[114:171],
			Challenge:      data[171:235],
			Polycom:        polycom,
			Ctexts:         ctexts,
			SharesRands:    srs,
		},
	}
}

func (p MPCitHVerEncProof) ToBytes() []byte {
	output := []byte{}
	output = append(output, p.BlindingPubkey...)
	output = append(output, p.EncryptionKey...)
	output = append(output, p.Statement...)
	output = append(output, p.Challenge...)

	for _, pol := range p.Polycom {
		output = append(output, pol...)
	}

	for _, ct := range p.Ctexts {
		output = append(output, ct.C1...)
		output = append(output, ct.C2...)
		output = binary.BigEndian.AppendUint64(output, ct.I)
	}

	for _, sr := range p.SharesRands {
		output = append(output, sr.S1...)
		output = append(output, sr.S2...)
		output = binary.BigEndian.AppendUint64(output, sr.I)
	}

	return output
}

func (p MPCitHVerEncProof) VerifyStatement(input []byte) bool {
	return VerencVerifyStatement(input, p.BlindingPubkey, p.Statement)
}

func (p MPCitHVerEncProof) GetStatement() []byte {
	return slices.Clone(p.Statement)
}

func (p MPCitHVerEncProof) GetEncryptionKey() []byte {
	return slices.Clone(p.EncryptionKey)
}

func (p MPCitHVerEncProof) Compress() crypto.VerEnc {
	compressed := VerencCompress(generated.VerencProof{
		BlindingPubkey: p.BlindingPubkey,
		EncryptionKey:  p.EncryptionKey,
		Statement:      p.Statement,
		Challenge:      p.Challenge,
		Polycom:        p.Polycom,
		Ctexts:         p.Ctexts,
		SharesRands:    p.SharesRands,
	})
	return MPCitHVerEnc{
		CompressedCiphertext: compressed,
		BlindingPubkey:       p.BlindingPubkey,
		Statement:            p.Statement,
	}
}

func (p MPCitHVerEncProof) Verify() bool {
	return VerencVerify(generated.VerencProof{
		BlindingPubkey: p.BlindingPubkey,
		EncryptionKey:  p.EncryptionKey,
		Statement:      p.Statement,
		Challenge:      p.Challenge,
		Polycom:        p.Polycom,
		Ctexts:         p.Ctexts,
		SharesRands:    p.SharesRands,
	})
}

type InlineEnc struct {
	iv         []byte
	ciphertext []byte
}

func MPCitHVerEncFromBytes(data []byte) crypto.VerEnc {
	if len(data) < 621 {
		return MPCitHVerEnc{}
	}

	ciphertext := generated.CompressedCiphertext{}
	for i := 0; i < 3; i++ {
		ciphertext.Ctexts = append(ciphertext.Ctexts, generated.VerencCiphertext{
			C1: data[0+(i*(57+56)) : 57+(i*(57+56))],
			C2: data[57+(i*(57+56)) : 113+(i*(57+56))],
		})
		ciphertext.Aux = append(ciphertext.Aux, data[339+(i*56):395+(i*56)])
	}
	return MPCitHVerEnc{
		CompressedCiphertext: ciphertext,
		BlindingPubkey:       data[507:564],
		Statement:            data[564:621],
	}
}

func (e MPCitHVerEnc) ToBytes() []byte {
	output := []byte{}
	for _, ct := range e.Ctexts {
		output = append(output, ct.C1...)
		output = append(output, ct.C2...)
	}
	for _, a := range e.Aux {
		output = append(output, a...)
	}
	output = append(output, e.BlindingPubkey...)
	output = append(output, e.Statement...)
	return output
}

func (e MPCitHVerEnc) GetStatement() []byte {
	return e.Statement
}

func (e MPCitHVerEnc) Verify(proof []byte) bool {
	proofData := MPCitHVerEncProofFromBytes(proof)
	return proofData.Verify()
}

type MPCitHVerifiableEncryptor struct {
	parallelism int
	lruCache    *lru.Cache[string, crypto.VerEnc]
}

func NewMPCitHVerifiableEncryptor(parallelism int) *MPCitHVerifiableEncryptor {
	cache, err := lru.New[string, crypto.VerEnc](10000)
	if err != nil {
		panic(err)
	}

	return &MPCitHVerifiableEncryptor{
		parallelism: parallelism,
		lruCache:    cache,
	}
}

func (v *MPCitHVerifiableEncryptor) ProofFromBytes(
	data []byte,
) crypto.VerEncProof {
	return MPCitHVerEncProofFromBytes(data)
}

func (v *MPCitHVerifiableEncryptor) FromBytes(data []byte) crypto.VerEnc {
	return MPCitHVerEncFromBytes(data)
}

func (v *MPCitHVerifiableEncryptor) Encrypt(
	data []byte,
	publicKey []byte,
) []crypto.VerEncProof {
	chunks := ChunkDataForVerenc(data)
	results := make([]crypto.VerEncProof, len(chunks))
	var wg sync.WaitGroup
	throttle := make(chan struct{}, v.parallelism)
	for i, chunk := range chunks {
		throttle <- struct{}{}
		wg.Add(1)
		go func(chunk []byte, i int) {
			defer func() { <-throttle }()
			defer wg.Done()
			proof := NewVerencProofEncryptOnly(chunk, publicKey)
			results[i] = MPCitHVerEncProof{
				generated.VerencProofAndBlindingKey{
					BlindingKey:    proof.BlindingKey,
					BlindingPubkey: proof.BlindingPubkey,
					EncryptionKey:  proof.EncryptionKey,
					Statement:      proof.Statement,
					Challenge:      proof.Challenge,
					Polycom:        proof.Polycom,
					Ctexts:         proof.Ctexts,
					SharesRands:    proof.SharesRands,
				},
			}
		}(chunk, i)
	}
	wg.Wait()
	return results
}

func (v *MPCitHVerifiableEncryptor) EncryptAndCompress(
	data []byte,
	publicKey []byte,
) []crypto.VerEnc {
	chunks := ChunkDataForVerenc(data)
	results := make([]crypto.VerEnc, len(chunks))
	var wg sync.WaitGroup
	throttle := make(chan struct{}, v.parallelism)
	for i, chunk := range chunks {
		throttle <- struct{}{}
		wg.Add(1)
		go func(chunk []byte, i int) {
			defer func() { <-throttle }()
			defer wg.Done()
			existing, ok := v.lruCache.Get(string(publicKey) + string(chunk))
			if ok {
				results[i] = existing
			} else {
				proof := NewVerencProofEncryptOnly(chunk, publicKey)
				result := MPCitHVerEncProof{
					generated.VerencProofAndBlindingKey{
						BlindingKey:    proof.BlindingKey,
						BlindingPubkey: proof.BlindingPubkey,
						EncryptionKey:  proof.EncryptionKey,
						Statement:      proof.Statement,
						Challenge:      proof.Challenge,
						Polycom:        proof.Polycom,
						Ctexts:         proof.Ctexts,
						SharesRands:    proof.SharesRands,
					},
				}
				results[i] = result.Compress()
				v.lruCache.Add(string(publicKey)+string(chunk), results[i])
			}
		}(chunk, i)
	}
	wg.Wait()
	return results
}

func (v *MPCitHVerifiableEncryptor) Decrypt(
	encrypted []crypto.VerEnc,
	decyptionKey []byte,
) []byte {
	results := make([][]byte, len(encrypted))
	var wg sync.WaitGroup
	throttle := make(chan struct{}, v.parallelism)
	for i, chunk := range encrypted {
		throttle <- struct{}{}
		wg.Add(1)
		go func(chunk crypto.VerEnc, i int) {
			defer func() { <-throttle }()
			defer wg.Done()
			results[i] = VerencRecover(generated.VerencDecrypt{
				BlindingPubkey: chunk.(MPCitHVerEnc).BlindingPubkey,
				DecryptionKey:  decyptionKey,
				Statement:      chunk.(MPCitHVerEnc).Statement,
				Ciphertexts:    chunk.(MPCitHVerEnc).CompressedCiphertext,
			})
		}(chunk, i)
	}
	wg.Wait()
	return CombineChunkedData(results)
}
