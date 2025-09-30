package bls48581

import (
	"bytes"
	gcrypto "crypto"
	"encoding/binary"
	"io"
	"runtime"
	"slices"
	"sync"

	"github.com/pkg/errors"
	generated "source.quilibrium.com/quilibrium/monorepo/bls48581/generated/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

//go:generate ./generate.sh

type BlsAggregateOutput struct {
	AggregatePublicKey []uint8
	AggregateSignature []uint8
}

type BlsKeygenOutput struct {
	SecretKey            []uint8
	PublicKey            []uint8
	ProofOfPossessionSig []uint8
}

type Multiproof struct {
	D     []uint8
	Proof []uint8
}

func (m *Multiproof) FromBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read D
	var dLen uint32
	if err := binary.Read(buf, binary.BigEndian, &dLen); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	m.D = make([]byte, dLen)
	if _, err := buf.Read(m.D); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Read Proof
	var proofLen uint32
	if err := binary.Read(buf, binary.BigEndian, &proofLen); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	m.Proof = make([]byte, proofLen)
	if _, err := buf.Read(m.Proof); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	return nil
}

func (m *Multiproof) ToBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write D
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.D)),
	); err != nil {
		return nil, errors.Wrap(err, "to bytes")
	}

	if _, err := buf.Write(m.D); err != nil {
		return nil, errors.Wrap(err, "to bytes")
	}

	// Write Proof
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Proof)),
	); err != nil {
		return nil, errors.Wrap(err, "to bytes")
	}

	if _, err := buf.Write(m.Proof); err != nil {
		return nil, errors.Wrap(err, "to bytes")
	}

	return buf.Bytes(), nil
}

func (o *BlsAggregateOutput) GetAggregatePublicKey() []byte {
	out := make([]byte, len(o.AggregatePublicKey))
	copy(out, o.AggregatePublicKey)
	return out
}

func (o *BlsAggregateOutput) GetAggregateSignature() []byte {
	out := make([]byte, len(o.AggregateSignature))
	copy(out, o.AggregateSignature)
	return out
}

func (o *BlsAggregateOutput) Verify(msg []byte, domain []byte) bool {
	return BlsVerify(o.AggregatePublicKey, o.AggregateSignature, msg, domain)
}

func (o *BlsKeygenOutput) GetPublicKey() []byte {
	out := make([]byte, len(o.PublicKey))
	copy(out, o.PublicKey)
	return out
}

func (o *BlsKeygenOutput) GetPrivateKey() []byte {
	out := make([]byte, len(o.SecretKey))
	copy(out, o.SecretKey)
	return out
}

func (o *BlsKeygenOutput) GetProofOfPossession() []byte {
	out := make([]byte, len(o.ProofOfPossessionSig))
	copy(out, o.ProofOfPossessionSig)
	return out
}

func (p *Multiproof) GetMulticommitment() []byte {
	out := make([]byte, len(p.D))
	copy(out, p.D)
	return out
}

func (p *Multiproof) GetProof() []byte {
	out := make([]byte, len(p.Proof))
	copy(out, p.Proof)
	return out
}

func Init() {
	generated.Init()
}

func CommitRaw(data []byte, polySize uint64) []byte {
	return generated.CommitRaw(data, polySize)
}

func ProveRaw(data []byte, index uint64, polySize uint64) []byte {
	return generated.ProveRaw(data, index, polySize)
}

func VerifyRaw(
	data []byte,
	commit []byte,
	index uint64,
	proof []byte,
	polySize uint64,
) bool {
	return generated.VerifyRaw(data, commit, index, proof, polySize)
}

func ProveMultiple(
	commitments [][]byte,
	polys [][]byte,
	indices []uint64,
	polySize uint64,
) crypto.Multiproof {
	mp := generated.ProveMultiple(commitments, polys, indices, polySize)
	d := slices.Clone(mp.D)
	proof := slices.Clone(mp.Proof)
	return &Multiproof{
		D:     d,
		Proof: proof,
	}
}

func VerifyMultiple(
	commitments [][]byte,
	evaluations [][]byte,
	indices []uint64,
	polySize uint64,
	multiCommitment []byte,
	proof []byte,
) bool {
	return generated.VerifyMultiple(
		commitments,
		evaluations,
		indices,
		polySize,
		multiCommitment,
		proof,
	)
}

func BlsAggregate(pks [][]byte, sigs [][]byte) crypto.BlsAggregateOutput {
	// Handle edge cases
	if len(pks) == 0 || len(sigs) == 0 || len(pks) != len(sigs) {
		return &BlsAggregateOutput{
			AggregatePublicKey: []byte{},
			AggregateSignature: []byte{},
		}
	}

	// For small inputs, use the non-parallelized version
	// Parallelization overhead isn't worth it for small sets
	const minParallelSize = 100
	if len(pks) < minParallelSize {
		ag := generated.BlsAggregate(pks, sigs)
		pk := slices.Clone(ag.AggregatePublicKey)
		sig := slices.Clone(ag.AggregateSignature)
		return &BlsAggregateOutput{
			AggregatePublicKey: pk,
			AggregateSignature: sig,
		}
	}

	// Determine optimal number of workers based on CPU cores and input size
	numCPU := runtime.NumCPU()
	numWorkers := numCPU

	// Adjust workers based on input size - each worker should handle at least
	// minParallelSize items
	maxWorkers := len(pks) / minParallelSize
	if numWorkers > maxWorkers {
		numWorkers = maxWorkers
	}

	// Ensure at least 2 workers for parallelization
	if numWorkers < 2 {
		numWorkers = 2
	}

	// Calculate chunk size for even distribution
	chunkSize := len(pks) / numWorkers
	remainder := len(pks) % numWorkers

	// Prepare for parallel aggregation
	var wg sync.WaitGroup
	wg.Add(numWorkers)

	type aggregateResult struct {
		pk  []byte
		sig []byte
		err error
	}

	results := make([]aggregateResult, numWorkers)

	// Launch parallel workers
	for i := 0; i < numWorkers; i++ {
		workerIdx := i
		start := workerIdx * chunkSize

		// Distribute remainder across first workers
		if workerIdx < remainder {
			start += workerIdx
		} else {
			start += remainder
		}

		end := start + chunkSize
		if workerIdx < remainder {
			end++
		}

		// Ensure we don't go out of bounds
		if end > len(pks) {
			end = len(pks)
		}

		go func(idx, s, e int) {
			defer wg.Done()

			if s >= e {
				results[idx] = aggregateResult{}
				return
			}

			// Aggregate this chunk
			chunkResult := generated.BlsAggregate(pks[s:e], sigs[s:e])
			results[idx] = aggregateResult{
				pk:  slices.Clone(chunkResult.AggregatePublicKey),
				sig: slices.Clone(chunkResult.AggregateSignature),
			}
		}(workerIdx, start, end)
	}

	// Wait for all workers to complete
	wg.Wait()

	// Collect non-empty results for final aggregation
	finalPks := make([][]byte, 0, numWorkers)
	finalSigs := make([][]byte, 0, numWorkers)

	for _, result := range results {
		if len(result.pk) > 0 && len(result.sig) > 0 {
			finalPks = append(finalPks, result.pk)
			finalSigs = append(finalSigs, result.sig)
		}
	}

	// If we only got one result (edge case), return it directly
	if len(finalPks) == 1 {
		return &BlsAggregateOutput{
			AggregatePublicKey: finalPks[0],
			AggregateSignature: finalSigs[0],
		}
	}

	// Final aggregation of the parallel results
	finalAg := generated.BlsAggregate(finalPks, finalSigs)
	pk := slices.Clone(finalAg.AggregatePublicKey)
	sig := slices.Clone(finalAg.AggregateSignature)

	return &BlsAggregateOutput{
		AggregatePublicKey: pk,
		AggregateSignature: sig,
	}
}

func BlsKeygen() crypto.BlsKeygenOutput {
	kg := generated.BlsKeygen()
	sk := slices.Clone(kg.SecretKey)
	pk := slices.Clone(kg.PublicKey)
	pops := slices.Clone(kg.ProofOfPossessionSig)
	return &BlsKeygenOutput{
		SecretKey:            sk,
		PublicKey:            pk,
		ProofOfPossessionSig: pops,
	}
}

func BlsSign(sk []byte, msg []byte, domain []byte) []byte {
	return generated.BlsSign(sk, msg, domain)
}

func BlsVerify(pk []byte, sig []byte, msg []byte, domain []byte) bool {
	if len(pk) != 585 || len(sig) != 74 {
		return false
	}

	return generated.BlsVerify(pk, sig, msg, domain)
}

type Bls48581KeyConstructor struct{}

// Aggregate implements crypto.BlsConstructor.
func (b *Bls48581KeyConstructor) Aggregate(
	publicKeys [][]byte,
	signatures [][]byte,
) (crypto.BlsAggregateOutput, error) {
	aggregate := BlsAggregate(publicKeys, signatures)
	if len(aggregate.GetAggregatePublicKey()) == 0 {
		return nil, errors.Wrap(errors.New("invalid aggregation"), "aggregate")
	}

	return aggregate, nil
}

// VerifySignatureRaw implements crypto.BlsConstructor.
func (b *Bls48581KeyConstructor) VerifySignatureRaw(
	publicKeyG2 []byte,
	signatureG1 []byte,
	message []byte,
	context []byte,
) bool {
	if len(publicKeyG2) != 585 || len(signatureG1) != 74 {
		return false
	}

	return generated.BlsVerify(publicKeyG2, signatureG1, message, context)
}

type Bls48581Key struct {
	privateKey []byte
	publicKey  []byte
}

// GetType implements crypto.Signer.
func (b *Bls48581Key) GetType() crypto.KeyType {
	return crypto.KeyTypeBLS48581G1
}

// Private implements crypto.Signer.
func (b *Bls48581Key) Private() []byte {
	return b.privateKey
}

// Public implements crypto.Signer.
func (b *Bls48581Key) Public() gcrypto.PublicKey {
	return b.publicKey
}

// Sign implements crypto.Signer.
func (b *Bls48581Key) Sign(
	rand io.Reader,
	digest []byte,
	opts gcrypto.SignerOpts,
) (signature []byte, err error) {
	return nil, errors.Wrap(errors.New("sign with domain must be used"), "sign")
}

// SignWithDomain implements crypto.Signer.
func (b *Bls48581Key) SignWithDomain(
	message []byte,
	domain []byte,
) (signature []byte, err error) {
	out := BlsSign(b.privateKey, message, domain)
	if len(out) == 0 {
		return nil, errors.Wrap(errors.New("unknown"), "sign with domain")
	}

	return out, nil
}

// FromBytes implements crypto.BlsConstructor.
func (b *Bls48581KeyConstructor) FromBytes(
	privateKey []byte,
	publicKey []byte,
) (crypto.Signer, error) {
	return &Bls48581Key{
		privateKey,
		publicKey,
	}, nil
}

// New implements crypto.BlsConstructor.
func (b *Bls48581KeyConstructor) New() (crypto.Signer, []byte, error) {
	key := BlsKeygen()
	return &Bls48581Key{
		privateKey: key.GetPrivateKey(),
		publicKey:  key.GetPublicKey(),
	}, key.GetProofOfPossession(), nil
}

var _ crypto.BlsConstructor = (*Bls48581KeyConstructor)(nil)
