package token

import (
	"math/big"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// FromProtobuf converts a protobuf Authority to intrinsics Authority
func AuthorityFromProtobuf(pb *protobufs.Authority) (*Authority, error) {
	if pb == nil {
		return nil, nil
	}
	return &Authority{
		KeyType:   crypto.KeyType(pb.KeyType),
		PublicKey: pb.PublicKey,
		CanBurn:   pb.CanBurn,
	}, nil
}

// ToProtobuf converts an intrinsics Authority to protobuf Authority
func (a *Authority) ToProtobuf() *protobufs.Authority {
	if a == nil {
		return nil
	}
	return &protobufs.Authority{
		KeyType:   uint32(a.KeyType),
		PublicKey: a.PublicKey,
		CanBurn:   a.CanBurn,
	}
}

// FromProtobuf converts a protobuf FeeBasis to intrinsics FeeBasis
func FeeBasisFromProtobuf(pb *protobufs.FeeBasis) (*FeeBasis, error) {
	if pb == nil {
		return nil, nil
	}

	baseline := new(big.Int)
	if len(pb.Baseline) > 0 {
		baseline.SetBytes(pb.Baseline)
	}

	return &FeeBasis{
		Type:     FeeBasisType(pb.Type),
		Baseline: baseline,
	}, nil
}

// ToProtobuf converts an intrinsics FeeBasis to protobuf FeeBasis
func (f *FeeBasis) ToProtobuf() *protobufs.FeeBasis {
	if f == nil {
		return nil
	}

	var baseline []byte
	if f.Baseline != nil {
		baseline = f.Baseline.Bytes()
	}

	return &protobufs.FeeBasis{
		Type:     protobufs.FeeBasisType(f.Type),
		Baseline: baseline,
	}
}

// FromProtobuf converts a protobuf TokenMintStrategy to intrinsics
// TokenMintStrategy
func TokenMintStrategyFromProtobuf(pb *protobufs.TokenMintStrategy) (
	*TokenMintStrategy,
	error,
) {
	if pb == nil {
		return nil, nil
	}

	authority, err := AuthorityFromProtobuf(pb.Authority)
	if err != nil {
		return nil, errors.Wrap(err, "converting authority")
	}

	feeBasis, err := FeeBasisFromProtobuf(pb.FeeBasis)
	if err != nil {
		return nil, errors.Wrap(err, "converting fee basis")
	}

	return &TokenMintStrategy{
		MintBehavior:   TokenMintBehavior(pb.MintBehavior),
		ProofBasis:     ProofBasisType(pb.ProofBasis),
		VerkleRoot:     pb.VerkleRoot,
		Authority:      authority,
		PaymentAddress: pb.PaymentAddress,
		FeeBasis:       feeBasis,
	}, nil
}

// ToProtobuf converts an intrinsics TokenMintStrategy to protobuf
// TokenMintStrategy
func (t *TokenMintStrategy) ToProtobuf() *protobufs.TokenMintStrategy {
	if t == nil {
		return nil
	}

	return &protobufs.TokenMintStrategy{
		MintBehavior:   protobufs.TokenMintBehavior(t.MintBehavior),
		ProofBasis:     protobufs.ProofBasisType(t.ProofBasis),
		VerkleRoot:     t.VerkleRoot,
		Authority:      t.Authority.ToProtobuf(),
		PaymentAddress: t.PaymentAddress,
		FeeBasis:       t.FeeBasis.ToProtobuf(),
	}
}

// FromProtobuf converts a protobuf TokenDeploy to intrinsics TokenDeploy
func TokenDeployFromProtobuf(
	pb *protobufs.TokenDeploy,
) (*TokenDeploy, error) {
	if pb == nil {
		return nil, nil
	}

	config, err := TokenConfigurationFromProtobuf(pb.Config)
	if err != nil {
		return nil, errors.Wrap(err, "token deploy from protobuf")
	}

	return &TokenDeploy{
		Config:    config,
		RDFSchema: pb.RdfSchema,
	}, nil
}

// ToProtobuf converts an intrinsics TokenDeploy to protobuf TokenDeploy
func (
	t *TokenDeploy,
) ToProtobuf() *protobufs.TokenDeploy {
	if t == nil {
		return nil
	}

	return &protobufs.TokenDeploy{
		Config:    t.Config.ToProtobuf(),
		RdfSchema: t.RDFSchema,
	}
}

// FromProtobuf converts a protobuf TokenUpdate to intrinsics TokenUpdate
func TokenUpdateFromProtobuf(
	pb *protobufs.TokenUpdate,
) (*TokenUpdate, error) {
	if pb == nil {
		return nil, nil
	}

	config, err := TokenConfigurationFromProtobuf(pb.Config)
	if err != nil {
		return nil, errors.Wrap(err, "token update from protobuf")
	}

	return &TokenUpdate{
		Config:         config,
		RDFSchema:      pb.RdfSchema,
		OwnerSignature: pb.PublicKeySignatureBls48581,
	}, nil
}

// ToProtobuf converts an intrinsics TokenUpdate to protobuf TokenUpdate
func (
	t *TokenUpdate,
) ToProtobuf() *protobufs.TokenUpdate {
	if t == nil {
		return nil
	}

	return &protobufs.TokenUpdate{
		Config:                     t.Config.ToProtobuf(),
		RdfSchema:                  t.RDFSchema,
		PublicKeySignatureBls48581: t.OwnerSignature,
	}
}

// FromProtobuf converts a protobuf TokenConfiguration to intrinsics
// TokenIntrinsicConfiguration
func TokenConfigurationFromProtobuf(pb *protobufs.TokenConfiguration) (
	*TokenIntrinsicConfiguration,
	error,
) {
	if pb == nil {
		return nil, nil
	}

	mintStrategy, err := TokenMintStrategyFromProtobuf(pb.MintStrategy)
	if err != nil {
		return nil, errors.Wrap(err, "converting mint strategy")
	}

	var units *big.Int
	if len(pb.Units) > 0 {
		units = new(big.Int).SetBytes(pb.Units)
	}

	var supply *big.Int
	if len(pb.Supply) > 0 {
		supply = new(big.Int).SetBytes(pb.Supply)
	}

	// Convert AdditionalReference from [][]byte to [64]byte
	var additionalRef [64]byte
	if len(pb.AdditionalReference) > 0 && len(pb.AdditionalReference[0]) > 0 {
		copy(additionalRef[:], pb.AdditionalReference[0])
	}

	return &TokenIntrinsicConfiguration{
		Behavior:            TokenIntrinsicBehavior(pb.Behavior),
		MintStrategy:        mintStrategy,
		Units:               units,
		Supply:              supply,
		Name:                pb.Name,
		Symbol:              pb.Symbol,
		AdditionalReference: additionalRef,
	}, nil
}

// ToProtobuf converts an intrinsics TokenIntrinsicConfiguration to protobuf
// TokenConfiguration
func (
	t *TokenIntrinsicConfiguration,
) ToProtobuf() *protobufs.TokenConfiguration {
	if t == nil {
		return nil
	}

	var units []byte
	if t.Units != nil {
		units = t.Units.Bytes()
	}

	var supply []byte
	if t.Supply != nil {
		supply = t.Supply.Bytes()
	}

	return &protobufs.TokenConfiguration{
		Behavior:            uint32(t.Behavior),
		MintStrategy:        t.MintStrategy.ToProtobuf(),
		Units:               units,
		Supply:              supply,
		Name:                t.Name,
		Symbol:              t.Symbol,
		AdditionalReference: [][]byte{t.AdditionalReference[:]},
	}
}

// FromProtobuf converts a protobuf RecipientBundle to intrinsics
// RecipientBundle
func RecipientBundleFromProtobuf(pb *protobufs.RecipientBundle) (
	*RecipientBundle,
	error,
) {
	if pb == nil {
		return nil, nil
	}

	// Validate field lengths
	if len(pb.OneTimeKey) != 56 {
		return nil, errors.Errorf(
			"invalid OneTimeKey length: expected 56, got %d",
			len(pb.OneTimeKey),
		)
	}
	if len(pb.VerificationKey) != 56 {
		return nil, errors.Errorf(
			"invalid VerificationKey length: expected 56, got %d",
			len(pb.VerificationKey),
		)
	}
	if len(pb.CoinBalance) != 56 {
		return nil, errors.Errorf(
			"invalid CoinBalance length: expected 56, got %d",
			len(pb.CoinBalance),
		)
	}
	if len(pb.Mask) != 56 {
		return nil, errors.Errorf(
			"invalid Mask length: expected 56, got %d",
			len(pb.Mask),
		)
	}
	if len(pb.AdditionalReference) != 0 && len(pb.AdditionalReference) != 64 {
		return nil, errors.Errorf(
			"invalid AdditionalReference length: expected 0 or 64, got %d",
			len(pb.AdditionalReference),
		)
	}
	if len(pb.AdditionalReferenceKey) != 0 && len(pb.AdditionalReferenceKey) != 56 {
		return nil, errors.Errorf(
			"invalid AdditionalReferenceKey length: expected 0 or 56, got %d",
			len(pb.AdditionalReferenceKey),
		)
	}

	return &RecipientBundle{
		OneTimeKey:             pb.OneTimeKey,
		VerificationKey:        pb.VerificationKey,
		CoinBalance:            pb.CoinBalance,
		Mask:                   pb.Mask,
		AdditionalReference:    pb.AdditionalReference,
		AdditionalReferenceKey: pb.AdditionalReferenceKey,
	}, nil
}

// ToProtobuf converts an intrinsics RecipientBundle to protobuf RecipientBundle
func (r *RecipientBundle) ToProtobuf() *protobufs.RecipientBundle {
	if r == nil {
		return nil
	}

	return &protobufs.RecipientBundle{
		OneTimeKey:             r.OneTimeKey,
		VerificationKey:        r.VerificationKey,
		CoinBalance:            r.CoinBalance,
		Mask:                   r.Mask,
		AdditionalReference:    r.AdditionalReference,
		AdditionalReferenceKey: r.AdditionalReferenceKey,
	}
}

// FromProtobuf converts a protobuf TransactionInput to intrinsics
// TransactionInput
func TransactionInputFromProtobuf(pb *protobufs.TransactionInput) (
	*TransactionInput,
	error,
) {
	if pb == nil {
		return nil, nil
	}

	return &TransactionInput{
		Commitment: pb.Commitment,
		Signature:  pb.Signature,
		Proofs:     pb.Proofs,
	}, nil
}

// ToProtobuf converts an intrinsics TransactionInput to protobuf
// TransactionInput
func (t *TransactionInput) ToProtobuf() *protobufs.TransactionInput {
	if t == nil {
		return nil
	}

	return &protobufs.TransactionInput{
		Commitment: t.Commitment,
		Signature:  t.Signature,
		Proofs:     t.Proofs,
	}
}

// FromProtobuf converts a protobuf TransactionOutput to intrinsics
// TransactionOutput
func TransactionOutputFromProtobuf(pb *protobufs.TransactionOutput) (
	*TransactionOutput,
	error,
) {
	if pb == nil {
		return nil, nil
	}

	recipientOutput, err := RecipientBundleFromProtobuf(pb.RecipientOutput)
	if err != nil {
		return nil, errors.Wrap(err, "converting recipient output")
	}

	return &TransactionOutput{
		FrameNumber:     pb.FrameNumber,
		Commitment:      pb.Commitment,
		RecipientOutput: *recipientOutput,
	}, nil
}

// ToProtobuf converts an intrinsics TransactionOutput to protobuf
// TransactionOutput
func (t *TransactionOutput) ToProtobuf() *protobufs.TransactionOutput {
	if t == nil {
		return nil
	}

	return &protobufs.TransactionOutput{
		FrameNumber:     t.FrameNumber,
		Commitment:      t.Commitment,
		RecipientOutput: t.RecipientOutput.ToProtobuf(),
	}
}

// FromProtobuf converts a protobuf Transaction to intrinsics Transaction
func TransactionFromProtobuf(
	pb *protobufs.Transaction,
	inclusionProver crypto.InclusionProver,
) (*Transaction, error) {
	if pb == nil {
		return nil, nil
	}

	// Convert domain from slice to array
	var domain [32]byte
	copy(domain[:], pb.Domain)

	// Convert inputs
	inputs := make([]*TransactionInput, len(pb.Inputs))
	for i, input := range pb.Inputs {
		converted, err := TransactionInputFromProtobuf(input)
		if err != nil {
			return nil, errors.Wrapf(err, "converting input %d", i)
		}
		inputs[i] = converted
	}

	// Convert outputs
	outputs := make([]*TransactionOutput, len(pb.Outputs))
	for i, output := range pb.Outputs {
		converted, err := TransactionOutputFromProtobuf(output)
		if err != nil {
			return nil, errors.Wrapf(err, "converting output %d", i)
		}
		outputs[i] = converted
	}

	// Convert fees from [][]byte to []*big.Int
	fees := make([]*big.Int, len(pb.Fees))
	for i, fee := range pb.Fees {
		fees[i] = new(big.Int).SetBytes(fee)
	}

	proof, err := TraversalProofFromProtobuf(pb.TraversalProof, inclusionProver)
	if err != nil {
		return nil, err
	}

	return &Transaction{
		Domain:         domain,
		Inputs:         inputs,
		Outputs:        outputs,
		Fees:           fees,
		RangeProof:     pb.RangeProof,
		TraversalProof: proof,
		// Runtime dependencies will be injected separately
	}, nil
}

// ToProtobuf converts an intrinsics Transaction to protobuf Transaction
func (t *Transaction) ToProtobuf() *protobufs.Transaction {
	if t == nil {
		return nil
	}

	// Convert inputs
	inputs := make([]*protobufs.TransactionInput, len(t.Inputs))
	for i, input := range t.Inputs {
		inputs[i] = input.ToProtobuf()
	}

	// Convert outputs
	outputs := make([]*protobufs.TransactionOutput, len(t.Outputs))
	for i, output := range t.Outputs {
		outputs[i] = output.ToProtobuf()
	}

	// Convert fees from []*big.Int to [][]byte
	fees := make([][]byte, len(t.Fees))
	for i, fee := range t.Fees {
		if fee != nil {
			fees[i] = fee.Bytes()
		}
	}

	// Convert TraversalProof if present
	var traversalProof *protobufs.TraversalProof
	if t.TraversalProof != nil {
		// Convert qcrypto.TraversalProof to protobufs.TraversalProof
		traversalProof = TraversalProofToProtobuf(t.TraversalProof)
	}

	return &protobufs.Transaction{
		Domain:         t.Domain[:],
		Inputs:         inputs,
		Outputs:        outputs,
		Fees:           fees,
		RangeProof:     t.RangeProof,
		TraversalProof: traversalProof,
	}
}

// FromProtobuf converts a protobuf PendingTransactionInput to intrinsics
// PendingTransactionInput
func PendingTransactionInputFromProtobuf(
	pb *protobufs.PendingTransactionInput,
) (*PendingTransactionInput, error) {
	if pb == nil {
		return nil, nil
	}

	return &PendingTransactionInput{
		Commitment: pb.Commitment,
		Signature:  pb.Signature,
		Proofs:     pb.Proofs,
	}, nil
}

// ToProtobuf converts an intrinsics PendingTransactionInput to protobuf
// PendingTransactionInput
func (
	p *PendingTransactionInput,
) ToProtobuf() *protobufs.PendingTransactionInput {
	if p == nil {
		return nil
	}

	return &protobufs.PendingTransactionInput{
		Commitment: p.Commitment,
		Signature:  p.Signature,
		Proofs:     p.Proofs,
	}
}

// FromProtobuf converts a protobuf PendingTransactionOutput to intrinsics
// PendingTransactionOutput
func PendingTransactionOutputFromProtobuf(
	pb *protobufs.PendingTransactionOutput,
) (*PendingTransactionOutput, error) {
	if pb == nil {
		return nil, nil
	}

	toOutput, err := RecipientBundleFromProtobuf(pb.To)
	if err != nil {
		return nil, errors.Wrap(err, "converting to output")
	}

	refundOutput, err := RecipientBundleFromProtobuf(pb.Refund)
	if err != nil {
		return nil, errors.Wrap(err, "converting refund output")
	}

	return &PendingTransactionOutput{
		FrameNumber:  pb.FrameNumber,
		Commitment:   pb.Commitment,
		ToOutput:     *toOutput,
		RefundOutput: *refundOutput,
		Expiration:   pb.Expiration,
	}, nil
}

// ToProtobuf converts an intrinsics PendingTransactionOutput to protobuf
// PendingTransactionOutput
func (
	p *PendingTransactionOutput,
) ToProtobuf() *protobufs.PendingTransactionOutput {
	if p == nil {
		return nil
	}

	return &protobufs.PendingTransactionOutput{
		FrameNumber: p.FrameNumber,
		Commitment:  p.Commitment,
		To:          p.ToOutput.ToProtobuf(),
		Refund:      p.RefundOutput.ToProtobuf(),
		Expiration:  p.Expiration,
	}
}

// FromProtobuf converts a protobuf PendingTransaction to intrinsics
// PendingTransaction
func PendingTransactionFromProtobuf(
	pb *protobufs.PendingTransaction,
	inclusionProver crypto.InclusionProver,
) (
	*PendingTransaction,
	error,
) {
	if pb == nil {
		return nil, nil
	}

	// Convert domain from slice to array
	var domain [32]byte
	copy(domain[:], pb.Domain)

	// Convert inputs
	inputs := make([]*PendingTransactionInput, len(pb.Inputs))
	for i, input := range pb.Inputs {
		converted, err := PendingTransactionInputFromProtobuf(input)
		if err != nil {
			return nil, errors.Wrapf(err, "converting input %d", i)
		}
		inputs[i] = converted
	}

	// Convert outputs
	outputs := make([]*PendingTransactionOutput, len(pb.Outputs))
	for i, output := range pb.Outputs {
		converted, err := PendingTransactionOutputFromProtobuf(output)
		if err != nil {
			return nil, errors.Wrapf(err, "converting output %d", i)
		}
		outputs[i] = converted
	}

	// Convert fees from [][]byte to []*big.Int
	fees := make([]*big.Int, len(pb.Fees))
	for i, fee := range pb.Fees {
		fees[i] = new(big.Int).SetBytes(fee)
	}

	proof, err := TraversalProofFromProtobuf(pb.TraversalProof, inclusionProver)
	if err != nil {
		return nil, err
	}

	return &PendingTransaction{
		Domain:         domain,
		Inputs:         inputs,
		Outputs:        outputs,
		Fees:           fees,
		RangeProof:     pb.RangeProof,
		TraversalProof: proof,
		// Runtime dependencies will be injected separately
	}, nil
}

// ToProtobuf converts an intrinsics PendingTransaction to protobuf
// PendingTransaction
func (p *PendingTransaction) ToProtobuf() *protobufs.PendingTransaction {
	if p == nil {
		return nil
	}

	// Convert inputs
	inputs := make([]*protobufs.PendingTransactionInput, len(p.Inputs))
	for i, input := range p.Inputs {
		inputs[i] = input.ToProtobuf()
	}

	// Convert outputs
	outputs := make([]*protobufs.PendingTransactionOutput, len(p.Outputs))
	for i, output := range p.Outputs {
		outputs[i] = output.ToProtobuf()
	}

	// Convert fees from []*big.Int to [][]byte
	fees := make([][]byte, len(p.Fees))
	for i, fee := range p.Fees {
		if fee != nil {
			fees[i] = fee.FillBytes(make([]byte, 32))
		}
	}

	// Convert TraversalProof if present
	var traversalProof *protobufs.TraversalProof
	if p.TraversalProof != nil {
		traversalProof = TraversalProofToProtobuf(p.TraversalProof)
	}

	return &protobufs.PendingTransaction{
		Domain:         p.Domain[:],
		Inputs:         inputs,
		Outputs:        outputs,
		Fees:           fees,
		RangeProof:     p.RangeProof,
		TraversalProof: traversalProof,
	}
}

// FromProtobuf converts a protobuf MintTransactionInput to intrinsics
// MintTransactionInput
func MintTransactionInputFromProtobuf(pb *protobufs.MintTransactionInput) (
	*MintTransactionInput,
	error,
) {
	if pb == nil {
		return nil, nil
	}

	// Convert value from bytes to big.Int
	value := new(big.Int)
	if len(pb.Value) > 0 {
		value.SetBytes(pb.Value)
	}

	return &MintTransactionInput{
		Value:                  value,
		Commitment:             pb.Commitment,
		Signature:              pb.Signature,
		Proofs:                 pb.Proofs,
		AdditionalReference:    pb.AdditionalReference,
		AdditionalReferenceKey: pb.AdditionalReferenceKey,
	}, nil
}

// ToProtobuf converts an intrinsics MintTransactionInput to protobuf
// MintTransactionInput
func (m *MintTransactionInput) ToProtobuf() *protobufs.MintTransactionInput {
	if m == nil {
		return nil
	}

	var valueBytes []byte
	if m.Value != nil {
		valueBytes = m.Value.Bytes()
	}

	return &protobufs.MintTransactionInput{
		Value:                  valueBytes,
		Commitment:             m.Commitment,
		Signature:              m.Signature,
		Proofs:                 m.Proofs,
		AdditionalReference:    m.AdditionalReference,
		AdditionalReferenceKey: m.AdditionalReferenceKey,
	}
}

// FromProtobuf converts a protobuf MintTransactionOutput to intrinsics
// MintTransactionOutput
func MintTransactionOutputFromProtobuf(pb *protobufs.MintTransactionOutput) (
	*MintTransactionOutput,
	error,
) {
	if pb == nil {
		return nil, nil
	}

	recipientOutput, err := RecipientBundleFromProtobuf(pb.RecipientOutput)
	if err != nil {
		return nil, errors.Wrap(err, "converting recipient output")
	}

	return &MintTransactionOutput{
		FrameNumber:     pb.FrameNumber,
		Commitment:      pb.Commitment,
		RecipientOutput: *recipientOutput,
	}, nil
}

// ToProtobuf converts an intrinsics MintTransactionOutput to protobuf
// MintTransactionOutput
func (m *MintTransactionOutput) ToProtobuf() *protobufs.MintTransactionOutput {
	if m == nil {
		return nil
	}

	return &protobufs.MintTransactionOutput{
		FrameNumber:     m.FrameNumber,
		Commitment:      m.Commitment,
		RecipientOutput: m.RecipientOutput.ToProtobuf(),
	}
}

// FromProtobuf converts a protobuf MintTransaction to intrinsics
// MintTransaction
func MintTransactionFromProtobuf(pb *protobufs.MintTransaction) (
	*MintTransaction,
	error,
) {
	if pb == nil {
		return nil, nil
	}

	// Convert domain from slice to array
	var domain [32]byte
	copy(domain[:], pb.Domain)

	// Convert inputs
	inputs := make([]*MintTransactionInput, len(pb.Inputs))
	for i, input := range pb.Inputs {
		converted, err := MintTransactionInputFromProtobuf(input)
		if err != nil {
			return nil, errors.Wrapf(err, "converting input %d", i)
		}
		inputs[i] = converted
	}

	// Convert outputs
	outputs := make([]*MintTransactionOutput, len(pb.Outputs))
	for i, output := range pb.Outputs {
		converted, err := MintTransactionOutputFromProtobuf(output)
		if err != nil {
			return nil, errors.Wrapf(err, "converting output %d", i)
		}
		outputs[i] = converted
	}

	// Convert fees from [][]byte to []*big.Int
	fees := make([]*big.Int, len(pb.Fees))
	for i, fee := range pb.Fees {
		fees[i] = new(big.Int).SetBytes(fee)
	}

	return &MintTransaction{
		Domain:     domain,
		Inputs:     inputs,
		Outputs:    outputs,
		Fees:       fees,
		RangeProof: pb.RangeProof,
		// Runtime dependencies will be injected separately
	}, nil
}

// ToProtobuf converts an intrinsics MintTransaction to protobuf MintTransaction
func (m *MintTransaction) ToProtobuf() *protobufs.MintTransaction {
	if m == nil {
		return nil
	}

	// Convert inputs
	inputs := make([]*protobufs.MintTransactionInput, len(m.Inputs))
	for i, input := range m.Inputs {
		inputs[i] = input.ToProtobuf()
	}

	// Convert outputs
	outputs := make([]*protobufs.MintTransactionOutput, len(m.Outputs))
	for i, output := range m.Outputs {
		outputs[i] = output.ToProtobuf()
	}

	// Convert fees from []*big.Int to [][]byte
	fees := make([][]byte, len(m.Fees))
	for i, fee := range m.Fees {
		if fee != nil {
			fees[i] = fee.Bytes()
		}
	}

	return &protobufs.MintTransaction{
		Domain:     m.Domain[:],
		Inputs:     inputs,
		Outputs:    outputs,
		Fees:       fees,
		RangeProof: m.RangeProof,
		// Note: MintProof is not available in intrinsics structure
	}
}

// TraversalProofToProtobuf converts qcrypto.TraversalProof to
// protobufs.TraversalProof
func TraversalProofToProtobuf(
	tp *tries.TraversalProof,
) *protobufs.TraversalProof {
	if tp == nil {
		return nil
	}

	// Convert Multiproof
	var multiproof *protobufs.Multiproof
	if tp.Multiproof != nil {
		multiproofBytes, _ := tp.Multiproof.ToBytes()
		// Split the bytes - assuming first part is multicommitment, rest is proof
		// This needs to match how the Multiproof is serialized
		if len(multiproofBytes) > 0 {
			multiproof = &protobufs.Multiproof{
				Multicommitment: multiproofBytes[:min(74, len(multiproofBytes))],
				Proof:           multiproofBytes[min(74, len(multiproofBytes)):],
			}
		}
	}

	// Convert SubProofs
	var subProofs []*protobufs.TraversalSubProof
	for _, sp := range tp.SubProofs {
		// Convert paths from [][]uint64 to []*protobufs.Path
		var paths []*protobufs.Path
		for _, path := range sp.Paths {
			paths = append(paths, &protobufs.Path{
				Indices: path,
			})
		}

		subProofs = append(subProofs, &protobufs.TraversalSubProof{
			Commits: sp.Commits,
			Ys:      sp.Ys,
			Paths:   paths,
		})
	}

	return &protobufs.TraversalProof{
		Multiproof: multiproof,
		SubProofs:  subProofs,
	}
}

// TraversalProofFromProtobuf converts protobufs.TraversalProof to
// qcrypto.TraversalProof
func TraversalProofFromProtobuf(
	pb *protobufs.TraversalProof,
	inclusionProver crypto.InclusionProver,
) (*tries.TraversalProof, error) {
	if pb == nil {
		return nil, nil
	}

	tp := &tries.TraversalProof{}

	// Convert Multiproof if present
	if pb.Multiproof != nil && inclusionProver != nil {
		mp := inclusionProver.NewMultiproof()
		// Reconstruct the multiproof from its components
		multiproofBytes := append(
			pb.Multiproof.Multicommitment,
			pb.Multiproof.Proof...,
		)
		if err := mp.FromBytes(multiproofBytes); err != nil {
			return nil, errors.Wrap(err, "deserializing multiproof")
		}
		tp.Multiproof = mp
	}

	// Convert SubProofs
	for _, pbSubProof := range pb.SubProofs {
		// Convert paths from []*protobufs.Path to [][]uint64
		var paths [][]uint64
		for _, path := range pbSubProof.Paths {
			paths = append(paths, path.Indices)
		}

		tp.SubProofs = append(tp.SubProofs, tries.TraversalSubProof{
			Commits: pbSubProof.Commits,
			Ys:      pbSubProof.Ys,
			Paths:   paths,
		})
	}

	return tp, nil
}
