package aggregator

import (
	"github.com/pkg/errors"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	typesconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

type ConsensusSignatureAggregatorWrapper struct {
	blsConstructor crypto.BlsConstructor
	provers        typesconsensus.ProverRegistry
	filter         []byte
}

type ConsensusAggregatedSignature struct {
	output  crypto.BlsAggregateOutput
	bitmask []byte
}

// GetBitmask implements models.AggregatedSignature.
func (c *ConsensusAggregatedSignature) GetBitmask() []byte {
	return c.bitmask
}

// GetPubKey implements models.AggregatedSignature.
func (c *ConsensusAggregatedSignature) GetPubKey() []byte {
	return c.output.GetAggregatePublicKey()
}

// GetSignature implements models.AggregatedSignature.
func (c *ConsensusAggregatedSignature) GetSignature() []byte {
	return c.output.GetAggregateSignature()
}

// Aggregate implements consensus.SignatureAggregator.
func (c *ConsensusSignatureAggregatorWrapper) Aggregate(
	publicKeys [][]byte,
	signatures [][]byte,
) (models.AggregatedSignature, error) {
	output, err := c.blsConstructor.Aggregate(
		publicKeys,
		signatures,
	)
	if err != nil {
		return nil, errors.Wrap(err, "aggregate")
	}

	provers, err := c.provers.GetActiveProvers(c.filter)
	if err != nil {
		return nil, errors.Wrap(err, "aggregate")
	}

	pubs := map[string]struct{}{}
	for _, p := range publicKeys {
		pubs[string(p)] = struct{}{}
	}

	bitmask := make([]byte, (len(provers)+7)/8)
	for i, p := range provers {
		if _, ok := pubs[string(p.PublicKey)]; ok {
			bitmask[i/8] |= (1 << (i % 8))
		}
	}

	return &ConsensusAggregatedSignature{output, bitmask}, nil
}

// VerifySignatureMultiMessage implements consensus.SignatureAggregator.
func (c *ConsensusSignatureAggregatorWrapper) VerifySignatureMultiMessage(
	publicKeys [][]byte,
	signature []byte,
	messages [][]byte,
	context []byte,
) bool {
	panic("unsupported")
}

// VerifySignatureRaw implements consensus.SignatureAggregator.
func (c *ConsensusSignatureAggregatorWrapper) VerifySignatureRaw(
	publicKey []byte,
	signature []byte,
	message []byte,
	context []byte,
) bool {
	return c.blsConstructor.VerifySignatureRaw(
		publicKey,
		signature,
		message,
		context,
	)
}

func WrapSignatureAggregator(
	blsConstructor crypto.BlsConstructor,
	proverRegistry typesconsensus.ProverRegistry,
	filter []byte,
) consensus.SignatureAggregator {
	return &ConsensusSignatureAggregatorWrapper{
		blsConstructor,
		proverRegistry,
		filter,
	}
}
