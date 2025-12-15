package aggregator

import (
	"github.com/pkg/errors"

	"source.quilibrium.com/quilibrium/monorepo/bls48581"
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
	noextSigs := [][]byte{}
	if len(c.filter) != 0 {
		for _, s := range signatures {
			noextSigs = append(noextSigs, s[:74])
		}
	} else {
		noextSigs = signatures // buildutils:allow-slice-alias slice will not mutate
	}

	output, err := c.blsConstructor.Aggregate(
		publicKeys,
		noextSigs,
	)
	if err != nil {
		return nil, errors.Wrap(err, "aggregate")
	}

	provers, err := c.provers.GetActiveProvers(c.filter)
	if err != nil {
		return nil, errors.Wrap(err, "aggregate")
	}

	pubs := map[string]int{}
	for i, p := range publicKeys {
		pubs[string(p)] = i
	}

	bitmask := make([]byte, (len(provers)+7)/8)
	extra := []byte{}
	if len(c.filter) != 0 {
		extra = make([]byte, 516*(len(provers)-1))
	}
	adj := 0
	for i, p := range provers {
		if j, ok := pubs[string(p.PublicKey)]; ok {
			bitmask[i/8] |= (1 << (i % 8))

			if len(c.filter) != 0 && len(signatures[j]) > 74 {
				copy(extra[516*adj:516*(adj+1)], signatures[j][74:])
				adj++
			}
		}
	}

	// TODO: remove direct reference
	if len(c.filter) != 0 {
		output.(*bls48581.BlsAggregateOutput).AggregateSignature =
			append(output.(*bls48581.BlsAggregateOutput).AggregateSignature, extra...)
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
