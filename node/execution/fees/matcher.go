package fees

import (
	"bytes"
	"math/big"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// Policy controls which ops PRODUCE fees and which ops CONSUME a single fee.
type Policy struct {
	// Domain whose tx/mint/pending PRODUCE fee outputs (flattened FIFO queue).
	// Typically token.QUIL_TOKEN_ADDRESS. Alt fee markets configure this
	// differently.
	ProducerDomain []byte

	// Consumers (each consumes exactly one fee, FIFO).
	ConsumeDeploy    bool
	ConsumeUpdate    bool
	ConsumeTx        bool
	ConsumePendingTx bool
	ConsumeMintTx    bool // MintTransaction (usually false; mints are free)

	// Compute ops (consumption)
	ConsumeComputeDeploy bool
	ConsumeComputeUpdate bool
	ConsumeCodeDeploy    bool
	ConsumeCodeExecute   bool
	ConsumeCodeFinalize  bool

	// Hypergraph ops (consumption)
	ConsumeHypergraphDeploy bool
	ConsumeHypergraphUpdate bool
	ConsumeVertexAdd        bool
	ConsumeVertexRemove     bool
	ConsumeHyperedgeAdd     bool
	ConsumeHyperedgeRemove  bool
}

// CollectBundleFees flattens fee outputs produced by ops in ProducerDomain.
// Operations that do not consume fees may still produce fee outputs for others.
func CollectBundleFees(
	bundle *protobufs.MessageBundle,
	pol *Policy,
) []*big.Int {
	feeQueue := []*big.Int{}

	push := func(raw [][]byte) {
		for _, b := range raw {
			if len(b) == 0 {
				continue
			}
			feeQueue = append(feeQueue, new(big.Int).SetBytes(b))
		}
	}

	for _, op := range bundle.Requests {
		switch t := op.Request.(type) {
		case *protobufs.MessageRequest_PendingTransaction:
			if t.PendingTransaction != nil &&
				bytes.Equal(t.PendingTransaction.Domain, pol.ProducerDomain) &&
				len(t.PendingTransaction.Fees) > 0 {
				push(t.PendingTransaction.Fees)
			}
		case *protobufs.MessageRequest_Transaction:
			if t.Transaction != nil &&
				bytes.Equal(t.Transaction.Domain, pol.ProducerDomain) &&
				len(t.Transaction.Fees) > 0 {
				push(t.Transaction.Fees)
			}
		case *protobufs.MessageRequest_MintTransaction:
			if t.MintTransaction != nil &&
				bytes.Equal(t.MintTransaction.Domain, pol.ProducerDomain) &&
				len(t.MintTransaction.Fees) > 0 {
				push(t.MintTransaction.Fees)
			}
		}
	}

	return feeQueue
}

// CountFeeConsumers counts how many ops in the bundle must consume a single fee
func CountFeeConsumers(bundle *protobufs.MessageBundle, pol *Policy) int {
	n := 0
	for _, op := range bundle.Requests {
		if NeedsOneFee(op, pol) {
			n++
		}
	}
	return n
}

// SanityCheck ensures there are enough fee outputs to satisfy all consumers.
func SanityCheck(feeQueue []*big.Int, consumers int) error {
	if len(feeQueue) < consumers {
		return errors.Wrap(
			errors.Wrapf(
				errors.New("insufficient fees"),
				"have %d fee outputs, need %d",
				len(feeQueue), consumers,
			),
			"sanity check",
		)
	}
	return nil
}

// NeedsOneFee says whether the given request consumes a fee under the policy.
func NeedsOneFee(req *protobufs.MessageRequest, pol *Policy) bool {
	switch req.Request.(type) {
	case *protobufs.MessageRequest_TokenDeploy:
		return pol.ConsumeDeploy
	case *protobufs.MessageRequest_TokenUpdate:
		return pol.ConsumeUpdate
	case *protobufs.MessageRequest_Transaction:
		return pol.ConsumeTx
	case *protobufs.MessageRequest_PendingTransaction:
		return pol.ConsumePendingTx
	case *protobufs.MessageRequest_MintTransaction:
		return pol.ConsumeMintTx
	case *protobufs.MessageRequest_ComputeDeploy:
		return pol.ConsumeComputeDeploy
	case *protobufs.MessageRequest_ComputeUpdate:
		return pol.ConsumeComputeUpdate
	case *protobufs.MessageRequest_CodeDeploy:
		return pol.ConsumeCodeDeploy
	case *protobufs.MessageRequest_CodeExecute:
		return pol.ConsumeCodeExecute
	case *protobufs.MessageRequest_CodeFinalize:
		return pol.ConsumeCodeFinalize
	case *protobufs.MessageRequest_HypergraphDeploy:
		return pol.ConsumeHypergraphDeploy
	case *protobufs.MessageRequest_HypergraphUpdate:
		return pol.ConsumeHypergraphUpdate
	case *protobufs.MessageRequest_VertexAdd:
		return pol.ConsumeVertexAdd
	case *protobufs.MessageRequest_VertexRemove:
		return pol.ConsumeVertexRemove
	case *protobufs.MessageRequest_HyperedgeAdd:
		return pol.ConsumeHyperedgeAdd
	case *protobufs.MessageRequest_HyperedgeRemove:
		return pol.ConsumeHyperedgeRemove
	default:
		return false
	}
}

// PopFee pops the next fee from the queue (caller should ensure availability).
func PopFee(queue *[]*big.Int) *big.Int {
	if len(*queue) == 0 {
		return big.NewInt(0)
	}
	f := (*queue)[0]
	*queue = (*queue)[1:]
	return f
}
