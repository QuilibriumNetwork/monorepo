package global

import (
	"bytes"
	"math/big"
	"slices"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/intrinsics"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

const maxProversThreshold = 32

type ShardSplitOp struct {
	ShardAddress               []byte
	ProposedShards             [][]byte
	FrameNumber                uint64
	PublicKeySignatureBLS48581 BLS48581AddressedSignature

	hypergraph     hypergraph.Hypergraph
	keyManager     keys.KeyManager
	shardsStore    store.ShardsStore
	proverRegistry consensus.ProverRegistry
}

func NewShardSplitOp(
	shardAddress []byte,
	proposedShards [][]byte,
	keyManager keys.KeyManager,
	shardsStore store.ShardsStore,
	proverRegistry consensus.ProverRegistry,
) *ShardSplitOp {
	return &ShardSplitOp{
		ShardAddress:   shardAddress,
		ProposedShards: proposedShards,
		keyManager:     keyManager,
		shardsStore:    shardsStore,
		proverRegistry: proverRegistry,
	}
}

func (op *ShardSplitOp) GetCost() (*big.Int, error) {
	return big.NewInt(0), nil
}

func (op *ShardSplitOp) Verify(frameNumber uint64) (bool, error) {
	if op.proverRegistry == nil {
		return false, errors.New("prover registry not initialized")
	}

	// Validate shard address length
	if len(op.ShardAddress) < 32 || len(op.ShardAddress) > 63 {
		return false, errors.New("shard_address must be 32-63 bytes")
	}

	// Validate proposed shards
	if len(op.ProposedShards) < 2 || len(op.ProposedShards) > 8 {
		return false, errors.New("proposed_shards must have 2-8 entries")
	}

	for _, shard := range op.ProposedShards {
		if len(shard) != len(op.ShardAddress)+1 &&
			len(shard) != len(op.ShardAddress)+2 {
			return false, errors.Errorf(
				"proposed shard length %d invalid for parent length %d",
				len(shard), len(op.ShardAddress),
			)
		}
		if !bytes.HasPrefix(shard, op.ShardAddress) {
			return false, errors.New("proposed shard must share parent prefix")
		}
	}

	// Look up the public key from the prover registry using the address
	address := op.PublicKeySignatureBLS48581.Address
	if len(address) != 32 {
		return false, errors.New("invalid address length")
	}

	info, err := op.proverRegistry.GetProverInfo(address)
	if err != nil || info == nil {
		return false, errors.New("signer is not a registered prover")
	}

	hasGlobal := false
	for _, alloc := range info.Allocations {
		if alloc.ConfirmationFilter == nil &&
			alloc.Status == consensus.ProverStatusActive {
			hasGlobal = true
			break
		}
	}
	if !hasGlobal {
		return false, errors.New("signer is not an active global prover")
	}

	pubKey := info.PublicKey

	// Verify BLS signature using the looked-up public key
	signedData := slices.Concat(
		big.NewInt(int64(op.FrameNumber)).FillBytes(make([]byte, 8)),
		op.ShardAddress,
	)

	splitDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("SHARD_SPLIT"),
	)
	splitDomain, err := poseidon.HashBytes(splitDomainPreimage)
	if err != nil {
		return false, errors.Wrap(err, "verify: invalid shard split")
	}

	ok, err := op.keyManager.ValidateSignature(
		crypto.KeyTypeBLS48581G1,
		pubKey,
		signedData,
		op.PublicKeySignatureBLS48581.Signature,
		splitDomain.Bytes(),
	)
	if err != nil || !ok {
		return false, errors.Wrap(
			errors.New("invalid BLS signature"),
			"verify: invalid shard split",
		)
	}

	// Verify shard has enough provers to warrant split (> maxProvers)
	count, err := op.proverRegistry.GetProverCount(op.ShardAddress)
	if err != nil {
		return false, errors.Wrap(err, "verify: invalid shard split: prover count")
	}
	if count <= maxProversThreshold {
		return false, errors.Errorf(
			"shard has %d provers, split requires > %d",
			count, maxProversThreshold,
		)
	}

	return true, nil
}

func (op *ShardSplitOp) Materialize(
	frameNumber uint64,
	s state.State,
) (state.State, error) {
	if op.shardsStore == nil {
		return nil, errors.New("shards store not initialized")
	}

	// Register each new sub-shard address in the shards store
	for _, proposedShard := range op.ProposedShards {
		// Extract L2 (first 32 bytes) and Path (remaining bytes as uint32s)
		l2 := proposedShard[:32]
		path := make([]uint32, 0, len(proposedShard)-32)
		for _, b := range proposedShard[32:] {
			path = append(path, uint32(b))
		}

		err := op.shardsStore.PutAppShard(nil, store.ShardInfo{
			L2:   slices.Clone(l2),
			Path: path,
		})
		if err != nil {
			return nil, errors.Wrap(err, "materialize shard split")
		}
	}

	return s, nil
}

func (op *ShardSplitOp) Prove(frameNumber uint64) error {
	if op.keyManager == nil {
		return errors.New("key manager not initialized")
	}

	signingKey, err := op.keyManager.GetSigningKey("q-prover-key")
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	pubKey := signingKey.Public().([]byte)

	// Derive the address from the public key
	addressBI, err := poseidon.HashBytes(pubKey)
	if err != nil {
		return errors.Wrap(err, "prove")
	}
	address := addressBI.FillBytes(make([]byte, 32))

	signedData := slices.Concat(
		big.NewInt(int64(frameNumber)).FillBytes(make([]byte, 8)),
		op.ShardAddress,
	)

	splitDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("SHARD_SPLIT"),
	)
	splitDomain, err := poseidon.HashBytes(splitDomainPreimage)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	signature, err := signingKey.SignWithDomain(
		signedData,
		splitDomain.Bytes(),
	)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	op.FrameNumber = frameNumber
	op.PublicKeySignatureBLS48581 = BLS48581AddressedSignature{
		Address:   address,
		Signature: signature,
	}

	return nil
}

func (op *ShardSplitOp) GetReadAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	return nil, nil
}

func (op *ShardSplitOp) GetWriteAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	// Shard split writes to shard addresses
	addresses := make([][]byte, 0, len(op.ProposedShards))
	for _, shard := range op.ProposedShards {
		addr := [64]byte{}
		copy(addr[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(addr[32:], shard)
		addresses = append(addresses, addr[:])
	}
	return addresses, nil
}

var _ intrinsics.IntrinsicOperation = (*ShardSplitOp)(nil)
