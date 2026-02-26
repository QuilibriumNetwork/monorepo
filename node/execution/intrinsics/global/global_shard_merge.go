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

type ShardMergeOp struct {
	ShardAddresses             [][]byte
	ParentAddress              []byte
	FrameNumber                uint64
	PublicKeySignatureBLS48581 BLS48581AddressedSignature

	hypergraph     hypergraph.Hypergraph
	keyManager     keys.KeyManager
	shardsStore    store.ShardsStore
	proverRegistry consensus.ProverRegistry
}

func NewShardMergeOp(
	shardAddresses [][]byte,
	parentAddress []byte,
	keyManager keys.KeyManager,
	shardsStore store.ShardsStore,
	proverRegistry consensus.ProverRegistry,
) *ShardMergeOp {
	return &ShardMergeOp{
		ShardAddresses: shardAddresses,
		ParentAddress:  parentAddress,
		keyManager:     keyManager,
		shardsStore:    shardsStore,
		proverRegistry: proverRegistry,
	}
}

func (op *ShardMergeOp) GetCost() (*big.Int, error) {
	return big.NewInt(0), nil
}

func (op *ShardMergeOp) Verify(frameNumber uint64) (bool, error) {
	if op.proverRegistry == nil {
		return false, errors.New("prover registry not initialized")
	}

	// Validate shard addresses
	if len(op.ShardAddresses) < 2 || len(op.ShardAddresses) > 8 {
		return false, errors.New("shard_addresses must have 2-8 entries")
	}

	if len(op.ParentAddress) != 32 {
		return false, errors.New("parent_address must be 32 bytes")
	}

	for _, addr := range op.ShardAddresses {
		if len(addr) <= 32 {
			return false, errors.New(
				"cannot merge base shards (must be > 32 bytes)",
			)
		}
		if !bytes.HasPrefix(addr, op.ParentAddress) {
			return false, errors.New(
				"all shard addresses must share the parent address prefix",
			)
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
		op.ParentAddress,
	)

	mergeDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("SHARD_MERGE"),
	)
	mergeDomain, err := poseidon.HashBytes(mergeDomainPreimage)
	if err != nil {
		return false, errors.Wrap(err, "verify: invalid shard merge")
	}

	ok, err := op.keyManager.ValidateSignature(
		crypto.KeyTypeBLS48581G1,
		pubKey,
		signedData,
		op.PublicKeySignatureBLS48581.Signature,
		mergeDomain.Bytes(),
	)
	if err != nil || !ok {
		return false, errors.Wrap(
			errors.New("invalid BLS signature"),
			"verify: invalid shard merge",
		)
	}

	// Verify all shards have fewer provers than minimum threshold
	globalProvers, err := op.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		return false, errors.Wrap(err, "verify: invalid shard merge: min provers")
	}
	minP := uint64(len(globalProvers)) * 2 / 3
	if minP > 6 {
		minP = 6
	}

	for _, addr := range op.ShardAddresses {
		count, err := op.proverRegistry.GetProverCount(addr)
		if err != nil {
			return false, errors.Wrap(err, "verify: invalid shard merge: prover count")
		}
		if uint64(count) >= minP {
			return false, errors.Errorf(
				"shard has %d provers (min threshold %d), merge not eligible",
				count, minP,
			)
		}
	}

	return true, nil
}

func (op *ShardMergeOp) Materialize(
	frameNumber uint64,
	s state.State,
) (state.State, error) {
	if op.shardsStore == nil {
		return nil, errors.New("shards store not initialized")
	}

	// Remove each sub-shard address from the shards store
	for _, shardAddr := range op.ShardAddresses {
		// Extract L2 (first 32 bytes) and Path (remaining bytes as uint32s)
		shardKey := shardAddr[:32]
		path := make([]uint32, 0, len(shardAddr)-32)
		for _, b := range shardAddr[32:] {
			path = append(path, uint32(b))
		}

		err := op.shardsStore.DeleteAppShard(nil, shardKey, path)
		if err != nil {
			return nil, errors.Wrap(err, "materialize shard merge")
		}
	}

	return s, nil
}

func (op *ShardMergeOp) Prove(frameNumber uint64) error {
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
		op.ParentAddress,
	)

	mergeDomainPreimage := slices.Concat(
		intrinsics.GLOBAL_INTRINSIC_ADDRESS[:],
		[]byte("SHARD_MERGE"),
	)
	mergeDomain, err := poseidon.HashBytes(mergeDomainPreimage)
	if err != nil {
		return errors.Wrap(err, "prove")
	}

	signature, err := signingKey.SignWithDomain(
		signedData,
		mergeDomain.Bytes(),
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

func (op *ShardMergeOp) GetReadAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	return nil, nil
}

func (op *ShardMergeOp) GetWriteAddresses(
	frameNumber uint64,
) ([][]byte, error) {
	// Shard merge writes to the shard addresses being removed
	addresses := make([][]byte, 0, len(op.ShardAddresses))
	for _, addr := range op.ShardAddresses {
		fullAddr := [64]byte{}
		copy(fullAddr[:32], intrinsics.GLOBAL_INTRINSIC_ADDRESS[:])
		copy(fullAddr[32:], addr)
		addresses = append(addresses, fullAddr[:])
	}
	return addresses, nil
}

var _ intrinsics.IntrinsicOperation = (*ShardMergeOp)(nil)
