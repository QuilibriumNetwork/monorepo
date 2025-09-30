package hypergraph

import (
	"bytes"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	hg "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

// Set to approximately 600 frames after deletion, we should reduce this as
// soon as we find a satisfactory distance.
const VERTEX_DATA_DELETION_INTERVAL = 10 * 60 * 1000

// Metadata entries for the hypergraph need to consistently occur at the same
// address – see more details in the HypergraphState.Init method
var HYPERGRAPH_METADATA_ADDRESS = bytes.Repeat([]byte{0xff}, 32)

type HypergraphState struct {
	hypergraph hypergraph.Hypergraph
	changeset  []state.StateChange
}

type VertexAddMaterializedState struct {
	hypergraph  *HypergraphState
	appAddress  [32]byte
	dataAddress [32]byte
	frameNumber uint64
	prior       *tries.VectorCommitmentTree
	data        *tries.VectorCommitmentTree
}

func (h *HypergraphState) NewVertexAddMaterializedState(
	appAddress [32]byte,
	dataAddress [32]byte,
	frameNumber uint64,
	prior *tries.VectorCommitmentTree,
	data *tries.VectorCommitmentTree,
) *VertexAddMaterializedState {
	return &VertexAddMaterializedState{
		h,
		appAddress,
		dataAddress,
		frameNumber,
		prior,
		data,
	}
}

// Commit implements state.MaterializedState.
func (v *VertexAddMaterializedState) Commit(
	txn tries.TreeBackingStoreTransaction,
) error {
	if err := v.hypergraph.hypergraph.AddVertex(txn, hg.NewVertex(
		v.appAddress,
		v.dataAddress,
		v.data.Commit(v.hypergraph.hypergraph.GetProver(), false),
		v.data.GetSize(),
	)); err != nil {
		return errors.Wrap(err, "vertex add commit")
	}

	id := slices.Concat(v.appAddress[:], v.dataAddress[:])
	err := v.hypergraph.hypergraph.SetVertexData(txn, [64]byte(id), v.data)
	if err != nil {
		return errors.Wrap(err, "vertex add commit")
	}

	shardKey := tries.ShardKey{
		L1: [3]byte(p2p.GetBloomFilterIndices(id[:32], 256, 3)),
		L2: [32]byte(append([]byte{}, id[:32]...)),
	}
	err = v.hypergraph.hypergraph.TrackChange(
		txn,
		id,
		v.prior,
		v.frameNumber,
		string(hypergraph.AddsPhaseType),
		string(hypergraph.VertexAtomType),
		shardKey,
	)

	return errors.Wrap(err, "vertex add commit")
}

// DataValue implements state.MaterializedState.
func (v *VertexAddMaterializedState) DataValue() *tries.VectorCommitmentTree {
	return v.data
}

func (v *VertexAddMaterializedState) GetVertex() hypergraph.Vertex {
	return hg.NewVertex(
		v.appAddress,
		v.dataAddress,
		v.data.Commit(v.hypergraph.hypergraph.GetProver(), false),
		v.data.GetSize(),
	)
}

type VertexRemoveMaterializedState struct {
	hypergraph   *HypergraphState
	appAddress   [32]byte
	dataAddress  [32]byte
	deleteAt     int64
	frameNumber  uint64
	prior        *tries.VectorCommitmentTree
	commitment   []byte
	originalSize *big.Int
}

func (h *HypergraphState) NewVertexRemoveMaterializedState(
	appAddress [32]byte,
	dataAddress [32]byte,
	deleteAt int64,
	frameNumber uint64,
	prior *tries.VectorCommitmentTree,
	commitment []byte,
	originalSize *big.Int,
) *VertexRemoveMaterializedState {
	return &VertexRemoveMaterializedState{
		h,
		appAddress,
		dataAddress,
		deleteAt,
		frameNumber,
		prior,
		commitment,
		originalSize,
	}
}

// Commit implements state.MaterializedState.
func (v *VertexRemoveMaterializedState) Commit(
	txn tries.TreeBackingStoreTransaction,
) error {
	id := slices.Concat(v.appAddress[:], v.dataAddress[:])

	err := v.hypergraph.hypergraph.RemoveVertex(txn, hg.NewVertex(
		v.appAddress,
		v.dataAddress,
		v.commitment,
		v.originalSize,
	))
	if err != nil {
		return errors.Wrap(err, "vertex remove commit")
	}

	shardKey := tries.ShardKey{
		L1: [3]byte(p2p.GetBloomFilterIndices(id[:32], 256, 3)),
		L2: [32]byte(append([]byte{}, id[:32]...)),
	}
	err = v.hypergraph.hypergraph.TrackChange(
		txn,
		id,
		v.prior,
		v.frameNumber,
		string(hypergraph.RemovesPhaseType),
		string(hypergraph.VertexAtomType),
		shardKey,
	)

	return errors.Wrap(err, "vertex remove commit")
}

// DataValue implements state.MaterializedState.
func (
	v *VertexRemoveMaterializedState,
) DataValue() *tries.VectorCommitmentTree {
	return nil
}

type HyperedgeAddMaterializedState struct {
	hypergraph  *HypergraphState
	frameNumber uint64
	prior       *tries.VectorCommitmentTree
	value       hypergraph.Hyperedge
}

func (h *HypergraphState) NewHyperedgeAddMaterializedState(
	frameNumber uint64,
	prior *tries.VectorCommitmentTree,
	value hypergraph.Hyperedge,
) *HyperedgeAddMaterializedState {
	return &HyperedgeAddMaterializedState{
		h,
		frameNumber,
		prior,
		value,
	}
}

// Commit implements state.MaterializedState.
func (h *HyperedgeAddMaterializedState) Commit(
	txn tries.TreeBackingStoreTransaction,
) error {
	err := h.hypergraph.hypergraph.AddHyperedge(txn, h.value)
	if err != nil {
		return errors.Wrap(err, "hyperedge add commit")
	}

	id := h.value.GetID()
	shardKey := tries.ShardKey{
		L1: [3]byte(p2p.GetBloomFilterIndices(id[:32], 256, 3)),
		L2: [32]byte(append([]byte{}, id[:32]...)),
	}
	err = h.hypergraph.hypergraph.TrackChange(
		txn,
		id[:],
		h.prior,
		h.frameNumber,
		string(hypergraph.AddsPhaseType),
		string(hypergraph.HyperedgeAtomType),
		shardKey,
	)

	return errors.Wrap(err, "hyperedge add commit")
}

// DataValue implements state.MaterializedState.
func (
	h *HyperedgeAddMaterializedState,
) DataValue() *tries.VectorCommitmentTree {
	return h.value.GetExtrinsicTree()
}

type HyperedgeRemoveMaterializedState struct {
	hypergraph  *HypergraphState
	frameNumber uint64
	prior       *tries.VectorCommitmentTree
	value       hypergraph.Hyperedge
}

func (h *HypergraphState) NewHyperedgeRemoveMaterializedState(
	frameNumber uint64,
	prior *tries.VectorCommitmentTree,
	value hypergraph.Hyperedge,
) *HyperedgeRemoveMaterializedState {
	return &HyperedgeRemoveMaterializedState{
		h,
		frameNumber,
		prior,
		value,
	}
}

// Commit implements state.MaterializedState.
func (h *HyperedgeRemoveMaterializedState) Commit(
	txn tries.TreeBackingStoreTransaction,
) error {
	err := h.hypergraph.hypergraph.RemoveHyperedge(txn, h.value)
	if err != nil {
		return errors.Wrap(err, "hyperedge remove commit")
	}

	id := h.value.GetID()
	shardKey := tries.ShardKey{
		L1: [3]byte(p2p.GetBloomFilterIndices(id[:32], 256, 3)),
		L2: [32]byte(append([]byte{}, id[:32]...)),
	}
	err = h.hypergraph.hypergraph.TrackChange(
		txn,
		id[:],
		h.prior,
		h.frameNumber,
		string(hypergraph.RemovesPhaseType),
		string(hypergraph.HyperedgeAtomType),
		shardKey,
	)

	return errors.Wrap(err, "hyperedge remove commit")
}

// DataValue implements state.MaterializedState.
func (
	h *HyperedgeRemoveMaterializedState,
) DataValue() *tries.VectorCommitmentTree {
	return nil
}

var (
	VertexAddsDiscriminator       []byte
	VertexRemovesDiscriminator    []byte
	HyperedgeAddsDiscriminator    []byte
	HyperedgeRemovesDiscriminator []byte
)

func init() {
	vertexAddsDiscriminatorBI, _ := poseidon.HashBytes(
		[]byte("vertex:adds"),
	)
	vertexRemovesDiscriminatorBI, _ := poseidon.HashBytes(
		[]byte("vertex:removes"),
	)
	hyperedgeAddsDiscriminatorBI, _ := poseidon.HashBytes(
		[]byte("hyperedge:adds"),
	)
	hyperedgeRemovesDiscriminatorBI, _ := poseidon.HashBytes(
		[]byte("hyperedge:removes"),
	)

	VertexAddsDiscriminator = make([]byte, 32)
	VertexRemovesDiscriminator = make([]byte, 32)
	HyperedgeAddsDiscriminator = make([]byte, 32)
	HyperedgeRemovesDiscriminator = make([]byte, 32)
	vertexAddsDiscriminatorBI.FillBytes(VertexAddsDiscriminator)
	vertexRemovesDiscriminatorBI.FillBytes(VertexRemovesDiscriminator)
	hyperedgeAddsDiscriminatorBI.FillBytes(HyperedgeAddsDiscriminator)
	hyperedgeRemovesDiscriminatorBI.FillBytes(HyperedgeRemovesDiscriminator)
}

func NewHypergraphState(hypergraph hypergraph.Hypergraph) *HypergraphState {
	return &HypergraphState{
		hypergraph: hypergraph,
		changeset:  []state.StateChange{},
	}
}

func (h *HypergraphState) GetProver() crypto.InclusionProver {
	return h.hypergraph.GetProver()
}

func (h *HypergraphState) sealMetadataStateAtIndex(
	metadata, subData *tries.VectorCommitmentTree,
	index byte,
	name string,
) error {
	if index > 63 {
		return errors.Wrap(state.ErrInvalidData, "seal metadata state at index")
	}

	if subData == nil {
		return errors.Wrap(
			errors.Wrap(state.ErrInvalidData, name),
			"seal metadata state at index",
		)
	}

	subDataCommit := subData.Commit(
		h.hypergraph.GetProver(),
		false,
	)

	subDataBytes, err := tries.SerializeNonLazyTree(subData)
	if err != nil {
		return errors.Wrap(errors.Wrap(err, name), "seal metadata state at index")
	}

	err = metadata.Insert(
		[]byte{index << 2}, // We move it up two bits to be in the first nibble
		subDataBytes,
		subDataCommit,
		subData.GetSize(),
	)
	if err != nil {
		return errors.Wrap(errors.Wrap(err, name), "seal metadata state at index")
	}

	return nil
}

func unsealMetadataStateAtIndex(
	metadata *tries.VectorCommitmentTree,
	index byte,
	name string,
) (*tries.VectorCommitmentTree, error) {
	if index > 63 {
		return nil, errors.Wrap(
			state.ErrInvalidData,
			"unseal metadata state at index",
		)
	}

	// We move it up two bits to be in the first nibble
	leaf, err := metadata.Get([]byte{index << 2})
	if err != nil {
		return nil, errors.Wrap(err, "unseal metadata state at index")
	}

	subTree, err := tries.DeserializeNonLazyTree(leaf)
	if err != nil {
		return nil, errors.Wrap(
			errors.Wrap(err, name),
			"unseal metadata state at index",
		)
	}

	return subTree, nil
}

func UnpackConsensusMetadata(
	tree *tries.VectorCommitmentTree,
) (*tries.VectorCommitmentTree, error) {
	consensusMetadata, err := unsealMetadataStateAtIndex(
		tree,
		0,
		"consensus metadata",
	)
	if err != nil {
		return nil, errors.Wrap(err, "unpack consensus metadata")
	}

	return consensusMetadata, nil
}

func UnpackSumcheckInfo(
	tree *tries.VectorCommitmentTree,
) (*tries.VectorCommitmentTree, error) {
	sumcheckInfo, err := unsealMetadataStateAtIndex(
		tree,
		1,
		"sumcheck info",
	)
	if err != nil {
		return nil, errors.Wrap(err, "unpack sumcheck info")
	}

	return sumcheckInfo, nil
}

func UnpackRdfHypergraphSchema(
	tree *tries.VectorCommitmentTree,
) (string, error) {
	leaf, err := tree.Get([]byte{2 << 2})
	if err != nil {
		return "", errors.Wrap(err, "unpack rdf indices")
	}

	if len(leaf) == 0 {
		return "", nil
	}

	valid, err := (&schema.TurtleRDFParser{}).Validate(string(leaf))
	if err != nil {
		return "", errors.Wrap(err, "unpack rdf indices")
	}

	if !valid {
		return "", errors.Wrap(errors.New("invalid schema"), "unpack rdf indices")
	}

	return string(leaf), nil
}

// Init implements state.State for hypergraphs, as an app-level shard.
// Hypergraph initialization only creates a vertex addition, as an empty VCT,
// at an address impossible to reach via regular address derivation, so as to
// ensure whatever metadata it holds does not need to adhere to the same
// encoding expectation as regular data stored in the hypergraph, so whatever
// necessary public state information needs to be held will not have risk of
// triggering confusion-based collision (as well as ensuring that metadata
// remains at a maximum branch distance of 1 from the domain root). VCT metadata
// encoding MUST include shard-level consensus metadata at index 0 (intrinsic-
// controlled and interpreted for extensibility purposes), MUST include relevant
// sumcheck info at index 1, MAY include RDF->HG index mapping at index 2,
// indices 3-15 are preserved for future use in general hypergraph metadata,
// indices 16-62 are left to intrinsic-specific use cases, 63 is the type
// designator.
func (h *HypergraphState) Init(
	domain []byte,
	consensusMetadata *tries.VectorCommitmentTree,
	sumcheckInfo *tries.VectorCommitmentTree,
	rdfSchema string,
	additionalData []*tries.VectorCommitmentTree,
	intrinsicType []byte,
) error {
	if len(domain) != 32 {
		return errors.Wrap(state.ErrInvalidDomain, "init")
	}

	if len(additionalData) > 62 {
		return errors.Wrap(state.ErrInvalidData, "init")
	}

	publicStateInformation := &tries.VectorCommitmentTree{}

	if err := h.sealMetadataStateAtIndex(
		publicStateInformation,
		consensusMetadata,
		0,
		"consensus metadata",
	); err != nil {
		return errors.Wrap(err, "init")
	}

	if err := h.sealMetadataStateAtIndex(
		publicStateInformation,
		sumcheckInfo,
		1,
		"sumcheck info",
	); err != nil {
		return errors.Wrap(err, "init")
	}

	if err := publicStateInformation.Insert(
		[]byte{2 << 2},
		[]byte(rdfSchema),
		nil,
		big.NewInt(int64(len(rdfSchema))),
	); err != nil {
		return errors.Wrap(err, "init")
	}

	if len(additionalData) > 59 {
		return errors.Wrap(errors.New("reserved metadata index"), "init")
	}

	if len(additionalData) > 0 {
		for i, add := range additionalData {
			index := i + 3

			if index < 16 {
				if add != nil {
					return errors.Wrap(errors.New("reserved metadata index"), "init")
				} else {
					continue
				}
			}

			if err := h.sealMetadataStateAtIndex(
				publicStateInformation,
				add,
				byte(index),
				fmt.Sprintf("parent intrinsic at index %d", i),
			); err != nil {
				return errors.Wrap(err, "init")
			}
		}
	}

	if err := publicStateInformation.Insert(
		bytes.Repeat([]byte{0xff}, 32),
		intrinsicType,
		nil,
		big.NewInt(int64(len(intrinsicType))),
	); err != nil {
		return errors.Wrap(err, "init")
	}

	initializedDomain := make([]byte, 32)
	copy(initializedDomain, domain)

	h.changeset = append(h.changeset, state.StateChange{
		Domain:        initializedDomain,
		Address:       HYPERGRAPH_METADATA_ADDRESS,
		Discriminator: VertexAddsDiscriminator,
		StateChange:   state.InitializeStateChangeEvent,
		Value: &VertexAddMaterializedState{
			hypergraph:  h,
			appAddress:  [32]byte(initializedDomain),
			dataAddress: [32]byte(HYPERGRAPH_METADATA_ADDRESS),
			data:        publicStateInformation,
		},
	})

	return nil
}

// Changeset implements state.State, as a list of hypergraph state changes. The
// returned slice is the underlying reference – upstream intrinsics MUST take
// caution to not mutate it.
func (h *HypergraphState) Changeset() []state.StateChange {
	return h.changeset
}

// Delete implements state.State as a deletion event on a hypergraph.
func (h *HypergraphState) Delete(
	domain []byte,
	address []byte,
	discriminator []byte,
	frameNumber uint64,
) error {
	id := [64]byte{}
	copy(id[:32], domain)
	copy(id[32:], address)

	var value state.MaterializedState
	if bytes.Equal(discriminator, VertexRemovesDiscriminator) {
		vertex, err := h.hypergraph.GetVertex(id)
		if err != nil {
			return errors.Wrap(err, "delete")
		}

		data, err := h.hypergraph.GetVertexData(id)
		if err != nil {
			return errors.Wrap(err, "delete")
		}

		value = h.NewVertexRemoveMaterializedState(
			[32]byte(domain),
			[32]byte(address),
			time.Now().UnixMilli()+VERTEX_DATA_DELETION_INTERVAL,
			frameNumber,
			data,
			vertex.Commit(nil),
			vertex.GetSize(),
		)
	} else if bytes.Equal(discriminator, HyperedgeRemovesDiscriminator) {
		hyperedge, err := h.hypergraph.GetHyperedge(id)
		if err != nil {
			return errors.Wrap(err, "delete")
		}

		value = h.NewHyperedgeRemoveMaterializedState(
			frameNumber,
			hyperedge.GetExtrinsicTree(),
			hyperedge,
		)
	} else {
		return errors.Wrap(state.ErrInvalidDiscriminator, "delete")
	}

	h.changeset = append(h.changeset, state.StateChange{
		Domain:        domain,
		Address:       address,
		Discriminator: discriminator,
		StateChange:   state.DeleteStateChangeEvent,
		Value:         value,
	})

	return nil
}

// Get implements state.State as a simple fetcher on the hypergraph.
// Discriminator is used to distinguish between set types (vertex vs hyperedge).
func (h *HypergraphState) Get(
	domain []byte,
	address []byte,
	discriminator []byte,
) (interface{}, error) {
	for _, c := range slices.Backward(h.changeset) {
		if bytes.Equal(c.Address, address) && bytes.Equal(c.Domain, domain) &&
			bytes.Equal(c.Discriminator, discriminator) {
			return c.Value.DataValue(), nil
		}
	}

	id := [64]byte{}
	copy(id[:32], domain)
	copy(id[32:], address)

	if bytes.Equal(discriminator, VertexAddsDiscriminator) {
		data, err := h.hypergraph.GetVertexData(id)
		if err != nil {
			return nil, errors.Wrap(err, "get")
		}

		return data, errors.Wrap(err, "get")
	} else if bytes.Equal(discriminator, HyperedgeAddsDiscriminator) {
		he, err := h.hypergraph.GetHyperedge(id)
		if err != nil {
			return nil, errors.Wrap(err, "get")
		}

		return he, nil
	}

	return nil, errors.Wrap(state.ErrInvalidDiscriminator, "get")
}

// Set implements state.State as a simple setter on the hypergraph.
// Discriminator is used to distinguish between set types (vertex vs hyperedge).
func (h *HypergraphState) Set(
	domain []byte,
	address []byte,
	discriminator []byte,
	frameNumber uint64,
	value state.MaterializedState,
) error {
	id := [64]byte{}
	copy(id[:32], domain)
	copy(id[32:], address)
	previousValue := false

	if bytes.Equal(discriminator, VertexAddsDiscriminator) {
		if _, ok := value.(*VertexAddMaterializedState); !ok {
			return errors.Wrap(state.ErrInvalidDiscriminator, "set")
		}

		vertex, err := h.hypergraph.GetVertex(id)
		if err != nil && errors.Is(err, hypergraph.ErrRemoved) {
			return errors.Wrap(err, "set")
		}

		if vertex != nil {
			previousValue = true
		}
	} else if bytes.Equal(discriminator, HyperedgeAddsDiscriminator) {
		if _, ok := value.(*HyperedgeAddMaterializedState); !ok {
			return errors.Wrap(state.ErrInvalidDiscriminator, "set")
		}

		hyperedge, err := h.hypergraph.GetHyperedge(id)
		if err != nil && errors.Is(err, hypergraph.ErrRemoved) {
			return errors.Wrap(err, "set")
		}
		if hyperedge != nil {
			previousValue = true
		}
	} else {
		return errors.Wrap(state.ErrInvalidDiscriminator, "set")
	}

	stateChange := state.CreateStateChangeEvent
	if previousValue {
		stateChange = state.UpdateStateChangeEvent
	}

	h.changeset = append(h.changeset, state.StateChange{
		Domain:        domain,
		Address:       address,
		Discriminator: discriminator,
		StateChange:   stateChange,
		Value:         value,
	})

	return nil
}

// Commit implements state.State, committing the (db-level) transaction set.
func (h *HypergraphState) Commit() error {
	txn, err := h.hypergraph.NewTransaction(false)
	if err != nil {
		return errors.Wrap(err, "commit")
	}

	for _, change := range h.changeset {
		if err := change.Value.Commit(txn); err != nil {
			if err := txn.Abort(); err != nil {
				return errors.Wrap(err, "commit")
			}

			return errors.Wrap(err, "commit")
		}
	}

	if err := txn.Commit(); err != nil {
		return errors.Wrap(err, "commit")
	}

	h.hypergraph.Commit()

	return nil
}

// Abort implements state.State, aborting the (db-level) transaction set.
func (h *HypergraphState) Abort() error {
	h.changeset = []state.StateChange{}
	return nil
}

var _ state.State = (*HypergraphState)(nil)
var _ state.MaterializedState = (*VertexAddMaterializedState)(nil)
var _ state.MaterializedState = (*VertexRemoveMaterializedState)(nil)
var _ state.MaterializedState = (*HyperedgeAddMaterializedState)(nil)
var _ state.MaterializedState = (*HyperedgeRemoveMaterializedState)(nil)
