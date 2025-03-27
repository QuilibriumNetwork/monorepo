package application

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"math/big"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
)

type AtomType string
type PhaseType string

const (
	VertexAtomType    AtomType  = "vertex"
	HyperedgeAtomType AtomType  = "hyperedge"
	AddsPhaseType     PhaseType = "adds"
	RemovesPhaseType  PhaseType = "removes"
)

type Location [64]byte // 32 bytes for AppAddress + 32 bytes for DataAddress

var ErrInvalidAtomType = errors.New("invalid atom type for set")
var ErrInvalidLocation = errors.New("invalid location")
var ErrMissingExtrinsics = errors.New("missing extrinsics")
var ErrIsExtrinsic = errors.New("is extrinsic")

// Extract only needed methods of VEnc interface
type Encrypted interface {
	ToBytes() []byte
	GetStatement() []byte
	Verify(proof []byte) bool
}

type Vertex interface {
	GetID() [64]byte
	GetAtomType() AtomType
	GetLocation() Location
	GetAppAddress() [32]byte
	GetDataAddress() [32]byte
	ToBytes() []byte
	GetData(func(id []byte) ([]Encrypted, error)) ([]Encrypted, error)
	GetSize() *big.Int
	Commit() []byte
}

type Hyperedge interface {
	GetID() [64]byte
	GetAtomType() AtomType
	GetLocation() Location
	GetAppAddress() [32]byte
	GetDataAddress() [32]byte
	ToBytes() []byte
	AddExtrinsic(a Atom)
	RemoveExtrinsic(a Atom)
	GetExtrinsics() map[[64]byte]Atom
	GetSize() *big.Int
	Commit() []byte
}

type vertex struct {
	appAddress  [32]byte
	dataAddress [32]byte
	commitment  []byte
	size        *big.Int
}

type hyperedge struct {
	appAddress  [32]byte
	dataAddress [32]byte
	extrinsics  map[[64]byte]Atom
	extTree     *crypto.VectorCommitmentTree
}

var _ Vertex = (*vertex)(nil)
var _ Hyperedge = (*hyperedge)(nil)

type Atom interface {
	GetID() [64]byte
	GetAtomType() AtomType
	GetLocation() Location
	GetAppAddress() [32]byte
	GetDataAddress() [32]byte
	GetSize() *big.Int
	ToBytes() []byte
	Commit() []byte
}

func EncryptedToVertexTree(encrypted []Encrypted) *crypto.VectorCommitmentTree {
	dataTree := &crypto.VectorCommitmentTree{}
	for i, d := range encrypted {
		dataBytes := d.ToBytes()
		id := binary.BigEndian.AppendUint64([]byte{}, uint64(i))
		dataTree.Insert(
			id,
			dataBytes,
			d.GetStatement(),
			big.NewInt(int64(len(encrypted)*54)),
		)
	}
	dataTree.Commit(false)
	return dataTree
}

func AtomFromBytes(data []byte) Atom {
	if len(data) == 0 {
		return nil
	}

	if data[0] == 0x00 {
		if len(data) < 161 {
			return nil
		}

		return &vertex{
			appAddress:  [32]byte(data[1:33]),
			dataAddress: [32]byte(data[33:65]),
			commitment:  data[65 : len(data)-32],
			size:        new(big.Int).SetBytes(data[len(data)-32:]),
		}
	} else {
		tree := &crypto.VectorCommitmentTree{}
		var b bytes.Buffer
		b.Write(data[65:])
		dec := gob.NewDecoder(&b)
		if err := dec.Decode(tree); err != nil {
			return nil
		}

		extrinsics := make(map[[64]byte]Atom)
		for _, a := range crypto.GetAllPreloadedLeaves(tree) {
			atom := AtomFromBytes(a.Value)
			extrinsics[[64]byte(a.Key)] = atom
		}
		return &hyperedge{
			appAddress:  [32]byte(data[1:33]),
			dataAddress: [32]byte(data[33:65]),
			extrinsics:  extrinsics,
			extTree:     tree,
		}
	}
}

func NewVertex(
	appAddress [32]byte,
	dataAddress [32]byte,
	commitment []byte,
	size *big.Int,
) Vertex {
	return &vertex{
		appAddress,
		dataAddress,
		commitment,
		size,
	}
}

func NewHyperedge(
	appAddress [32]byte,
	dataAddress [32]byte,
) Hyperedge {
	return &hyperedge{
		appAddress:  appAddress,
		dataAddress: dataAddress,
		extrinsics:  make(map[[64]byte]Atom),
		extTree:     &crypto.VectorCommitmentTree{},
	}
}

func (v *vertex) GetID() [64]byte {
	id := [64]byte{}
	copy(id[:32], v.appAddress[:])
	copy(id[32:64], v.dataAddress[:])
	return id
}

func (v *vertex) GetSize() *big.Int {
	return v.size
}

func (v *vertex) GetAtomType() AtomType {
	return VertexAtomType
}

func (v *vertex) GetLocation() Location {
	var loc Location
	copy(loc[:32], v.appAddress[:])
	copy(loc[32:], v.dataAddress[:])
	return loc
}

func (v *vertex) GetAppAddress() [32]byte {
	return v.appAddress
}

func (v *vertex) GetDataAddress() [32]byte {
	return v.dataAddress
}

func (v *vertex) GetData(
	retrievalFunc func(id []byte) ([]Encrypted, error),
) ([]Encrypted, error) {
	id := v.GetID()
	return retrievalFunc(id[:])
}

func (v *vertex) ToBytes() []byte {
	return append(
		append(
			append(
				append(
					[]byte{0x00},
					v.appAddress[:]...,
				),
				v.dataAddress[:]...,
			),
			v.commitment[:]...,
		),
		v.size.FillBytes(make([]byte, 32))...,
	)
}

func (v *vertex) Commit() []byte {
	return v.commitment
}

func (h *hyperedge) GetID() [64]byte {
	id := [64]byte{}
	copy(id[:32], h.appAddress[:])
	copy(id[32:], h.dataAddress[:])
	return id
}

func (h *hyperedge) GetSize() *big.Int {
	return big.NewInt(int64(len(h.extrinsics)))
}

func (h *hyperedge) GetAtomType() AtomType {
	return HyperedgeAtomType
}

func (h *hyperedge) GetLocation() Location {
	var loc Location
	copy(loc[:32], h.appAddress[:])
	copy(loc[32:], h.dataAddress[:])
	return loc
}

func (h *hyperedge) GetAppAddress() [32]byte {
	return h.appAddress
}

func (h *hyperedge) GetDataAddress() [32]byte {
	return h.dataAddress
}

func (h *hyperedge) ToBytes() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(h.extrinsics); err != nil {
		return nil
	}
	return append(
		append(
			append(
				[]byte{0x01},
				h.appAddress[:]...,
			),
			h.dataAddress[:]...,
		),
		buf.Bytes()...,
	)
}

func (h *hyperedge) AddExtrinsic(a Atom) {
	id := a.GetID()
	atomType := []byte{0x00}
	if a.GetAtomType() == HyperedgeAtomType {
		atomType = []byte{0x01}
	}
	h.extTree.Insert(id[:], append(atomType, id[:]...), nil, a.GetSize())
	h.extrinsics[id] = a
}

func (h *hyperedge) RemoveExtrinsic(a Atom) {
	id := a.GetID()
	h.extTree.Delete(id[:])
	delete(h.extrinsics, id)
}

func (h *hyperedge) GetExtrinsics() map[[64]byte]Atom {
	ext := make(map[[64]byte]Atom)
	for id := range h.extrinsics {
		ext[id] = h.extrinsics[id]
	}
	return ext
}

func (h *hyperedge) Commit() []byte {
	return h.extTree.Commit(false)
}

type ShardAddress struct {
	L1 [3]byte
	L2 [32]byte
	L3 [32]byte
}

func GetShardAddress(a Atom) ShardAddress {
	appAddress := a.GetAppAddress()
	dataAddress := a.GetDataAddress()

	return ShardAddress{
		L1: [3]byte(p2p.GetBloomFilterIndices(appAddress[:], 256, 3)),
		L2: [32]byte(append([]byte{}, appAddress[:]...)),
		L3: [32]byte(append([]byte{}, dataAddress[:]...)),
	}
}

func GetShardKey(a Atom) crypto.ShardKey {
	s := GetShardAddress(a)
	return crypto.ShardKey{L1: s.L1, L2: s.L2}
}

type IdSet struct {
	dirty    bool
	atomType AtomType
	atoms    map[[64]byte]Atom
	tree     *crypto.LazyVectorCommitmentTree
}

func NewIdSet(
	atomType AtomType,
	phaseType PhaseType,
	shardKey crypto.ShardKey,
	store crypto.TreeBackingStore,
) *IdSet {
	return &IdSet{
		dirty:    false,
		atomType: atomType,
		atoms:    make(map[[64]byte]Atom),
		tree: &crypto.LazyVectorCommitmentTree{
			SetType:   string(atomType),
			PhaseType: string(phaseType),
			ShardKey:  shardKey,
			Store:     store,
		},
	}
}

func (set *IdSet) FromBytes(
	atomType AtomType,
	phaseType PhaseType,
	shardKey crypto.ShardKey,
	store crypto.TreeBackingStore,
	treeData []byte,
) ([]Atom, error) {
	var err error
	set.tree, err = crypto.DeserializeTree(
		string(atomType),
		string(phaseType),
		shardKey,
		store,
		treeData,
	)
	leaves := crypto.ConvertAllPreloadedLeaves(
		string(atomType),
		string(phaseType),
		shardKey,
		store,
		set.tree.Root,
		[]int{},
	)
	atoms := []Atom{}
	for _, leaf := range leaves {
		atom := AtomFromBytes(leaf.Value)
		atoms = append(atoms, atom)
	}

	return atoms, errors.Wrap(err, "from bytes")
}

func (set *IdSet) IsDirty() bool {
	return set.dirty
}

func (set *IdSet) ToBytes() ([]byte, error) {
	return crypto.SerializeTree(set.tree)
}

func (set *IdSet) Add(
	txn crypto.TreeBackingStoreTransaction,
	atom Atom,
) error {
	if atom.GetAtomType() != set.atomType {
		return ErrInvalidAtomType
	}

	id := atom.GetID()
	set.atoms[id] = atom
	set.dirty = true
	return set.tree.Insert(
		txn,
		id[:],
		atom.ToBytes(),
		atom.Commit(),
		atom.GetSize(),
	)
}

func (set *IdSet) GetSize() *big.Int {
	size := set.tree.GetSize()
	if size == nil {
		size = big.NewInt(0)
	}
	return size
}

func (set *IdSet) Has(key [64]byte) bool {
	_, err := set.tree.Store.GetNodeByKey(
		set.tree.SetType,
		set.tree.PhaseType,
		set.tree.ShardKey,
		key[:],
	)
	return err == nil
}

func (set *IdSet) GetTree() *crypto.LazyVectorCommitmentTree {
	return set.tree
}

type Hypergraph struct {
	size             *big.Int
	vertexAdds       map[crypto.ShardKey]*IdSet
	vertexRemoves    map[crypto.ShardKey]*IdSet
	hyperedgeAdds    map[crypto.ShardKey]*IdSet
	hyperedgeRemoves map[crypto.ShardKey]*IdSet
	store            crypto.TreeBackingStore
}

func NewHypergraph(store crypto.TreeBackingStore) *Hypergraph {
	return &Hypergraph{
		size:             big.NewInt(0),
		vertexAdds:       make(map[crypto.ShardKey]*IdSet),
		vertexRemoves:    make(map[crypto.ShardKey]*IdSet),
		hyperedgeAdds:    make(map[crypto.ShardKey]*IdSet),
		hyperedgeRemoves: make(map[crypto.ShardKey]*IdSet),
		store:            store,
	}
}

func (hg *Hypergraph) GetVertexAdds() map[crypto.ShardKey]*IdSet {
	return hg.vertexAdds
}

func (hg *Hypergraph) GetVertexRemoves() map[crypto.ShardKey]*IdSet {
	return hg.vertexRemoves
}

func (hg *Hypergraph) GetHyperedgeAdds() map[crypto.ShardKey]*IdSet {
	return hg.hyperedgeAdds
}

func (hg *Hypergraph) GetHyperedgeRemoves() map[crypto.ShardKey]*IdSet {
	return hg.hyperedgeRemoves
}

func (hg *Hypergraph) Commit() [][]byte {
	commits := [][]byte{}
	for _, vertexAdds := range hg.vertexAdds {
		root := vertexAdds.tree.Commit(false)
		if bytes.Equal(root, []byte{}) {
			root = vertexAdds.tree.Commit(true)
		}
		commits = append(commits, root)
	}
	for _, vertexRemoves := range hg.vertexRemoves {
		root := vertexRemoves.tree.Commit(false)
		if bytes.Equal(root, []byte{}) {
			root = vertexRemoves.tree.Commit(true)
		}
		commits = append(commits, root)
	}
	for _, hyperedgeAdds := range hg.hyperedgeAdds {
		root := hyperedgeAdds.tree.Commit(false)
		if bytes.Equal(root, []byte{}) {
			root = hyperedgeAdds.tree.Commit(true)
		}
		commits = append(commits, root)
	}
	for _, hyperedgeRemoves := range hg.hyperedgeRemoves {
		root := hyperedgeRemoves.tree.Commit(false)
		if bytes.Equal(root, []byte{}) {
			root = hyperedgeRemoves.tree.Commit(true)
		}
		commits = append(commits, root)
	}
	return commits
}

func (hg *Hypergraph) ImportTree(
	atomType AtomType,
	phaseType PhaseType,
	shardKey crypto.ShardKey,
	root crypto.LazyVectorCommitmentNode,
	store crypto.TreeBackingStore,
) error {
	set := NewIdSet(
		atomType,
		phaseType,
		shardKey,
		store,
	)
	set.tree = &crypto.LazyVectorCommitmentTree{
		Root:      root,
		SetType:   string(atomType),
		PhaseType: string(phaseType),
		ShardKey:  shardKey,
		Store:     store,
	}

	switch atomType {
	case VertexAtomType:
		switch phaseType {
		case AddsPhaseType:
			hg.size.Add(hg.size, set.GetSize())
			hg.vertexAdds[shardKey] = set
		case RemovesPhaseType:
			hg.size.Sub(hg.size, set.GetSize())
			hg.vertexRemoves[shardKey] = set
		}
	case HyperedgeAtomType:
		switch phaseType {
		case AddsPhaseType:
			hg.size.Add(hg.size, set.GetSize())
			hg.hyperedgeAdds[shardKey] = set
		case RemovesPhaseType:
			hg.size.Sub(hg.size, set.GetSize())
			hg.hyperedgeRemoves[shardKey] = set
		}
	}

	return nil
}

func (hg *Hypergraph) GetSize() *big.Int {
	return hg.size
}

func (hg *Hypergraph) getOrCreateIdSet(
	shardAddr crypto.ShardKey,
	addMap map[crypto.ShardKey]*IdSet,
	removeMap map[crypto.ShardKey]*IdSet,
	atomType AtomType,
	phaseType PhaseType,
) (*IdSet, *IdSet) {
	if _, ok := addMap[shardAddr]; !ok {
		addMap[shardAddr] = NewIdSet(
			atomType,
			phaseType,
			shardAddr,
			hg.store,
		)
	}
	if _, ok := removeMap[shardAddr]; !ok {
		removeMap[shardAddr] = NewIdSet(
			atomType,
			phaseType,
			shardAddr,
			hg.store,
		)
	}
	return addMap[shardAddr], removeMap[shardAddr]
}

func (hg *Hypergraph) AddVertex(
	txn crypto.TreeBackingStoreTransaction,
	v Vertex,
) error {
	shardAddr := GetShardKey(v)
	addSet, _ := hg.getOrCreateIdSet(
		shardAddr,
		hg.vertexAdds,
		hg.vertexRemoves,
		VertexAtomType,
		AddsPhaseType,
	)
	hg.size.Add(hg.size, v.GetSize())
	return errors.Wrap(addSet.Add(txn, v), "add vertex")
}

func (hg *Hypergraph) AddHyperedge(
	txn crypto.TreeBackingStoreTransaction,
	h Hyperedge,
) error {
	if !hg.LookupAtomSet(&h.(*hyperedge).extrinsics) {
		return ErrMissingExtrinsics
	}
	shardAddr := GetShardKey(h)
	addSet, removeSet := hg.getOrCreateIdSet(
		shardAddr,
		hg.hyperedgeAdds,
		hg.hyperedgeRemoves,
		HyperedgeAtomType,
		AddsPhaseType,
	)
	id := h.GetID()
	if !removeSet.Has(id) {
		hg.size.Add(hg.size, h.GetSize())
		return errors.Wrap(addSet.Add(txn, h), "add hyperedge")
	}
	return nil
}

func (hg *Hypergraph) RemoveVertex(
	txn crypto.TreeBackingStoreTransaction,
	v Vertex,
) error {
	shardKey := GetShardKey(v)
	if !hg.LookupVertex(v.(*vertex)) {
		addSet, removeSet := hg.getOrCreateIdSet(
			shardKey,
			hg.vertexAdds,
			hg.vertexRemoves,
			VertexAtomType,
			AddsPhaseType,
		)
		if err := addSet.Add(txn, v); err != nil {
			return errors.Wrap(err, "remove vertex")
		}
		return errors.Wrap(removeSet.Add(txn, v), "remove vertex")
	}

	id := v.GetID()

	for _, hyperedgeAdds := range hg.hyperedgeAdds {
		for _, atom := range hyperedgeAdds.atoms {
			if he, ok := atom.(*hyperedge); ok {
				if _, ok := he.extrinsics[id]; ok {
					return ErrIsExtrinsic
				}
			}
		}
	}
	_, removeSet := hg.getOrCreateIdSet(
		shardKey,
		hg.vertexAdds,
		hg.vertexRemoves,
		VertexAtomType,
		RemovesPhaseType,
	)
	hg.size.Sub(hg.size, v.GetSize())
	err := removeSet.Add(txn, v)
	return err
}

func (hg *Hypergraph) RemoveHyperedge(
	txn crypto.TreeBackingStoreTransaction,
	h Hyperedge,
) error {
	shardKey := GetShardKey(h)
	wasPresent := hg.LookupHyperedge(h.(*hyperedge))
	if !wasPresent {
		addSet, removeSet := hg.getOrCreateIdSet(
			shardKey,
			hg.hyperedgeAdds,
			hg.hyperedgeRemoves,
			HyperedgeAtomType,
			AddsPhaseType,
		)
		if err := addSet.Add(txn, h); err != nil {
			return errors.Wrap(err, "remove hyperedge")
		}

		return errors.Wrap(removeSet.Add(txn, h), "remove hyperedge")
	}

	id := h.GetID()
	for _, hyperedgeAdds := range hg.hyperedgeAdds {
		for _, atom := range hyperedgeAdds.atoms {
			if he, ok := atom.(*hyperedge); ok {
				if _, ok := he.extrinsics[id]; ok {
					return ErrIsExtrinsic
				}
			}
		}
	}
	_, removeSet := hg.getOrCreateIdSet(
		shardKey,
		hg.hyperedgeAdds,
		hg.hyperedgeRemoves,
		HyperedgeAtomType,
		RemovesPhaseType,
	)
	hg.size.Sub(hg.size, h.GetSize())
	err := removeSet.Add(txn, h)
	return err
}

func (hg *Hypergraph) LookupVertex(v Vertex) bool {
	shardAddr := GetShardKey(v)
	addSet, removeSet := hg.getOrCreateIdSet(
		shardAddr,
		hg.vertexAdds,
		hg.vertexRemoves,
		VertexAtomType,
		AddsPhaseType,
	)
	id := v.GetID()
	return addSet.Has(id) && !removeSet.Has(id)
}

func (hg *Hypergraph) LookupHyperedge(h Hyperedge) bool {
	shardAddr := GetShardKey(h)
	addSet, removeSet := hg.getOrCreateIdSet(
		shardAddr,
		hg.hyperedgeAdds,
		hg.hyperedgeRemoves,
		HyperedgeAtomType,
		AddsPhaseType,
	)
	id := h.GetID()
	return hg.LookupAtomSet(&h.(*hyperedge).extrinsics) && addSet.Has(id) && !removeSet.Has(id)
}

func (hg *Hypergraph) LookupAtom(a Atom) bool {
	switch v := a.(type) {
	case *vertex:
		return hg.LookupVertex(v)
	case *hyperedge:
		return hg.LookupHyperedge(v)
	default:
		return false
	}
}

func (hg *Hypergraph) LookupAtomSet(atomSet *map[[64]byte]Atom) bool {
	for _, atom := range *atomSet {
		if !hg.LookupAtom(atom) {
			return false
		}
	}
	return true
}

func (hg *Hypergraph) Within(a, h Atom) bool {
	if he, ok := h.(*hyperedge); ok {
		addr := a.GetID()
		if _, ok := he.extrinsics[addr]; ok || a.GetID() == h.GetID() {
			return true
		}
		for _, extrinsic := range he.extrinsics {
			if nestedHe, ok := extrinsic.(*hyperedge); ok {
				if hg.LookupHyperedge(nestedHe) && hg.Within(a, nestedHe) {
					return true
				}
			}
		}
	}
	return false
}
