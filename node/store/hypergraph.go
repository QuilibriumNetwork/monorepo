package store

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/cockroachdb/pebble"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/hypergraph/application"
	"source.quilibrium.com/quilibrium/monorepo/node/utils"
)

type HypergraphStore interface {
	NewTransaction(indexed bool) (Transaction, error)
	LoadVertexTree(id []byte) (
		*crypto.VectorCommitmentTree,
		error,
	)
	LoadVertexData(id []byte) ([]application.Encrypted, error)
	SaveVertexTree(
		txn Transaction,
		id []byte,
		vertTree *crypto.VectorCommitmentTree,
	) error
	CommitAndSaveVertexData(
		txn Transaction,
		id []byte,
		data []application.Encrypted,
	) (*crypto.VectorCommitmentTree, []byte, error)
	LoadHypergraph() (
		*application.Hypergraph,
		error,
	)
	SaveHypergraph(
		hg *application.Hypergraph,
	) error
	GetNodeByKey(
		setType string,
		phaseType string,
		shardKey crypto.ShardKey,
		key []byte,
	) (crypto.LazyVectorCommitmentNode, error)
	GetNodeByPath(
		setType string,
		phaseType string,
		shardKey crypto.ShardKey,
		path []int,
	) (crypto.LazyVectorCommitmentNode, error)
	InsertNode(
		txn crypto.TreeBackingStoreTransaction,
		setType string,
		phaseType string,
		shardKey crypto.ShardKey,
		key []byte,
		path []int,
		node crypto.LazyVectorCommitmentNode,
	) error
	SaveRoot(
		setType string,
		phaseType string,
		shardKey crypto.ShardKey,
		node crypto.LazyVectorCommitmentNode,
	) error
	DeletePath(
		setType string,
		phaseType string,
		shardKey crypto.ShardKey,
		path []int,
	) error
	MarkHypergraphAsComplete()
}

var _ HypergraphStore = (*PebbleHypergraphStore)(nil)

type PebbleHypergraphStore struct {
	config *config.DBConfig
	db     KVDB
	logger *zap.Logger
}

func NewPebbleHypergraphStore(
	config *config.DBConfig,
	db KVDB,
	logger *zap.Logger,
) *PebbleHypergraphStore {
	return &PebbleHypergraphStore{
		config,
		db,
		logger,
	}
}

const (
	HYPERGRAPH_SHARD                    = 0x09
	VERTEX_ADDS                         = 0x00
	VERTEX_REMOVES                      = 0x10
	VERTEX_DATA                         = 0xF0
	HYPEREDGE_ADDS                      = 0x01
	HYPEREDGE_REMOVES                   = 0x11
	VERTEX_ADDS_TREE_NODE               = 0x02
	VERTEX_REMOVES_TREE_NODE            = 0x12
	HYPEREDGE_ADDS_TREE_NODE            = 0x03
	HYPEREDGE_REMOVES_TREE_NODE         = 0x13
	VERTEX_ADDS_TREE_NODE_BY_PATH       = 0x22
	VERTEX_REMOVES_TREE_NODE_BY_PATH    = 0x32
	HYPEREDGE_ADDS_TREE_NODE_BY_PATH    = 0x23
	HYPEREDGE_REMOVES_TREE_NODE_BY_PATH = 0x33
	HYPERGRAPH_COMPLETE                 = 0xFB
	VERTEX_ADDS_TREE_ROOT               = 0xFC
	VERTEX_REMOVES_TREE_ROOT            = 0xFD
	HYPEREDGE_ADDS_TREE_ROOT            = 0xFE
	HYPEREDGE_REMOVES_TREE_ROOT         = 0xFF
)

func hypergraphVertexAddsKey(shardKey crypto.ShardKey) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_ADDS}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func hypergraphVertexDataKey(id []byte) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_DATA}
	key = append(key, id...)
	return key
}

func hypergraphVertexRemovesKey(shardKey crypto.ShardKey) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_REMOVES}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func hypergraphHyperedgeAddsKey(shardKey crypto.ShardKey) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func hypergraphHyperedgeRemovesKey(shardKey crypto.ShardKey) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func hypergraphVertexAddsTreeNodeKey(
	shardKey crypto.ShardKey,
	nodeKey []byte,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_ADDS_TREE_NODE}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	key = append(key, nodeKey...)
	return key
}

func hypergraphVertexRemovesTreeNodeKey(
	shardKey crypto.ShardKey,
	nodeKey []byte,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_REMOVES_TREE_NODE}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	key = append(key, nodeKey...)
	return key
}

func hypergraphHyperedgeAddsTreeNodeKey(
	shardKey crypto.ShardKey,
	nodeKey []byte,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS_TREE_NODE}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	key = append(key, nodeKey...)
	return key
}

func hypergraphHyperedgeRemovesTreeNodeKey(
	shardKey crypto.ShardKey,
	nodeKey []byte,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES_TREE_NODE}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	key = append(key, nodeKey...)
	return key
}

func hypergraphVertexAddsTreeNodeByPathKey(
	shardKey crypto.ShardKey,
	path []int,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_ADDS_TREE_NODE_BY_PATH}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	for _, p := range path {
		key = binary.BigEndian.AppendUint64(key, uint64(p))
	}
	return key
}

func hypergraphVertexRemovesTreeNodeByPathKey(
	shardKey crypto.ShardKey,
	path []int,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_REMOVES_TREE_NODE_BY_PATH}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	for _, p := range path {
		key = binary.BigEndian.AppendUint64(key, uint64(p))
	}
	return key
}

func hypergraphHyperedgeAddsTreeNodeByPathKey(
	shardKey crypto.ShardKey,
	path []int,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS_TREE_NODE_BY_PATH}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	for _, p := range path {
		key = binary.BigEndian.AppendUint64(key, uint64(p))
	}
	return key
}

func hypergraphHyperedgeRemovesTreeNodeByPathKey(
	shardKey crypto.ShardKey,
	path []int,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES_TREE_NODE_BY_PATH}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	for _, p := range path {
		key = binary.BigEndian.AppendUint64(key, uint64(p))
	}
	return key
}

func hypergraphVertexAddsTreeRootKey(
	shardKey crypto.ShardKey,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_ADDS_TREE_ROOT}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func hypergraphVertexRemovesTreeRootKey(
	shardKey crypto.ShardKey,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, VERTEX_REMOVES_TREE_ROOT}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func hypergraphHyperedgeAddsTreeRootKey(
	shardKey crypto.ShardKey,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS_TREE_ROOT}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func hypergraphHyperedgeRemovesTreeRootKey(
	shardKey crypto.ShardKey,
) []byte {
	key := []byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES_TREE_ROOT}
	key = append(key, shardKey.L1[:]...)
	key = append(key, shardKey.L2[:]...)
	return key
}

func shardKeyFromKey(key []byte) crypto.ShardKey {
	return crypto.ShardKey{
		L1: [3]byte(key[2:5]),
		L2: [32]byte(key[5:]),
	}
}

func (p *PebbleHypergraphStore) NewTransaction(indexed bool) (
	Transaction,
	error,
) {
	return p.db.NewBatch(indexed), nil
}

func (p *PebbleHypergraphStore) LoadVertexTree(id []byte) (
	*crypto.VectorCommitmentTree,
	error,
) {
	tree := &crypto.VectorCommitmentTree{}
	var b bytes.Buffer
	vertexData, closer, err := p.db.Get(hypergraphVertexDataKey(id))
	if err != nil {
		return nil, errors.Wrap(err, "load vertex data")
	}
	defer closer.Close()
	b.Write(vertexData)

	dec := gob.NewDecoder(&b)
	if err := dec.Decode(tree); err != nil {
		return nil, errors.Wrap(err, "load vertex data")
	}

	return tree, nil
}

func (p *PebbleHypergraphStore) LoadVertexData(id []byte) (
	[]application.Encrypted,
	error,
) {
	tree := &crypto.VectorCommitmentTree{}
	var b bytes.Buffer
	vertexData, closer, err := p.db.Get(hypergraphVertexDataKey(id))
	if err != nil {
		return nil, errors.Wrap(err, "load vertex data")
	}
	defer closer.Close()
	b.Write(vertexData)

	dec := gob.NewDecoder(&b)
	if err := dec.Decode(tree); err != nil {
		return nil, errors.Wrap(err, "load vertex data")
	}

	encData := []application.Encrypted{}
	for _, d := range crypto.GetAllPreloadedLeaves(tree) {
		verencData := crypto.MPCitHVerEncFromBytes(d.Value)
		encData = append(encData, verencData)
	}

	return encData, nil
}

func (p *PebbleHypergraphStore) SaveVertexTree(
	txn Transaction,
	id []byte,
	vertTree *crypto.VectorCommitmentTree,
) error {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(vertTree); err != nil {
		return errors.Wrap(err, "save vertex tree")
	}

	return errors.Wrap(
		txn.Set(hypergraphVertexDataKey(id), buf.Bytes()),
		"save vertex tree",
	)
}

func (p *PebbleHypergraphStore) CommitAndSaveVertexData(
	txn Transaction,
	id []byte,
	data []application.Encrypted,
) (*crypto.VectorCommitmentTree, []byte, error) {
	dataTree := application.EncryptedToVertexTree(data)
	commit := dataTree.Commit(false)

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(dataTree); err != nil {
		return nil, nil, errors.Wrap(err, "commit and save vertex data")
	}

	return dataTree, commit, errors.Wrap(
		txn.Set(hypergraphVertexDataKey(id), buf.Bytes()),
		"commit and save vertex data",
	)
}

func (p *PebbleHypergraphStore) LoadHypergraph() (
	*application.Hypergraph,
	error,
) {
	hg := application.NewHypergraph(p)
	hypergraphDir := path.Join(p.config.Path, "hypergraph")

	flag, flagCloser, err := p.db.Get(
		[]byte{HYPERGRAPH_SHARD, HYPERGRAPH_COMPLETE},
	)
	complete := false
	inProgress := false
	if err == nil {
		if flag[0] == 0x01 {
			inProgress = true
		} else {
			complete = true
		}
		flagCloser.Close()
	}

	if complete || inProgress {
		vertexAddsIter, err := p.db.NewIter(
			[]byte{HYPERGRAPH_SHARD, VERTEX_ADDS_TREE_ROOT},
			[]byte{HYPERGRAPH_SHARD, VERTEX_REMOVES_TREE_ROOT},
		)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}
		defer vertexAddsIter.Close()

		loadedFromDB := false
		for vertexAddsIter.First(); vertexAddsIter.Valid(); vertexAddsIter.Next() {
			loadedFromDB = true
			shardKey := shardKeyFromKey(vertexAddsIter.Key())
			data := vertexAddsIter.Value()

			var node crypto.LazyVectorCommitmentNode
			switch data[0] {
			case crypto.TypeLeaf:
				node, err = crypto.DeserializeLeafNode(p, bytes.NewReader(data[1:]))
			case crypto.TypeBranch:
				pathLength := binary.BigEndian.Uint32(data[1:5])

				node, err = crypto.DeserializeBranchNode(
					p,
					bytes.NewReader(data[5+(pathLength*4):]),
					false,
				)

				fullPrefix := []int{}
				for i := range pathLength {
					fullPrefix = append(
						fullPrefix,
						int(binary.BigEndian.Uint32(data[5+(i*4):5+((i+1)*4)])),
					)
				}
				branch := node.(*crypto.LazyVectorCommitmentBranchNode)
				branch.FullPrefix = fullPrefix
			default:
				err = ErrInvalidData
			}

			if err != nil {
				return nil, errors.Wrap(err, "load hypergraph")
			}

			err = hg.ImportTree(
				application.VertexAtomType,
				application.AddsPhaseType,
				shardKey,
				node,
				p,
			)
			if err != nil {
				return nil, errors.Wrap(err, "load hypergraph")
			}
		}

		vertexRemovesIter, err := p.db.NewIter(
			[]byte{HYPERGRAPH_SHARD, VERTEX_REMOVES_TREE_ROOT},
			[]byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS_TREE_ROOT},
		)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}
		defer vertexRemovesIter.Close()

		for vertexRemovesIter.First(); vertexRemovesIter.Valid(); vertexRemovesIter.Next() {
			loadedFromDB = true
			shardKey := shardKeyFromKey(vertexRemovesIter.Key())
			data := vertexRemovesIter.Value()

			var node crypto.LazyVectorCommitmentNode
			switch data[0] {
			case crypto.TypeLeaf:
				node, err = crypto.DeserializeLeafNode(p, bytes.NewReader(data[1:]))
			case crypto.TypeBranch:
				pathLength := binary.BigEndian.Uint32(data[1:5])

				node, err = crypto.DeserializeBranchNode(
					p,
					bytes.NewReader(data[5+(pathLength*4):]),
					false,
				)

				fullPrefix := []int{}
				for i := range pathLength {
					fullPrefix = append(
						fullPrefix,
						int(binary.BigEndian.Uint32(data[5+(i*4):5+((i+1)*4)])),
					)
				}
				branch := node.(*crypto.LazyVectorCommitmentBranchNode)
				branch.FullPrefix = fullPrefix
			default:
				err = ErrInvalidData
			}

			if err != nil {
				return nil, errors.Wrap(err, "load hypergraph")
			}

			err = hg.ImportTree(
				application.VertexAtomType,
				application.RemovesPhaseType,
				shardKey,
				node,
				p,
			)
			if err != nil {
				return nil, errors.Wrap(err, "load hypergraph")
			}
		}

		hyperedgeAddsIter, err := p.db.NewIter(
			[]byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS_TREE_ROOT},
			[]byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES_TREE_ROOT},
		)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}
		defer hyperedgeAddsIter.Close()

		for hyperedgeAddsIter.First(); hyperedgeAddsIter.Valid(); hyperedgeAddsIter.Next() {
			loadedFromDB = true
			shardKey := shardKeyFromKey(hyperedgeAddsIter.Key())
			data := hyperedgeAddsIter.Value()

			var node crypto.LazyVectorCommitmentNode
			switch data[0] {
			case crypto.TypeLeaf:
				node, err = crypto.DeserializeLeafNode(
					p,
					bytes.NewReader(data[1:]),
				)
			case crypto.TypeBranch:
				pathLength := binary.BigEndian.Uint32(data[1:5])
				node, err = crypto.DeserializeBranchNode(
					p,
					bytes.NewReader(data[5+(pathLength*4):]),
					false,
				)
				if err != nil {
					return nil, errors.Wrap(err, "load hypergraph")
				}

				fullPrefix := []int{}
				for i := range pathLength {
					fullPrefix = append(
						fullPrefix,
						int(binary.BigEndian.Uint32(data[5+(i*4):5+((i+1)*4)])),
					)
				}

				branch := node.(*crypto.LazyVectorCommitmentBranchNode)
				branch.FullPrefix = fullPrefix
			default:
				err = ErrInvalidData
			}

			if err != nil {
				return nil, errors.Wrap(err, "load hypergraph")
			}

			err = hg.ImportTree(
				application.HyperedgeAtomType,
				application.AddsPhaseType,
				shardKey,
				node,
				p,
			)
			if err != nil {
				return nil, errors.Wrap(err, "load hypergraph")
			}
		}

		hyperedgeRemovesIter, err := p.db.NewIter(
			[]byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES_TREE_ROOT},
			[]byte{(HYPERGRAPH_SHARD + 1), 0x00},
		)
		if err != nil {
			return nil, errors.Wrap(err, "load hypergraph")
		}
		defer hyperedgeRemovesIter.Close()

		for hyperedgeRemovesIter.First(); hyperedgeRemovesIter.Valid(); hyperedgeRemovesIter.Next() {
			loadedFromDB = true
			shardKey := shardKeyFromKey(hyperedgeRemovesIter.Key())
			data := hyperedgeRemovesIter.Value()

			var node crypto.LazyVectorCommitmentNode
			switch data[0] {
			case crypto.TypeLeaf:
				node, err = crypto.DeserializeLeafNode(p, bytes.NewReader(data[1:]))
			case crypto.TypeBranch:
				pathLength := binary.BigEndian.Uint32(data[1:5])

				node, err = crypto.DeserializeBranchNode(
					p,
					bytes.NewReader(data[5+(pathLength*4):]),
					false,
				)

				fullPrefix := []int{}
				for i := range pathLength {
					fullPrefix = append(
						fullPrefix,
						int(binary.BigEndian.Uint32(data[5+(i*4):5+((i+1)*4)])),
					)
				}
				branch := node.(*crypto.LazyVectorCommitmentBranchNode)
				branch.FullPrefix = fullPrefix
			default:
				err = ErrInvalidData
			}

			if err != nil {
				return nil, errors.Wrap(err, "load hypergraph")
			}

			err = hg.ImportTree(
				application.HyperedgeAtomType,
				application.RemovesPhaseType,
				shardKey,
				node,
				p,
			)
			if err != nil {
				return nil, errors.Wrap(err, "load hypergraph")
			}
		}

		if loadedFromDB && complete {
			return hg, nil
		}
	}

	vertexAddsPrefix := hex.EncodeToString(
		[]byte{HYPERGRAPH_SHARD, VERTEX_ADDS},
	)
	vertexRemovesPrefix := hex.EncodeToString(
		[]byte{HYPERGRAPH_SHARD, VERTEX_REMOVES},
	)
	hyperedgeAddsPrefix := hex.EncodeToString(
		[]byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS},
	)
	hyperedgeRemovesPrefix := hex.EncodeToString(
		[]byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES},
	)

	p.logger.Info("converting hypergraph, this may take a moment")
	if !inProgress {
		p.db.DeleteRange(
			[]byte{HYPERGRAPH_SHARD, VERTEX_ADDS_TREE_ROOT},
			[]byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES_TREE_ROOT},
		)
		p.db.DeleteRange(
			[]byte{HYPERGRAPH_SHARD, VERTEX_ADDS_TREE_NODE},
			[]byte{HYPERGRAPH_SHARD, VERTEX_ADDS_TREE_NODE + 1},
		)
		p.db.DeleteRange(
			[]byte{HYPERGRAPH_SHARD, VERTEX_REMOVES_TREE_NODE},
			[]byte{HYPERGRAPH_SHARD, VERTEX_REMOVES_TREE_NODE + 1},
		)
		p.db.DeleteRange(
			[]byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS_TREE_NODE},
			[]byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS_TREE_NODE + 1},
		)
		p.db.DeleteRange(
			[]byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES_TREE_NODE},
			[]byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES_TREE_NODE + 1},
		)
		p.db.DeleteRange(
			[]byte{HYPERGRAPH_SHARD, VERTEX_ADDS_TREE_NODE_BY_PATH},
			[]byte{HYPERGRAPH_SHARD, VERTEX_ADDS_TREE_NODE_BY_PATH + 1},
		)
		p.db.DeleteRange(
			[]byte{HYPERGRAPH_SHARD, VERTEX_REMOVES_TREE_NODE_BY_PATH},
			[]byte{HYPERGRAPH_SHARD, VERTEX_REMOVES_TREE_NODE_BY_PATH + 1},
		)
		p.db.DeleteRange(
			[]byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS_TREE_NODE_BY_PATH},
			[]byte{HYPERGRAPH_SHARD, HYPEREDGE_ADDS_TREE_NODE_BY_PATH + 1},
		)
		p.db.DeleteRange(
			[]byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES_TREE_NODE_BY_PATH},
			[]byte{HYPERGRAPH_SHARD, HYPEREDGE_REMOVES_TREE_NODE_BY_PATH + 1},
		)
		p.db.Set([]byte{HYPERGRAPH_SHARD, HYPERGRAPH_COMPLETE}, []byte{0x01})
	}

	err = errors.Wrap(
		filepath.WalkDir(
			hypergraphDir,
			func(pa string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					return nil
				}

				if len(strings.Split(d.Name(), ".")) != 2 ||
					strings.Split(d.Name(), ".")[1] != "vct" {
					return nil
				}

				shardSet, err := hex.DecodeString(strings.Split(d.Name(), ".")[0])
				if err != nil {
					return err
				}

				var atomType application.AtomType
				var setType application.PhaseType

				if strings.HasPrefix(d.Name(), vertexAddsPrefix) {
					atomType = application.VertexAtomType
					setType = application.AddsPhaseType
				} else if strings.HasPrefix(d.Name(), vertexRemovesPrefix) {
					atomType = application.VertexAtomType
					setType = application.RemovesPhaseType
				} else if strings.HasPrefix(d.Name(), hyperedgeAddsPrefix) {
					atomType = application.HyperedgeAtomType
					setType = application.AddsPhaseType
				} else if strings.HasPrefix(d.Name(), hyperedgeRemovesPrefix) {
					atomType = application.HyperedgeAtomType
					setType = application.RemovesPhaseType
				}

				fileBytes, err := os.ReadFile(pa)
				if err != nil {
					return err
				}

				set := application.NewIdSet(
					atomType,
					setType,
					shardKeyFromKey(shardSet),
					p,
				)
				atoms, err := set.FromBytes(
					atomType,
					setType,
					shardKeyFromKey(shardSet),
					p,
					fileBytes,
				)
				if err != nil {
					return err
				}

				var existingTree *crypto.LazyVectorCommitmentTree
				if inProgress {
					existing, ok := hg.GetVertexAdds()[shardKeyFromKey(shardSet)]
					if ok {
						existingTree = existing.GetTree()
					}
				}

				txn, err := p.NewTransaction(false)
				if err != nil {
					return err
				}
				size := len(atoms)
				for i, atom := range atoms {
					vert, ok := atom.(application.Vertex)
					if !ok {
						continue
					}
					id := vert.GetID()
					if existingTree != nil {
						if v, _ := existingTree.Get(id[:]); v != nil {
							continue
						}
					}
					hg.AddVertex(txn, vert)

					if i%100 == 99 {
						if err := txn.Commit(); err != nil {
							txn.Abort()
							return err
						}
						txn, err = p.NewTransaction(false)
						if err != nil {
							return err
						}
						p.logger.Info(
							"converted batch",
							zap.Float32("percentage", float32(i*100)/float32(size)),
						)
					}
				}

				p.logger.Info(
					"converted batch",
					zap.Float32("percentage", float32(100)),
				)
				if txn != nil {
					if err := txn.Commit(); err != nil {
						txn.Abort()
						return err
					}
				}

				p.db.Set([]byte{HYPERGRAPH_SHARD, HYPERGRAPH_COMPLETE}, []byte{0x02})
				return nil
			},
		),
		"load hypergraph",
	)
	if err != nil {
		return nil, err
	}

	return hg, nil
}

func (p *PebbleHypergraphStore) MarkHypergraphAsComplete() {
	p.db.Set([]byte{HYPERGRAPH_SHARD, HYPERGRAPH_COMPLETE}, []byte{0x02})
}

func (p *PebbleHypergraphStore) SaveHypergraph(
	hg *application.Hypergraph,
) error {
	hypergraphDir := path.Join(p.config.Path, "hypergraph")
	if _, err := os.Stat(hypergraphDir); os.IsNotExist(err) {
		err := os.MkdirAll(hypergraphDir, 0777)
		if err != nil {
			return errors.Wrap(err, "save hypergraph")
		}
	}

	for shardKey, vertexAdds := range hg.GetVertexAdds() {
		if vertexAdds.IsDirty() {
			data, err := vertexAdds.ToBytes()
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}

			err = os.WriteFile(
				path.Join(
					hypergraphDir,
					hex.EncodeToString(hypergraphVertexAddsKey(shardKey))+".tmp",
				),
				data,
				os.FileMode(0644),
			)
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}

			if err = os.Rename(
				path.Join(
					hypergraphDir,
					hex.EncodeToString(hypergraphVertexAddsKey(shardKey))+".tmp",
				),
				path.Join(
					hypergraphDir,
					hex.EncodeToString(hypergraphVertexAddsKey(shardKey))+".vct",
				),
			); err != nil {
				return errors.Wrap(err, "save hypergraph")
			}
		}
	}

	for shardKey, vertexRemoves := range hg.GetVertexRemoves() {
		if vertexRemoves.IsDirty() {
			data, err := vertexRemoves.ToBytes()
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}

			err = os.WriteFile(
				path.Join(
					hypergraphDir,
					hex.EncodeToString(hypergraphVertexRemovesKey(shardKey))+".tmp",
				),
				data,
				os.FileMode(0644),
			)
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}

			if err = os.Rename(
				path.Join(
					hypergraphDir,
					hex.EncodeToString(hypergraphVertexRemovesKey(shardKey))+".tmp",
				),
				path.Join(
					hypergraphDir,
					hex.EncodeToString(hypergraphVertexRemovesKey(shardKey))+".vct",
				),
			); err != nil {
				return errors.Wrap(err, "save hypergraph")
			}
		}
	}

	for shardKey, hyperedgeAdds := range hg.GetHyperedgeAdds() {
		if hyperedgeAdds.IsDirty() {
			data, err := hyperedgeAdds.ToBytes()
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}

			err = os.WriteFile(
				path.Join(
					hypergraphDir,
					hex.EncodeToString(hypergraphHyperedgeAddsKey(shardKey))+".tmp",
				),
				data,
				os.FileMode(0644),
			)
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}

			if err = os.Rename(
				path.Join(
					hypergraphDir,
					hex.EncodeToString(hypergraphHyperedgeAddsKey(shardKey))+".tmp",
				),
				path.Join(
					hypergraphDir,
					hex.EncodeToString(hypergraphHyperedgeAddsKey(shardKey))+".vct",
				),
			); err != nil {
				return errors.Wrap(err, "save hypergraph")
			}
		}
	}

	for shardKey, hyperedgeRemoves := range hg.GetHyperedgeRemoves() {
		if hyperedgeRemoves.IsDirty() {
			data, err := hyperedgeRemoves.ToBytes()
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}

			err = os.WriteFile(
				path.Join(
					hypergraphDir,
					hex.EncodeToString(hypergraphHyperedgeRemovesKey(shardKey))+".tmp",
				),
				data,
				os.FileMode(0644),
			)
			if err != nil {
				return errors.Wrap(err, "save hypergraph")
			}

			if err = os.Rename(
				path.Join(
					hypergraphDir,
					hex.EncodeToString(hypergraphHyperedgeRemovesKey(shardKey))+".tmp",
				),
				path.Join(
					hypergraphDir,
					hex.EncodeToString(hypergraphHyperedgeRemovesKey(shardKey))+".vct",
				),
			); err != nil {
				return errors.Wrap(err, "save hypergraph")
			}
		}
	}

	return nil
}

func (p *PebbleHypergraphStore) GetNodeByKey(
	setType string,
	phaseType string,
	shardKey crypto.ShardKey,
	key []byte,
) (crypto.LazyVectorCommitmentNode, error) {
	keyFn := hypergraphVertexAddsTreeNodeKey
	switch application.AtomType(setType) {
	case application.VertexAtomType:
		switch application.PhaseType(phaseType) {
		case application.AddsPhaseType:
			keyFn = hypergraphVertexAddsTreeNodeKey
		case application.RemovesPhaseType:
			keyFn = hypergraphVertexRemovesTreeNodeKey
		}
	case application.HyperedgeAtomType:
		switch application.PhaseType(phaseType) {
		case application.AddsPhaseType:
			keyFn = hypergraphHyperedgeAddsTreeNodeKey
		case application.RemovesPhaseType:
			keyFn = hypergraphHyperedgeRemovesTreeNodeKey
		}
	}
	data, closer, err := p.db.Get(keyFn(shardKey, key))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			err = ErrNotFound
			return nil, err
		}
	}
	defer closer.Close()

	var node crypto.LazyVectorCommitmentNode

	switch data[0] {
	case crypto.TypeLeaf:
		node, err = crypto.DeserializeLeafNode(p, bytes.NewReader(data[1:]))
	case crypto.TypeBranch:
		pathLength := binary.BigEndian.Uint32(data[1:5])

		node, err = crypto.DeserializeBranchNode(
			p,
			bytes.NewReader(data[5+(pathLength*4):]),
			false,
		)

		fullPrefix := []int{}
		for i := range pathLength {
			fullPrefix = append(
				fullPrefix,
				int(binary.BigEndian.Uint32(data[5+(i*4):5+((i+1)*4)])),
			)
		}
		branch := node.(*crypto.LazyVectorCommitmentBranchNode)
		branch.FullPrefix = fullPrefix
	default:
		err = ErrInvalidData
	}

	return node, errors.Wrap(err, "get node by key")
}

func (p *PebbleHypergraphStore) GetNodeByPath(
	setType string,
	phaseType string,
	shardKey crypto.ShardKey,
	path []int,
) (crypto.LazyVectorCommitmentNode, error) {
	keyFn := hypergraphVertexAddsTreeNodeByPathKey
	switch application.AtomType(setType) {
	case application.VertexAtomType:
		switch application.PhaseType(phaseType) {
		case application.AddsPhaseType:
			keyFn = hypergraphVertexAddsTreeNodeByPathKey
		case application.RemovesPhaseType:
			keyFn = hypergraphVertexRemovesTreeNodeByPathKey
		}
	case application.HyperedgeAtomType:
		switch application.PhaseType(phaseType) {
		case application.AddsPhaseType:
			keyFn = hypergraphHyperedgeAddsTreeNodeByPathKey
		case application.RemovesPhaseType:
			keyFn = hypergraphHyperedgeRemovesTreeNodeByPathKey
		}
	}
	pathKey := keyFn(shardKey, path)
	data, closer, err := p.db.Get(pathKey)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			err = ErrNotFound
			return nil, err
		}
	}
	defer closer.Close()

	nodeData, nodeCloser, err := p.db.Get(data)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			err = ErrNotFound
			return nil, err
		}
	}
	defer nodeCloser.Close()

	var node crypto.LazyVectorCommitmentNode

	switch nodeData[0] {
	case crypto.TypeLeaf:
		node, err = crypto.DeserializeLeafNode(
			p,
			bytes.NewReader(nodeData[1:]),
		)
	case crypto.TypeBranch:
		pathLength := binary.BigEndian.Uint32(nodeData[1:5])

		node, err = crypto.DeserializeBranchNode(
			p,
			bytes.NewReader(nodeData[5+(pathLength*4):]),
			false,
		)
		fullPrefix := []int{}
		for i := range pathLength {
			fullPrefix = append(
				fullPrefix,
				int(binary.BigEndian.Uint32(nodeData[5+(i*4):5+((i+1)*4)])),
			)
		}
		branch := node.(*crypto.LazyVectorCommitmentBranchNode)
		branch.FullPrefix = fullPrefix
	default:
		err = ErrInvalidData
	}

	return node, errors.Wrap(err, "get node by path")
}

func generateSlices(fullpref, pref []int) [][]int {
	result := [][]int{}
	if len(pref) > len(fullpref) {
		utils.GetLogger().Panic("invalid prefix length")
	}
	for i := len(pref); i <= len(fullpref); i++ {
		newSlice := make([]int, i)
		copy(newSlice, fullpref[:i])
		result = append(result, newSlice)
	}

	return result
}

func (p *PebbleHypergraphStore) InsertNode(
	txn crypto.TreeBackingStoreTransaction,
	setType string,
	phaseType string,
	shardKey crypto.ShardKey,
	key []byte,
	path []int,
	node crypto.LazyVectorCommitmentNode,
) error {
	setter := p.db.Set
	if txn != nil {
		setter = txn.Set
	}

	keyFn := hypergraphVertexAddsTreeNodeKey
	pathFn := hypergraphVertexAddsTreeNodeByPathKey
	switch application.AtomType(setType) {
	case application.VertexAtomType:
		switch application.PhaseType(phaseType) {
		case application.AddsPhaseType:
			keyFn = hypergraphVertexAddsTreeNodeKey
			pathFn = hypergraphVertexAddsTreeNodeByPathKey
		case application.RemovesPhaseType:
			keyFn = hypergraphVertexRemovesTreeNodeKey
			pathFn = hypergraphVertexRemovesTreeNodeByPathKey
		}
	case application.HyperedgeAtomType:
		switch application.PhaseType(phaseType) {
		case application.AddsPhaseType:
			keyFn = hypergraphHyperedgeAddsTreeNodeKey
			pathFn = hypergraphHyperedgeAddsTreeNodeByPathKey
		case application.RemovesPhaseType:
			keyFn = hypergraphHyperedgeRemovesTreeNodeKey
			pathFn = hypergraphHyperedgeRemovesTreeNodeByPathKey
		}
	}

	var b bytes.Buffer
	nodeKey := keyFn(shardKey, key)
	switch n := node.(type) {
	case *crypto.LazyVectorCommitmentBranchNode:
		length := uint32(len(n.FullPrefix))
		pathBytes := []byte{}
		pathBytes = binary.BigEndian.AppendUint32(pathBytes, length)
		for i := range int(length) {
			pathBytes = binary.BigEndian.AppendUint32(pathBytes, uint32(n.FullPrefix[i]))
		}
		err := crypto.SerializeBranchNode(&b, n, false)
		if err != nil {
			return errors.Wrap(err, "insert node")
		}
		data := append([]byte{crypto.TypeBranch}, pathBytes...)
		data = append(data, b.Bytes()...)
		err = setter(nodeKey, data)
		if err != nil {
			return errors.Wrap(err, "insert node")
		}
		sets := generateSlices(n.FullPrefix, path)
		for _, set := range sets {
			pathKey := pathFn(shardKey, set)
			err = setter(pathKey, nodeKey)
			if err != nil {
				return errors.Wrap(err, "insert node")
			}
		}
		return nil
	case *crypto.LazyVectorCommitmentLeafNode:
		err := crypto.SerializeLeafNode(&b, n)
		if err != nil {
			return errors.Wrap(err, "insert node")
		}
		data := append([]byte{crypto.TypeLeaf}, b.Bytes()...)
		pathKey := pathFn(shardKey, path)
		err = setter(nodeKey, data)
		if err != nil {
			return errors.Wrap(err, "insert node")
		}
		return errors.Wrap(setter(pathKey, nodeKey), "insert node")
	}

	return nil
}

func (p *PebbleHypergraphStore) SaveRoot(
	setType string,
	phaseType string,
	shardKey crypto.ShardKey,
	node crypto.LazyVectorCommitmentNode,
) error {
	keyFn := hypergraphVertexAddsTreeRootKey
	switch application.AtomType(setType) {
	case application.VertexAtomType:
		switch application.PhaseType(phaseType) {
		case application.AddsPhaseType:
			keyFn = hypergraphVertexAddsTreeRootKey
		case application.RemovesPhaseType:
			keyFn = hypergraphVertexRemovesTreeRootKey
		}
	case application.HyperedgeAtomType:
		switch application.PhaseType(phaseType) {
		case application.AddsPhaseType:
			keyFn = hypergraphHyperedgeAddsTreeRootKey
		case application.RemovesPhaseType:
			keyFn = hypergraphHyperedgeRemovesTreeRootKey
		}
	}

	var b bytes.Buffer
	nodeKey := keyFn(shardKey)
	switch n := node.(type) {
	case *crypto.LazyVectorCommitmentBranchNode:
		length := uint32(len(n.FullPrefix))
		pathBytes := []byte{}
		pathBytes = binary.BigEndian.AppendUint32(pathBytes, length)
		for i := range int(length) {
			pathBytes = binary.BigEndian.AppendUint32(
				pathBytes,
				uint32(n.FullPrefix[i]),
			)
		}
		err := crypto.SerializeBranchNode(&b, n, false)
		if err != nil {
			return errors.Wrap(err, "insert node")
		}
		data := append([]byte{crypto.TypeBranch}, pathBytes...)
		data = append(data, b.Bytes()...)
		err = p.db.Set(nodeKey, data)
		return errors.Wrap(err, "insert node")
	case *crypto.LazyVectorCommitmentLeafNode:
		err := crypto.SerializeLeafNode(&b, n)
		if err != nil {
			return errors.Wrap(err, "insert node")
		}
		data := append([]byte{crypto.TypeLeaf}, b.Bytes()...)
		err = p.db.Set(nodeKey, data)
		return errors.Wrap(err, "insert node")
	}

	return nil
}

func (p *PebbleHypergraphStore) DeletePath(
	setType string,
	phaseType string,
	shardKey crypto.ShardKey,
	path []int,
) error {
	keyFn := hypergraphVertexAddsTreeNodeByPathKey
	switch application.AtomType(setType) {
	case application.VertexAtomType:
		switch application.PhaseType(phaseType) {
		case application.AddsPhaseType:
			keyFn = hypergraphVertexAddsTreeNodeByPathKey
		case application.RemovesPhaseType:
			keyFn = hypergraphVertexRemovesTreeNodeByPathKey
		}
	case application.HyperedgeAtomType:
		switch application.PhaseType(phaseType) {
		case application.AddsPhaseType:
			keyFn = hypergraphHyperedgeAddsTreeNodeByPathKey
		case application.RemovesPhaseType:
			keyFn = hypergraphHyperedgeRemovesTreeNodeByPathKey
		}
	}
	pathKey := keyFn(shardKey, path)
	return errors.Wrap(p.db.Delete(pathKey), "delete path")
}
