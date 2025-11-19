package global

import (
	"encoding/binary"
	"math/big"
	"slices"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	thypergraph "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type appShardCacheEntry struct {
	info     *protobufs.AppShardInfo
	shardKey []byte
}

func (entry *appShardCacheEntry) toResponse(
	includeShardKey bool,
) *protobufs.AppShardInfo {
	response := &protobufs.AppShardInfo{
		Prefix:     entry.info.Prefix,
		Size:       entry.info.Size,
		DataShards: entry.info.DataShards,
		Commitment: entry.info.Commitment,
	}
	if includeShardKey {
		response.ShardKey = entry.shardKey
	}
	return response
}

func (e *GlobalConsensusEngine) rebuildAppShardCache(
	rank uint64,
) error {
	hg, ok := e.hypergraph.(*hypergraph.HypergraphCRDT)
	if !ok {
		return errors.New("hypergraph does not support caching")
	}

	shards, err := e.shardsStore.RangeAppShards()
	if err != nil {
		return errors.Wrap(err, "range app shards")
	}

	cache := make(map[string]*appShardCacheEntry, len(shards))
	for _, shard := range shards {
		entry := e.buildAppShardCacheEntry(hg, shard)
		if entry == nil {
			continue
		}
		cache[appShardCacheKey(shard)] = entry
	}

	e.appShardCacheMu.Lock()
	e.appShardCache = cache
	e.appShardCacheRank = rank
	e.appShardCacheMu.Unlock()

	return nil
}

func (e *GlobalConsensusEngine) buildAppShardCacheEntry(
	hg *hypergraph.HypergraphCRDT,
	shard store.ShardInfo,
) *appShardCacheEntry {
	shardKey, ok := toTriesShardKey(shard)
	if !ok {
		return nil
	}

	commitment, size, dataShards := e.computeAppShardMetadata(
		hg,
		shardKey,
		shard,
	)

	info := &protobufs.AppShardInfo{
		Prefix:     slices.Clone(shard.Path),
		Size:       size,
		DataShards: dataShards,
		Commitment: commitment,
	}

	return &appShardCacheEntry{
		info:     info,
		shardKey: slices.Concat(shard.L1, shard.L2),
	}
}

func (e *GlobalConsensusEngine) computeAppShardMetadata(
	hg *hypergraph.HypergraphCRDT,
	shardKey tries.ShardKey,
	shard store.ShardInfo,
) ([][]byte, []byte, uint64) {
	fullPrefix := buildAppShardFullPrefix(shard)
	phaseSets := []thypergraph.IdSet{
		hg.GetVertexAddsSet(shardKey),
		hg.GetVertexRemovesSet(shardKey),
		hg.GetHyperedgeAddsSet(shardKey),
		hg.GetHyperedgeRemovesSet(shardKey),
	}

	size := big.NewInt(0)
	commitments := make([][]byte, 0, len(phaseSets))
	var dataShards uint64

	for _, ps := range phaseSets {
		commitment, shardCount, nodeSize := getNodeMetadata(ps, fullPrefix)
		commitments = append(commitments, commitment)
		if nodeSize != nil {
			size = nodeSize
		}
		dataShards += shardCount
	}

	return commitments, size.Bytes(), dataShards
}

func (e *GlobalConsensusEngine) getAppShardInfoForShard(
	hg *hypergraph.HypergraphCRDT,
	shard store.ShardInfo,
	includeShardKey bool,
) *protobufs.AppShardInfo {
	key := appShardCacheKey(shard)
	e.appShardCacheMu.RLock()
	entry := e.appShardCache[key]
	e.appShardCacheMu.RUnlock()

	if entry == nil {
		entry = e.buildAppShardCacheEntry(hg, shard)
		if entry != nil {
			e.appShardCacheMu.Lock()
			e.appShardCache[key] = entry
			e.appShardCacheMu.Unlock()
		}
	}

	if entry == nil {
		info := &protobufs.AppShardInfo{
			Prefix: shard.Path,
			Commitment: [][]byte{
				make([]byte, 64),
				make([]byte, 64),
				make([]byte, 64),
				make([]byte, 64),
			},
		}
		if includeShardKey {
			info.ShardKey = slices.Concat(shard.L1, shard.L2)
		}
		return info
	}

	return entry.toResponse(includeShardKey)
}

func appShardCacheKey(shard store.ShardInfo) string {
	buf := make([]byte, 0, len(shard.L1)+len(shard.L2)+4*len(shard.Path))
	buf = append(buf, shard.L1...)
	buf = append(buf, shard.L2...)

	tmp := make([]byte, 4)
	for _, p := range shard.Path {
		binary.BigEndian.PutUint32(tmp, p)
		buf = append(buf, tmp...)
	}

	return string(buf)
}

func buildAppShardFullPrefix(shard store.ShardInfo) []int {
	base := tries.GetFullPath(shard.L2)
	fullPrefix := make([]int, 0, len(base)+len(shard.Path))
	fullPrefix = append(fullPrefix, base...)
	for _, p := range shard.Path {
		fullPrefix = append(fullPrefix, int(p))
	}
	return fullPrefix
}

func getNodeMetadata(
	ps thypergraph.IdSet,
	fullPrefix []int,
) ([]byte, uint64, *big.Int) {
	node, err := ps.GetTree().GetByPath(fullPrefix)
	if err != nil {
		return make([]byte, 64), 0, nil
	}

	switch n := node.(type) {
	case *tries.LazyVectorCommitmentBranchNode:
		return slices.Clone(n.Commitment),
			uint64(n.LeafCount),
			new(big.Int).Set(n.Size)
	case *tries.LazyVectorCommitmentLeafNode:
		return slices.Clone(n.Commitment), 1, new(big.Int).Set(n.Size)
	default:
		return make([]byte, 64), 0, nil
	}
}

func toTriesShardKey(shard store.ShardInfo) (tries.ShardKey, bool) {
	var l1 [3]byte
	var l2 [32]byte
	if len(shard.L1) != len(l1) || len(shard.L2) != len(l2) {
		return tries.ShardKey{}, false
	}
	copy(l1[:], shard.L1)
	copy(l2[:], shard.L2)
	return tries.ShardKey{
		L1: l1,
		L2: l2,
	}, true
}
