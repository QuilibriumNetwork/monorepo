package hypergraph

import (
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

// ShardAddress represents the three-level addressing scheme used for sharding.
// L1 is a bloom filter index, L2 is the app address, L3 is the data address.
type ShardAddress struct {
	L1 [3]byte
	L2 [32]byte
	L3 [32]byte
}

// GetShardAddress calculates the shard address for an atom based on its
// app and data addresses. The L1 field is computed using bloom filter indices.
func GetShardAddress(a Atom) ShardAddress {
	appAddress := a.GetAppAddress()
	dataAddress := a.GetDataAddress()

	return ShardAddress{
		L1: [3]byte(p2p.GetBloomFilterIndices(appAddress[:], 256, 3)),
		L2: [32]byte(append([]byte{}, appAddress[:]...)),
		L3: [32]byte(append([]byte{}, dataAddress[:]...)),
	}
}

// GetShardKey returns the shard key for an atom, which includes only the
// L1 and L2 components of the shard address.
func GetShardKey(a Atom) tries.ShardKey {
	s := GetShardAddress(a)
	return tries.ShardKey{L1: s.L1, L2: s.L2}
}
