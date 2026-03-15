package global

import (
	"bytes"
	"context"
	"math/big"
	"slices"
	"time"

	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/reward"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	typesconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

type shardEntry struct {
	filter      []byte
	size        *big.Int
	dataShards  uint64
	totalActive int
	isAllocated bool
}

// GetShardInfo implements typesconsensus.ShardInfoProvider.
// Returns: shardDetails, difficulty, pomwBasis, frameNumber, error.
func (e *GlobalConsensusEngine) GetShardInfo(
	includeAll bool,
) ([]*typesconsensus.ShardDetail, uint64, *big.Int, uint64, error) {
	frame, err := e.clockStore.GetLatestGlobalClockFrame()
	if err != nil {
		return nil, 0, nil, 0, errors.Wrap(err, "get shard info: latest frame")
	}

	difficulty := uint64(frame.Header.Difficulty)
	frameNumber := frame.Header.FrameNumber

	self, _ := e.allocationContext()

	// Build a set of filters this prover is allocated to.
	allocatedFilters := map[string]bool{}
	if self != nil {
		currentFrame := e.proverRegistry.CurrentFrame()
		for _, alloc := range self.Allocations {
			if alloc.Status == typesconsensus.ProverStatusJoining &&
				currentFrame > alloc.JoinFrameNumber+720 {
				continue
			}
			if alloc.Status == typesconsensus.ProverStatusLeaving &&
				currentFrame > alloc.LeaveFrameNumber+720 {
				continue
			}
			if alloc.Status == typesconsensus.ProverStatusActive ||
				alloc.Status == typesconsensus.ProverStatusJoining {
				allocatedFilters[string(alloc.ConfirmationFilter)] = true
			}
		}
	}

	appShards, err := e.shardsStore.RangeAppShards()
	if err != nil {
		return nil, 0, nil, 0, errors.Wrap(err, "get shard info: range shards")
	}

	// Consolidate into high-level L2 shards.
	shardMap := map[string]store.ShardInfo{}
	for _, s := range appShards {
		shardMap[string(s.L2)] = s
	}

	shards := make([]store.ShardInfo, 0, len(shardMap))
	for _, s := range shardMap {
		shards = append(shards, store.ShardInfo{
			L1: s.L1,
			L2: s.L2,
		})
	}

	// Try local hypergraph first.
	hg, ok := e.hypergraph.(*hypergraph.HypergraphCRDT)
	if !ok {
		return nil, 0, nil, 0, errors.New("get shard info: hypergraph type unsupported")
	}

	entries, worldBytes := e.buildShardEntries(
		shards,
		func(shardKey []byte, si store.ShardInfo) ([]*shardInfoEntry, error) {
			return e.getLocalAppShards(hg, shardKey, si)
		},
		allocatedFilters,
		includeAll,
	)

	// If local hypergraph has no data (non-archive node), fall back to
	// fetching shard sizes from the latest frame's prover.
	if worldBytes.Sign() == 0 {
		client, conn, err := e.dialFrameProver(frame)
		if err == nil {
			defer conn.Close()
			entries, worldBytes = e.buildShardEntries(
				shards,
				func(shardKey []byte, _ store.ShardInfo) ([]*shardInfoEntry, error) {
					return e.getRemoteAppShards(client, shardKey)
				},
				allocatedFilters,
				includeAll,
			)
		}
	}

	if worldBytes.Sign() == 0 {
		return nil, difficulty, big.NewInt(0), frameNumber, nil
	}

	basis := reward.PomwBasis(difficulty, worldBytes.Uint64(), 8_000_000_000)

	details := make([]*typesconsensus.ShardDetail, 0, len(entries))
	for _, entry := range entries {
		// Ring matches the actual assignment in computeRingAssignments:
		// floor(totalActiveJoining / 8) for current members, +1 for a
		// new joiner.
		ring := uint8(entry.totalActive / 8)
		if !entry.isAllocated && includeAll {
			ring = uint8((entry.totalActive + 1) / 8)
		}

		est := computeShardReward(basis, entry.size, worldBytes, ring, entry.dataShards)

		details = append(details, &typesconsensus.ShardDetail{
			Filter:          entry.filter,
			ShardSize:       entry.size,
			ActiveProvers:   entry.totalActive,
			Ring:            ring,
			EstimatedReward: est,
			IsAllocated:     entry.isAllocated,
		})
	}

	return details, difficulty, basis, frameNumber, nil
}

// buildShardEntries iterates the provided shards, fetches size data via the
// supplied function, and constructs entries enriched with local prover registry
// data. Returns the entries and total world state bytes.
func (e *GlobalConsensusEngine) buildShardEntries(
	shards []store.ShardInfo,
	getSizes func(shardKey []byte, si store.ShardInfo) ([]*shardInfoEntry, error),
	allocatedFilters map[string]bool,
	includeAll bool,
) ([]shardEntry, *big.Int) {
	worldBytes := big.NewInt(0)
	var entries []shardEntry

	for _, shardInfo := range shards {
		shardKey := slices.Concat(shardInfo.L1, shardInfo.L2)
		resp, err := getSizes(shardKey, shardInfo)
		if err != nil {
			continue
		}

		for _, shard := range resp {
			size := new(big.Int).SetBytes(shard.Size)
			if size.Cmp(big.NewInt(0)) == 0 {
				continue
			}
			worldBytes.Add(worldBytes, size)

			bp := slices.Clone(shardInfo.L2)
			for _, p := range shard.Prefix {
				bp = append(bp, byte(p))
			}

			isAlloc := allocatedFilters[string(bp)]

			if !includeAll && !isAlloc {
				continue
			}

			prs, err := e.proverRegistry.GetProvers(bp)
			if err != nil {
				continue
			}

			totalActive := 0
			for _, i := range prs {
				for _, a := range i.Allocations {
					if !bytes.Equal(a.ConfirmationFilter, bp) {
						continue
					}
					if a.Status == typesconsensus.ProverStatusActive ||
						a.Status == typesconsensus.ProverStatusJoining {
						totalActive++
					}
					break
				}
			}

			entries = append(entries, shardEntry{
				filter:      bp,
				size:        size,
				dataShards:  shard.DataShards,
				totalActive: totalActive,
				isAllocated: isAlloc,
			})
		}
	}

	return entries, worldBytes
}

// dialFrameProver establishes a gRPC connection to the prover that produced
// the given frame. The prover is discovered via the key registry and peer info
// manager. The caller must close the returned connection.
func (e *GlobalConsensusEngine) dialFrameProver(
	frame *protobufs.GlobalFrame,
) (protobufs.GlobalServiceClient, *grpc.ClientConn, error) {
	registry, err := e.keyStore.GetKeyRegistryByProver(frame.Header.Prover)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get key registry for prover")
	}

	if registry.IdentityKey == nil || registry.IdentityKey.KeyValue == nil {
		return nil, nil, errors.New("prover identity key missing")
	}

	pub, err := pcrypto.UnmarshalEd448PublicKey(registry.IdentityKey.KeyValue)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unmarshal identity key")
	}

	peerId, err := peer.IDFromPublicKey(pub)
	if err != nil {
		return nil, nil, errors.Wrap(err, "derive peer id")
	}

	info := e.peerInfoManager.GetPeerInfo([]byte(peerId))
	if info == nil {
		return nil, nil, errors.New("no peer info for prover")
	}

	if len(info.Reachability) == 0 ||
		len(info.Reachability[0].StreamMultiaddrs) == 0 {
		return nil, nil, errors.New("no stream multiaddrs for prover")
	}

	s := info.Reachability[0].StreamMultiaddrs[0]

	creds, err := p2p.NewPeerAuthenticator(
		e.logger,
		e.config.P2P,
		nil, nil, nil, nil,
		[][]byte{[]byte(peerId)},
		map[string]channel.AllowedPeerPolicyType{},
		map[string]channel.AllowedPeerPolicyType{},
	).CreateClientTLSCredentials([]byte(peerId))
	if err != nil {
		return nil, nil, errors.Wrap(err, "create credentials")
	}

	maddr, err := multiaddr.StringCast(s)
	if err != nil {
		return nil, nil, errors.Wrap(err, "parse stream multiaddr")
	}

	mga, err := mn.ToNetAddr(maddr)
	if err != nil {
		return nil, nil, errors.Wrap(err, "convert multiaddr")
	}

	conn, err := grpc.NewClient(
		mga.String(),
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "dial prover")
	}

	return protobufs.NewGlobalServiceClient(conn), conn, nil
}

// getRemoteAppShards fetches shard sizes from a remote peer via GetAppShards.
func (e *GlobalConsensusEngine) getRemoteAppShards(
	client protobufs.GlobalServiceClient,
	shardKey []byte,
) ([]*shardInfoEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.GetAppShards(ctx, &protobufs.GetAppShardsRequest{
		ShardKey: shardKey,
		Prefix:   []uint32{},
	})
	if err != nil {
		return nil, err
	}

	var result []*shardInfoEntry
	for _, shard := range resp.GetInfo() {
		result = append(result, &shardInfoEntry{
			Prefix:     shard.GetPrefix(),
			Size:       shard.GetSize(),
			DataShards: shard.GetDataShards(),
		})
	}
	return result, nil
}

// getLocalAppShards retrieves app shard info from the local cache/hypergraph.
func (e *GlobalConsensusEngine) getLocalAppShards(
	hg *hypergraph.HypergraphCRDT,
	shardKey []byte,
	shardInfo store.ShardInfo,
) ([]*shardInfoEntry, error) {
	subShards, err := e.shardsStore.GetAppShards(shardKey, nil)
	if err != nil {
		return nil, err
	}

	if len(subShards) == 0 {
		subShards = []store.ShardInfo{shardInfo}
	}

	var result []*shardInfoEntry
	for _, sub := range subShards {
		info := e.getAppShardInfoForShard(hg, sub, false)
		if info == nil {
			continue
		}
		result = append(result, &shardInfoEntry{
			Prefix:     info.Prefix,
			Size:       info.Size,
			DataShards: info.DataShards,
		})
	}
	return result, nil
}

type shardInfoEntry struct {
	Prefix     []uint32
	Size       []byte
	DataShards uint64
}

// computeShardReward computes the per-frame reward estimate for a single shard.
// Formula matches proof_of_meaningful_work.go:
//
//	(basis * shardSize / worldBytes) / (2^(ring+1) * sqrt(activeProvers))
func computeShardReward(
	basis *big.Int,
	shardSize *big.Int,
	worldBytes *big.Int,
	ring uint8,
	activeProvers uint64,
) *big.Int {
	if basis.Sign() == 0 || worldBytes.Sign() == 0 || activeProvers == 0 {
		return big.NewInt(0)
	}

	// Use the same decimal math as the reward module.
	// factor = shardSize * basis / worldBytes
	factor := new(big.Int).Mul(shardSize, basis)
	factor.Div(factor, worldBytes)

	// divisor = 2^(ring+1)
	divisor := int64(1)
	for i := uint8(0); i < ring+1; i++ {
		divisor <<= 1
	}
	if divisor == 0 {
		return big.NewInt(0)
	}
	factor.Div(factor, big.NewInt(divisor))

	// Approximate sqrt(activeProvers) using integer math:
	// Newton's method for isqrt.
	if activeProvers > 1 {
		sqrtVal := isqrt(activeProvers)
		if sqrtVal > 0 {
			factor.Div(factor, big.NewInt(int64(sqrtVal)))
		}
	}

	return factor
}

// isqrt returns the integer square root of n using Newton's method.
func isqrt(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	x := n
	y := (x + 1) / 2
	for y < x {
		x = y
		y = (x + n/x) / 2
	}
	return x
}
