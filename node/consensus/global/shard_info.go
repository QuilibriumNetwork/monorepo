package global

import (
	"bytes"
	"context"
	"math/big"
	"slices"
	"sort"
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
	filter        []byte
	size          *big.Int
	dataShards    uint64
	totalActive   int
	proversOnRing int
	isAllocated   bool
	ring          uint8
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

	self, _ := e.workerAllocator.allocationContext()

	var selfAddress []byte
	if self != nil {
		selfAddress = self.Address
	}

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
		selfAddress,
		includeAll,
	)

	// Non-archive nodes only have local hypergraph data for shards they're
	// assigned to. When includeAll is requested the local path returns
	// partial results (zero-size shards are dropped in buildShardEntries),
	// but worldBytes > 0 from the allocated shards prevents the fallback
	// from triggering. Fall back to the remote path when the local result
	// is incomplete.
	useRemote := worldBytes.Sign() == 0
	if !useRemote && includeAll && !e.config.Engine.ArchiveMode {
		// Count how many shards we expect vs how many we got.
		// If local data is incomplete, prefer remote.
		useRemote = len(entries) < len(shards)
	}

	if useRemote {
		client, conn, err := e.dialFrameProver(frame)
		if err == nil {
			defer conn.Close()
			entries, worldBytes = e.buildShardEntries(
				shards,
				func(shardKey []byte, _ store.ShardInfo) ([]*shardInfoEntry, error) {
					return e.getRemoteAppShards(client, shardKey)
				},
				allocatedFilters,
				selfAddress,
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
		est := computeShardReward(basis, entry.size, worldBytes, entry.ring, entry.dataShards)

		details = append(details, &typesconsensus.ShardDetail{
			Filter:          entry.filter,
			ShardSize:       entry.size,
			ActiveProvers:   entry.totalActive,
			Ring:            entry.ring,
			EstimatedReward: est,
			IsAllocated:     entry.isAllocated,
			DataShards:      entry.dataShards,
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
	selfAddress []byte,
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

			// Compute the actual ring assignment for this prover by
			// replicating the sort from computeRingAssignments:
			// sort by joinFrame asc, seniority desc, address asc.
			type candidate struct {
				joinFrame uint64
				seniority uint64
				address   []byte
			}
			var candidates []candidate
			for _, pr := range prs {
				for _, a := range pr.Allocations {
					if !bytes.Equal(a.ConfirmationFilter, bp) {
						continue
					}
					if a.Status == typesconsensus.ProverStatusActive ||
						a.Status == typesconsensus.ProverStatusJoining {
						jf := a.JoinFrameNumber
						if jf == 0 && a.JoinConfirmFrameNumber != 0 {
							jf = a.JoinConfirmFrameNumber
						}
						candidates = append(candidates, candidate{
							joinFrame: jf,
							seniority: pr.Seniority,
							address:   pr.Address,
						})
					}
					break
				}
			}

			sort.Slice(candidates, func(i, j int) bool {
				if candidates[i].joinFrame != candidates[j].joinFrame {
					return candidates[i].joinFrame < candidates[j].joinFrame
				}
				if candidates[i].seniority != candidates[j].seniority {
					return candidates[i].seniority > candidates[j].seniority
				}
				return bytes.Compare(candidates[i].address, candidates[j].address) < 0
			})

			ring, onRing := resolveProverRing(
				len(candidates), isAlloc, selfAddress,
				func() [][]byte {
					addrs := make([][]byte, len(candidates))
					for i, c := range candidates {
						addrs[i] = c.address
					}
					return addrs
				},
			)

			entries = append(entries, shardEntry{
				filter:        bp,
				size:          size,
				dataShards:    shard.DataShards,
				totalActive:   len(candidates),
				proversOnRing: onRing,
				isAllocated:   isAlloc,
				ring:          ring,
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

// computeShardReward computes the per-prover per-frame reward estimate.
// Formula matches proof_of_meaningful_work.go (Materialize):
//
//	per_ring  = (basis * shardSize / worldBytes) / (2^(ring+1) * sqrt(dataShards))
//	per_prover = per_ring / proversOnRing
func computeShardReward(
	basis *big.Int,
	shardSize *big.Int,
	worldBytes *big.Int,
	ring uint8,
	dataShards uint64,
) *big.Int {
	if basis.Sign() == 0 || worldBytes.Sign() == 0 || dataShards == 0 {
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

	// sqrt(dataShards) — matches the sqrt(shardCount) in the reward module.
	if dataShards > 1 {
		sqrtVal := isqrt(dataShards)
		if sqrtVal > 0 {
			factor.Div(factor, big.NewInt(int64(sqrtVal)))
		}
	}

	// Divide by constant max ring size (partially filled rings still split by 8).
	factor.Div(factor, big.NewInt(8))

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
