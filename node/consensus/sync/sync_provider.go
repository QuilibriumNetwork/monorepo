package sync

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"slices"
	"time"

	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	tconsensus "source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	tp2p "source.quilibrium.com/quilibrium/monorepo/types/p2p"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

const defaultStateQueueCapacity = 1

type syncRequest struct {
	frameNumber uint64
	peerId      []byte
	identity    []byte
}

type UniqueFrame interface {
	models.Unique
	GetFrameNumber() uint64
}

type ProposalProcessor[ProposalT any] interface {
	AddProposal(proposal ProposalT)
}

// SyncProvider implements consensus.SyncProvider
type SyncProvider[StateT UniqueFrame, ProposalT any] struct {
	logger               *zap.Logger
	queuedStates         chan syncRequest
	forks                consensus.Forks[StateT]
	proverRegistry       tconsensus.ProverRegistry
	signerRegistry       tconsensus.SignerRegistry
	peerInfoManager      tp2p.PeerInfoManager
	proposalSynchronizer SyncClient[StateT, ProposalT]
	hypergraph           hypergraph.Hypergraph
	config               *config.Config

	filter        []byte
	proverAddress []byte
	filterLabel   string
	hooks         SyncProviderHooks[StateT, ProposalT]
}

var _ consensus.SyncProvider[*protobufs.GlobalFrame] = (*SyncProvider[*protobufs.GlobalFrame, *protobufs.GlobalProposal])(nil)

type SyncProviderHooks[StateT UniqueFrame, ProposalT any] interface {
	BeforeMeshSync(
		ctx context.Context,
		provider *SyncProvider[StateT, ProposalT],
	)
}

func NewSyncProvider[StateT UniqueFrame, ProposalT any](
	logger *zap.Logger,
	forks consensus.Forks[StateT],
	proverRegistry tconsensus.ProverRegistry,
	signerRegistry tconsensus.SignerRegistry,
	peerInfoManager tp2p.PeerInfoManager,
	proposalSynchronizer SyncClient[StateT, ProposalT],
	hypergraph hypergraph.Hypergraph,
	config *config.Config,
	filter []byte,
	proverAddress []byte,
	hooks SyncProviderHooks[StateT, ProposalT],
) *SyncProvider[StateT, ProposalT] {
	label := "global"
	if len(filter) > 0 {
		label = hex.EncodeToString(filter)
	}
	return &SyncProvider[StateT, ProposalT]{
		logger:               logger,
		filter:               filter, // buildutils:allow-slice-alias slice is static
		forks:                forks,
		proverRegistry:       proverRegistry,
		signerRegistry:       signerRegistry,
		peerInfoManager:      peerInfoManager,
		proposalSynchronizer: proposalSynchronizer,
		hypergraph:           hypergraph,
		proverAddress:        proverAddress, // buildutils:allow-slice-alias slice is static
		config:               config,
		queuedStates:         make(chan syncRequest, defaultStateQueueCapacity),
		filterLabel:          label,
		hooks:                hooks,
	}
}

func (p *SyncProvider[StateT, ProposalT]) Start(
	ctx lifecycle.SignalerContext,
	ready lifecycle.ReadyFunc,
) {
	ready()
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-p.queuedStates:
			finalized := p.forks.FinalizedState()
			if request.frameNumber <=
				(*p.forks.FinalizedState().State).GetFrameNumber() {
				continue
			}
			p.logger.Info(
				"synchronizing with peer",
				zap.String("peer", peer.ID(request.peerId).String()),
				zap.Uint64("finalized_rank", finalized.Rank),
				zap.Uint64("peer_frame", request.frameNumber),
			)
			p.processState(
				ctx,
				request.frameNumber,
				request.peerId,
				request.identity,
			)
		case <-time.After(10 * time.Minute):
			peerId, err := p.getRandomProverPeerId()
			if err != nil {
				p.logger.Debug("could not get random prover peer id", zap.Error(err))
				continue
			}

			select {
			case p.queuedStates <- syncRequest{
				frameNumber: (*p.forks.FinalizedState().State).GetFrameNumber() + 1,
				peerId:      []byte(peerId),
			}:
			default:
			}
		}
	}
}

func (p *SyncProvider[StateT, ProposalT]) processState(
	ctx context.Context,
	frameNumber uint64,
	peerID []byte,
	identity []byte,
) {
	err := p.syncWithPeer(
		ctx,
		frameNumber,
		peerID,
		identity,
	)
	if err != nil {
		p.logger.Error("could not sync with peer", zap.Error(err))
	}
}

func (p *SyncProvider[StateT, ProposalT]) Synchronize(
	ctx context.Context,
	existing *StateT,
) (<-chan *StateT, <-chan error) {
	dataCh := make(chan *StateT, 1)
	errCh := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				if errCh != nil {
					errCh <- errors.New(fmt.Sprintf("fatal error encountered: %+v", r))
				}
			}
		}()
		defer close(dataCh)
		defer close(errCh)

		head := p.forks.FinalizedState()
		hasFrame := head != nil

		if !hasFrame {
			errCh <- errors.New("no frame")
			return
		}

		err := p.syncWithMesh(ctx)
		if err != nil {
			dataCh <- existing
			errCh <- err
			return
		}

		if hasFrame {
			dataCh <- head.State
		}

		syncStatusCheck.WithLabelValues(p.filterLabel, "synced").Inc()
		errCh <- nil
	}()

	return dataCh, errCh
}

func (p *SyncProvider[StateT, ProposalT]) syncWithMesh(
	ctx context.Context,
) error {
	p.logger.Info("synchronizing with peers")

	if p.hooks != nil {
		p.hooks.BeforeMeshSync(ctx, p)
	}

	head := p.forks.FinalizedState()

	peers, err := p.proverRegistry.GetActiveProvers(p.filter)
	if len(peers) <= 1 || err != nil {
		return nil
	}

	for _, candidate := range peers {
		if bytes.Equal(candidate.Address, p.proverAddress) {
			continue
		}

		registry, err := p.signerRegistry.GetKeyRegistryByProver(
			candidate.Address,
		)
		if err != nil {
			continue
		}

		if registry.IdentityKey == nil || registry.IdentityKey.KeyValue == nil {
			continue
		}

		pub, err := pcrypto.UnmarshalEd448PublicKey(registry.IdentityKey.KeyValue)
		if err != nil {
			p.logger.Warn("error unmarshaling identity key", zap.Error(err))
			continue
		}

		peerID, err := peer.IDFromPublicKey(pub)
		if err != nil {
			p.logger.Warn("error deriving peer id", zap.Error(err))
			continue
		}

		err = p.syncWithPeer(
			ctx,
			(*head.State).GetFrameNumber(),
			[]byte(peerID),
			nil,
		)
		if err != nil {
			p.logger.Debug("error syncing frame", zap.Error(err))
		}
	}

	head = p.forks.FinalizedState()

	p.logger.Info(
		"returning leader frame",
		zap.Uint64("frame_number", (*head.State).GetFrameNumber()),
		zap.Duration(
			"frame_age",
			time.Since(time.UnixMilli(int64((*head.State).GetTimestamp()))),
		),
	)

	return nil
}

func (p *SyncProvider[StateT, ProposalT]) syncWithPeer(
	ctx context.Context,
	frameNumber uint64,
	peerId []byte,
	expectedIdentity []byte,
) error {
	p.logger.Info(
		"polling peer for new frames",
		zap.String("peer_id", peer.ID(peerId).String()),
		zap.Uint64("current_frame", frameNumber),
	)

	info := p.peerInfoManager.GetPeerInfo(peerId)
	if info == nil {
		p.logger.Info(
			"no peer info known yet, skipping sync",
			zap.String("peer", peer.ID(peerId).String()),
		)
		return nil
	}
	if len(info.Reachability) == 0 {
		p.logger.Info(
			"no reachability info known yet, skipping sync",
			zap.String("peer", peer.ID(peerId).String()),
		)
		return nil
	}

	for _, reachability := range info.Reachability {
		if !bytes.Equal(reachability.Filter, p.filter) {
			continue
		}
		for _, s := range reachability.StreamMultiaddrs {
			cc, err := p.getDirectChannel(peerId, s)
			if err != nil {
				p.logger.Debug(
					"could not establish direct channel, trying next multiaddr",
					zap.String("peer", peer.ID(peerId).String()),
					zap.String("multiaddr", s),
					zap.Error(err),
				)
				continue
			}
			defer func() {
				if err := cc.Close(); err != nil {
					p.logger.Error("error while closing connection", zap.Error(err))
				}
			}()

			err = p.proposalSynchronizer.Sync(
				ctx,
				p.logger.With(
					zap.String("peer", peer.ID(peerId).String()),
					zap.String("multiaddr", s),
				),
				cc,
				frameNumber,
				expectedIdentity,
			)
			if err != nil {
				if errors.Is(err, ErrConnectivityFailed) {
					continue
				}

				return errors.Wrap(err, "sync")
			}
		}
		break
	}

	p.logger.Debug(
		"failed to complete sync for all known multiaddrs",
		zap.String("peer", peer.ID(peerId).String()),
	)
	return nil
}

func (p *SyncProvider[StateT, ProposalT]) HyperSync(
	ctx context.Context,
	prover []byte,
	shardKey tries.ShardKey,
	filter []byte,
	expectedRoot []byte,
) {
	registry, err := p.signerRegistry.GetKeyRegistryByProver(prover)
	if err != nil || registry == nil || registry.IdentityKey == nil {
		p.logger.Debug(
			"failed to find key registry info for prover",
			zap.String("prover", hex.EncodeToString(prover)),
		)
		return
	}

	peerKey := registry.IdentityKey
	pubKey, err := pcrypto.UnmarshalEd448PublicKey(peerKey.KeyValue)
	if err != nil {
		p.logger.Error(
			"could not unmarshal key info",
			zap.String("prover", hex.EncodeToString(prover)),
			zap.String("prover", hex.EncodeToString(peerKey.KeyValue)),
		)
		return
	}

	peerId, err := peer.IDFromPublicKey(pubKey)
	info := p.peerInfoManager.GetPeerInfo([]byte(peerId))
	if info == nil {
		p.logger.Info(
			"no peer info known yet, skipping hypersync",
			zap.String("peer", peer.ID(peerId).String()),
		)
		return
	}
	if len(info.Reachability) == 0 {
		p.logger.Info(
			"no reachability info known yet, skipping sync",
			zap.String("peer", peer.ID(peerId).String()),
		)
		return
	}

	phaseSyncs := []func(
		protobufs.HypergraphComparisonService_HyperStreamClient,
		tries.ShardKey,
		[]byte,
	){
		p.hyperSyncVertexAdds,
		p.hyperSyncVertexRemoves,
		p.hyperSyncHyperedgeAdds,
		p.hyperSyncHyperedgeRemoves,
	}

	for _, reachability := range info.Reachability {
		if !bytes.Equal(reachability.Filter, filter) {
			continue
		}
		for _, s := range reachability.StreamMultiaddrs {
			for _, syncPhase := range phaseSyncs {
				ch, err := p.getDirectChannel([]byte(peerId), s)
				if err != nil {
					p.logger.Debug(
						"could not establish direct channel, trying next multiaddr",
						zap.String("peer", peer.ID(peerId).String()),
						zap.String("multiaddr", s),
						zap.Error(err),
					)
					continue
				}

				client := protobufs.NewHypergraphComparisonServiceClient(ch)
				str, err := client.HyperStream(ctx)
				if err != nil {
					p.logger.Error("error from sync", zap.Error(err))
					return
				}

				syncPhase(str, shardKey, expectedRoot)
				if cerr := ch.Close(); cerr != nil {
					p.logger.Error("error while closing connection", zap.Error(cerr))
				}
			}
		}
		break
	}
}

// HyperSyncSelf syncs from our own master node using our peer ID.
// This is used by workers to sync global prover state from their master
// instead of burdening the proposer.
func (p *SyncProvider[StateT, ProposalT]) HyperSyncSelf(
	ctx context.Context,
	selfPeerID peer.ID,
	shardKey tries.ShardKey,
	filter []byte,
	expectedRoot []byte,
) {
	info := p.peerInfoManager.GetPeerInfo([]byte(selfPeerID))
	if info == nil {
		p.logger.Debug(
			"no peer info for self, skipping self-sync",
			zap.String("peer", selfPeerID.String()),
		)
		return
	}
	if len(info.Reachability) == 0 {
		p.logger.Debug(
			"no reachability info for self, skipping self-sync",
			zap.String("peer", selfPeerID.String()),
		)
		return
	}

	phaseSyncs := []func(
		protobufs.HypergraphComparisonService_HyperStreamClient,
		tries.ShardKey,
		[]byte,
	){
		p.hyperSyncVertexAdds,
		p.hyperSyncVertexRemoves,
		p.hyperSyncHyperedgeAdds,
		p.hyperSyncHyperedgeRemoves,
	}

	for _, reachability := range info.Reachability {
		if !bytes.Equal(reachability.Filter, filter) {
			continue
		}
		for _, s := range reachability.StreamMultiaddrs {
			for _, syncPhase := range phaseSyncs {
				ch, err := p.getDirectChannel([]byte(selfPeerID), s)
				if err != nil {
					p.logger.Debug(
						"could not establish direct channel for self-sync, trying next multiaddr",
						zap.String("peer", selfPeerID.String()),
						zap.String("multiaddr", s),
						zap.Error(err),
					)
					continue
				}

				client := protobufs.NewHypergraphComparisonServiceClient(ch)
				str, err := client.HyperStream(ctx)
				if err != nil {
					p.logger.Error("error from self-sync", zap.Error(err))
					return
				}

				syncPhase(str, shardKey, expectedRoot)
				if cerr := ch.Close(); cerr != nil {
					p.logger.Error("error while closing connection", zap.Error(cerr))
				}
			}
		}
		break
	}
}

func (p *SyncProvider[StateT, ProposalT]) hyperSyncVertexAdds(
	str protobufs.HypergraphComparisonService_HyperStreamClient,
	shardKey tries.ShardKey,
	expectedRoot []byte,
) {
	err := p.hypergraph.Sync(
		str,
		shardKey,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
		expectedRoot,
	)
	if err != nil {
		p.logger.Error("error from sync", zap.Error(err))
	}
	str.CloseSend()
}

func (p *SyncProvider[StateT, ProposalT]) hyperSyncVertexRemoves(
	str protobufs.HypergraphComparisonService_HyperStreamClient,
	shardKey tries.ShardKey,
	expectedRoot []byte,
) {
	err := p.hypergraph.Sync(
		str,
		shardKey,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_REMOVES,
		expectedRoot,
	)
	if err != nil {
		p.logger.Error("error from sync", zap.Error(err))
	}
	str.CloseSend()
}

func (p *SyncProvider[StateT, ProposalT]) hyperSyncHyperedgeAdds(
	str protobufs.HypergraphComparisonService_HyperStreamClient,
	shardKey tries.ShardKey,
	expectedRoot []byte,
) {
	err := p.hypergraph.Sync(
		str,
		shardKey,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_ADDS,
		expectedRoot,
	)
	if err != nil {
		p.logger.Error("error from sync", zap.Error(err))
	}
	str.CloseSend()
}

func (p *SyncProvider[StateT, ProposalT]) hyperSyncHyperedgeRemoves(
	str protobufs.HypergraphComparisonService_HyperStreamClient,
	shardKey tries.ShardKey,
	expectedRoot []byte,
) {
	err := p.hypergraph.Sync(
		str,
		shardKey,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_REMOVES,
		expectedRoot,
	)
	if err != nil {
		p.logger.Error("error from sync", zap.Error(err))
	}
	str.CloseSend()
}

func (p *SyncProvider[StateT, ProposalT]) AddState(
	sourcePeerID []byte,
	frameNumber uint64,
	expectedIdentity []byte,
) {
	// Adjust if we're within the threshold
	if frameNumber <=
		(*p.forks.FinalizedState().State).GetFrameNumber() &&
		frameNumber != 0 {
		frameNumber = frameNumber + 1
		expectedIdentity = nil
	}

	// Handle special case: we're at genesis frame on time reel
	if frameNumber == 0 {
		frameNumber = 1
		expectedIdentity = []byte{}
	}

	// Enqueue if we can, otherwise drop it because we'll catch up
	select {
	case p.queuedStates <- syncRequest{
		frameNumber: frameNumber,
		peerId:      slices.Clone(sourcePeerID),
		identity:    slices.Clone(expectedIdentity),
	}:
		p.logger.Debug(
			"enqueued sync request",
			zap.String("peer", peer.ID(sourcePeerID).String()),
			zap.Uint64("enqueued_frame_number", frameNumber),
		)
	default:
		p.logger.Debug("no queue capacity, dropping state for sync")
	}
}

func (p *SyncProvider[StateT, ProposalT]) getDirectChannel(
	peerId []byte,
	multiaddrString string,
) (
	*grpc.ClientConn,
	error,
) {
	creds, err := p2p.NewPeerAuthenticator(
		p.logger,
		p.config.P2P,
		nil,
		nil,
		nil,
		nil,
		[][]byte{peerId},
		map[string]channel.AllowedPeerPolicyType{},
		map[string]channel.AllowedPeerPolicyType{},
	).CreateClientTLSCredentials(peerId)
	if err != nil {
		return nil, err
	}

	ma, err := multiaddr.StringCast(multiaddrString)
	if err != nil {
		return nil, err
	}

	mga, err := mn.ToNetAddr(ma)
	if err != nil {
		return nil, err
	}

	cc, err := grpc.NewClient(
		mga.String(),
		grpc.WithTransportCredentials(creds),
	)
	return cc, err
}

func (e *SyncProvider[StateT, ProposalT]) getPeerIDOfProver(
	prover []byte,
) (peer.ID, error) {
	registry, err := e.signerRegistry.GetKeyRegistryByProver(
		prover,
	)
	if err != nil {
		e.logger.Debug(
			"could not get registry for prover",
			zap.Error(err),
		)
		return "", err
	}

	if registry == nil || registry.IdentityKey == nil {
		e.logger.Debug("registry for prover not found")
		return "", err
	}

	pk, err := pcrypto.UnmarshalEd448PublicKey(registry.IdentityKey.KeyValue)
	if err != nil {
		e.logger.Debug(
			"could not parse pub key",
			zap.Error(err),
		)
		return "", err
	}

	id, err := peer.IDFromPublicKey(pk)
	if err != nil {
		e.logger.Debug(
			"could not derive peer id",
			zap.Error(err),
		)
		return "", err
	}

	return id, nil
}

func (e *SyncProvider[StateT, ProposalT]) getRandomProverPeerId() (
	peer.ID,
	error,
) {
	provers, err := e.proverRegistry.GetActiveProvers(nil)
	if err != nil {
		e.logger.Error(
			"could not get active provers for sync",
			zap.Error(err),
		)
	}
	if len(provers) == 0 {
		return "", err
	}

	otherProvers := []*tconsensus.ProverInfo{}
	for _, p := range provers {
		if bytes.Equal(p.Address, e.proverAddress) {
			continue
		}
		otherProvers = append(otherProvers, p)
	}

	index := rand.Intn(len(otherProvers))
	return e.getPeerIDOfProver(otherProvers[index].Address)
}
