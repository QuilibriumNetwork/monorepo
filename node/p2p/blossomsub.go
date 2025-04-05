package p2p

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	libp2pconfig "github.com/libp2p/go-libp2p/config"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/libp2p/go-libp2p/p2p/host/eventbus"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	routedhost "github.com/libp2p/go-libp2p/p2p/host/routed"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/libp2p/go-libp2p/p2p/net/gostream"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/mr-tron/base58"
	ma "github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/wrapperspb"
	blossomsub "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	qgrpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/observability"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p/internal"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/utils"
)

const (
	DecayInterval = 10 * time.Second
	AppDecay      = .9
)

type appScore struct {
	expire time.Time
	score  float64
}

type BlossomSub struct {
	ps           *blossomsub.PubSub
	ctx          context.Context
	logger       *zap.Logger
	peerID       peer.ID
	bitmaskMap   map[string]*blossomsub.Bitmask
	h            host.Host
	signKey      crypto.PrivKey
	peerScore    map[string]*appScore
	peerScoreMx  sync.Mutex
	bootstrap    internal.PeerConnector
	discovery    internal.PeerConnector
	reachability atomic.Pointer[network.Reachability]
	p2pConfig    config.P2PConfig
}

var _ PubSub = (*BlossomSub)(nil)
var ErrNoPeersAvailable = errors.New("no peers available")

var BITMASK_ALL = []byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

var ANNOUNCE_PREFIX = "quilibrium-2.0.2-dusk-"

func getPeerID(p2pConfig *config.P2PConfig) peer.ID {
	logger := utils.GetLogger().With(zap.String("stage", "get-peer-id"))
	peerPrivKey, err := hex.DecodeString(p2pConfig.PeerPrivKey)
	if err != nil {
		logger.Panic("error unmarshaling peerkey", zap.Error(err))
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		logger.Panic("error unmarshaling peerkey", zap.Error(err))
	}

	pub := privKey.GetPublic()
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		logger.Panic("error getting peer id", zap.Error(err))
	}

	return id
}

func NewBlossomSubStreamer(
	p2pConfig *config.P2PConfig,
	logger *zap.Logger,
) *BlossomSub {
	ctx := context.Background()

	opts := []libp2pconfig.Option{
		libp2p.ListenAddrStrings(p2pConfig.ListenMultiaddr),
	}

	bootstrappers := []peer.AddrInfo{}

	peerinfo, err := peer.AddrInfoFromString("/ip4/185.209.178.191/udp/8336/quic-v1/p2p/QmcKQjpQmLpbDsiif2MuakhHFyxWvqYauPsJDaXnLav7PJ")
	if err != nil {
		logger.Panic("error getting peer info", zap.Error(err))
	}

	bootstrappers = append(bootstrappers, *peerinfo)

	var privKey crypto.PrivKey
	if p2pConfig.PeerPrivKey != "" {
		peerPrivKey, err := hex.DecodeString(p2pConfig.PeerPrivKey)
		if err != nil {
			logger.Panic("error unmarshaling peerkey", zap.Error(err))
		}

		privKey, err = crypto.UnmarshalEd448PrivateKey(peerPrivKey)
		if err != nil {
			logger.Panic("error unmarshaling peerkey", zap.Error(err))
		}

		opts = append(opts, libp2p.Identity(privKey))
	}

	bs := &BlossomSub{
		ctx:        ctx,
		logger:     logger,
		bitmaskMap: make(map[string]*blossomsub.Bitmask),
		signKey:    privKey,
		peerScore:  make(map[string]*appScore),
		p2pConfig:  *p2pConfig,
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		logger.Panic("error constructing p2p", zap.Error(err))
	}

	logger.Info("established peer id", zap.String("peer_id", h.ID().String()))

	_ = initDHT(
		ctx,
		logger,
		h,
		false,
		bootstrappers,
		p2pConfig.Network,
	)

	peerID := h.ID()
	bs.peerID = peerID
	bs.h = h
	bs.signKey = privKey

	return bs
}

func NewBlossomSub(
	p2pConfig *config.P2PConfig,
	logger *zap.Logger,
) *BlossomSub {
	ctx := context.Background()

	opts := []libp2pconfig.Option{
		libp2p.ListenAddrStrings(p2pConfig.ListenMultiaddr),
		libp2p.EnableNATService(),
		libp2p.NATPortMap(),
	}

	isBootstrapPeer := false
	peerId := getPeerID(p2pConfig)

	if p2pConfig.Network == 0 {
		for _, peerAddr := range config.BootstrapPeers {
			peerinfo, err := peer.AddrInfoFromString(peerAddr)
			if err != nil {
				logger.Panic("error getting peer info", zap.Error(err))
			}

			if bytes.Equal([]byte(peerinfo.ID), []byte(peerId)) {
				isBootstrapPeer = true
				break
			}
		}
	} else {
		for _, peerAddr := range p2pConfig.BootstrapPeers {
			peerinfo, err := peer.AddrInfoFromString(peerAddr)
			if err != nil {
				logger.Panic("error getting peer info", zap.Error(err))
			}

			if bytes.Equal([]byte(peerinfo.ID), []byte(peerId)) {
				isBootstrapPeer = true
				break
			}
		}
	}

	defaultBootstrapPeers := append([]string{}, p2pConfig.BootstrapPeers...)

	if p2pConfig.Network == 0 {
		defaultBootstrapPeers = config.BootstrapPeers
	}

	bootstrappers := []peer.AddrInfo{}

	for _, peerAddr := range defaultBootstrapPeers {
		peerinfo, err := peer.AddrInfoFromString(peerAddr)
		if err != nil {
			logger.Panic("error getting peer info", zap.Error(err))
		}

		bootstrappers = append(bootstrappers, *peerinfo)
	}

	var privKey crypto.PrivKey
	if p2pConfig.PeerPrivKey != "" {
		peerPrivKey, err := hex.DecodeString(p2pConfig.PeerPrivKey)
		if err != nil {
			logger.Panic("error unmarshaling peerkey", zap.Error(err))
		}

		privKey, err = crypto.UnmarshalEd448PrivateKey(peerPrivKey)
		if err != nil {
			logger.Panic("error unmarshaling peerkey", zap.Error(err))
		}

		opts = append(opts, libp2p.Identity(privKey))
	}

	allowedPeers := []peer.AddrInfo{}
	allowedPeers = append(allowedPeers, bootstrappers...)

	directPeers := []peer.AddrInfo{}
	if len(p2pConfig.DirectPeers) > 0 {
		logger.Info("found direct peers in config")
		for _, peerAddr := range p2pConfig.DirectPeers {
			peerinfo, err := peer.AddrInfoFromString(peerAddr)
			if err != nil {
				logger.Panic("error getting peer info", zap.Error(err))
			}
			logger.Info("adding direct peer", zap.String("peer", peerinfo.ID.String()))
			directPeers = append(directPeers, *peerinfo)
		}
	}
	allowedPeers = append(allowedPeers, directPeers...)

	if p2pConfig.LowWatermarkConnections != -1 &&
		p2pConfig.HighWatermarkConnections != -1 {
		cm, err := connmgr.NewConnManager(
			p2pConfig.LowWatermarkConnections,
			p2pConfig.HighWatermarkConnections,
			connmgr.WithEmergencyTrim(true),
		)
		if err != nil {
			logger.Panic("error creating connection manager", zap.Error(err))
		}

		rm, err := resourceManager(
			p2pConfig.HighWatermarkConnections,
			allowedPeers,
		)
		if err != nil {
			logger.Panic("error creating resource manager", zap.Error(err))
		}

		opts = append(
			opts,
			libp2p.SwarmOpts(
				swarm.WithIPv6BlackHoleConfig(false, 0, 0),
				swarm.WithUDPBlackHoleConfig(false, 0, 0),
			),
		)
		opts = append(opts, libp2p.ConnectionManager(cm))
		opts = append(opts, libp2p.ResourceManager(rm))
	}

	bs := &BlossomSub{
		ctx:        ctx,
		logger:     logger,
		bitmaskMap: make(map[string]*blossomsub.Bitmask),
		signKey:    privKey,
		peerScore:  make(map[string]*appScore),
		p2pConfig:  *p2pConfig,
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		logger.Panic("error constructing p2p", zap.Error(err))
	}
	idService := internal.IDServiceFromHost(h)

	logger.Info("established peer id", zap.String("peer_id", h.ID().String()))

	reachabilitySub, err := h.EventBus().Subscribe(&event.EvtLocalReachabilityChanged{}, eventbus.Name("blossomsub"))
	if err != nil {
		logger.Panic("error subscribing to reachability events", zap.Error(err))
	}
	go func() {
		defer reachabilitySub.Close()
		logger := logger.Named("reachability")
		for {
			select {
			case <-ctx.Done():
				return
			case evt, ok := <-reachabilitySub.Out():
				if !ok {
					return
				}
				state := evt.(event.EvtLocalReachabilityChanged).Reachability
				bs.reachability.Store(&state)
				switch state {
				case network.ReachabilityPublic:
					logger.Info("node is externally reachable")
				case network.ReachabilityPrivate:
					logger.Info("node is not externally reachable")
				case network.ReachabilityUnknown:
					logger.Info("node reachability is unknown")
				default:
					logger.Debug("unknown reachability state", zap.Any("state", state))
				}
			}
		}
	}()

	kademliaDHT := initDHT(
		ctx,
		logger,
		h,
		isBootstrapPeer,
		bootstrappers,
		p2pConfig.Network,
	)
	h = routedhost.Wrap(h, kademliaDHT)

	routingDiscovery := routing.NewRoutingDiscovery(kademliaDHT)
	util.Advertise(ctx, routingDiscovery, getNetworkNamespace(p2pConfig.Network))

	minBootstrapPeers := min(len(bootstrappers), p2pConfig.MinBootstrapPeers)
	bootstrap := internal.NewPeerConnector(
		ctx,
		logger.Named("bootstrap"),
		h,
		idService,
		minBootstrapPeers,
		p2pConfig.BootstrapParallelism,
		internal.NewStaticPeerSource(bootstrappers, true),
	)
	if err := bootstrap.Connect(ctx); err != nil {
		logger.Panic("error connecting to bootstrap peers", zap.Error(err))
	}
	bootstrap = internal.NewConditionalPeerConnector(
		ctx,
		internal.NewNotEnoughPeersCondition(
			h,
			minBootstrapPeers,
			internal.PeerAddrInfosToPeerIDMap(bootstrappers),
		),
		bootstrap,
	)
	bs.bootstrap = bootstrap

	discovery := internal.NewPeerConnector(
		ctx,
		logger.Named("discovery"),
		h,
		idService,
		p2pConfig.D,
		p2pConfig.DiscoveryParallelism,
		internal.NewRoutingDiscoveryPeerSource(
			routingDiscovery,
			getNetworkNamespace(p2pConfig.Network),
			p2pConfig.DiscoveryPeerLookupLimit,
		),
	)
	if err := discovery.Connect(ctx); err != nil {
		logger.Panic("error connecting to discovery peers", zap.Error(err))
	}
	discovery = internal.NewChainedPeerConnector(ctx, bootstrap, discovery)
	bs.discovery = discovery

	internal.MonitorPeers(
		ctx,
		logger.Named("peer-monitor"),
		h,
		p2pConfig.PingTimeout,
		p2pConfig.PingPeriod,
		p2pConfig.PingAttempts,
	)

	// TODO: turn into an option flag for console logging, this is too noisy for
	// default logging behavior
	var tracer *blossomsub.JSONTracer
	if p2pConfig.TraceLogFile == "" {
		// tracer, err = blossomsub.NewStdoutJSONTracer()
		// if err != nil {
		// 	panic(errors.Wrap(err, "error building stdout tracer"))
		// }
	} else {
		tracer, err = blossomsub.NewJSONTracer(p2pConfig.TraceLogFile)
		if err != nil {
			logger.Panic("error building file tracer", zap.Error(err))
		}
	}

	blossomOpts := []blossomsub.Option{
		blossomsub.WithStrictSignatureVerification(true),
	}

	if len(directPeers) > 0 {
		blossomOpts = append(blossomOpts, blossomsub.WithDirectPeers(directPeers))
	}

	if tracer != nil {
		blossomOpts = append(blossomOpts, blossomsub.WithEventTracer(tracer))
	}
	blossomOpts = append(blossomOpts, blossomsub.WithPeerScore(
		&blossomsub.PeerScoreParams{
			SkipAtomicValidation:        false,
			BitmaskScoreCap:             0,
			IPColocationFactorWeight:    0,
			IPColocationFactorThreshold: 6,
			BehaviourPenaltyWeight:      -10,
			BehaviourPenaltyThreshold:   100,
			BehaviourPenaltyDecay:       .5,
			DecayInterval:               DecayInterval,
			DecayToZero:                 .1,
			RetainScore:                 60 * time.Minute,
			AppSpecificScore: func(p peer.ID) float64 {
				return float64(bs.GetPeerScore([]byte(p)))
			},
			AppSpecificWeight: 10.0,
		},
		&blossomsub.PeerScoreThresholds{
			SkipAtomicValidation:        false,
			GossipThreshold:             -2000,
			PublishThreshold:            -5000,
			GraylistThreshold:           -10000,
			AcceptPXThreshold:           1,
			OpportunisticGraftThreshold: 2,
		},
	))
	blossomOpts = append(blossomOpts,
		blossomsub.WithValidateQueueSize(p2pConfig.ValidateQueueSize),
		blossomsub.WithValidateWorkers(p2pConfig.ValidateWorkers),
		blossomsub.WithPeerOutboundQueueSize(p2pConfig.PeerOutboundQueueSize),
	)
	blossomOpts = append(blossomOpts, observability.WithPrometheusRawTracer())
	blossomOpts = append(blossomOpts, blossomsub.WithPeerFilter(internal.NewStaticPeerFilter(
		// We filter out the bootstrap peers explicitly from BlossomSub
		// as they do not subscribe to relevant topics anymore.
		// However, the beacon is one of the bootstrap peers usually
		// and as such it gets special treatment - it is the only bootstrap
		// peer which is engaged in the network.
		[]peer.ID{internal.BeaconPeerID(uint(p2pConfig.Network))},
		internal.PeerAddrInfosToPeerIDSlice(bootstrappers),
		true,
	)))
	blossomOpts = append(blossomOpts, blossomsub.WithDiscovery(
		internal.NewPeerConnectorDiscovery(discovery),
	))

	params := toBlossomSubParams(p2pConfig)
	rt := blossomsub.NewBlossomSubRouter(h, params, bs.p2pConfig.Network)
	blossomOpts = append(blossomOpts, rt.WithDefaultTagTracer())
	pubsub, err := blossomsub.NewBlossomSubWithRouter(ctx, h, rt, blossomOpts...)
	if err != nil {
		logger.Panic("error creating pubsub", zap.Error(err))
	}

	peerID := h.ID()
	bs.ps = pubsub
	bs.peerID = peerID
	bs.h = h
	bs.signKey = privKey

	go bs.background(ctx)

	return bs
}

// adjusted from Lotus' reference implementation, addressing
// https://github.com/libp2p/go-libp2p/issues/1640
func resourceManager(highWatermark int, allowed []peer.AddrInfo) (
	network.ResourceManager,
	error,
) {
	defaultLimits := rcmgr.DefaultLimits

	libp2p.SetDefaultServiceLimits(&defaultLimits)

	defaultLimits.SystemBaseLimit.Memory = 1 << 28
	defaultLimits.SystemLimitIncrease.Memory = 1 << 28
	defaultLimitConfig := defaultLimits.AutoScale()

	changes := rcmgr.PartialLimitConfig{}

	if defaultLimitConfig.ToPartialLimitConfig().System.Memory > 2<<30 {
		changes.System.Memory = 2 << 30
	}

	maxconns := uint(highWatermark)
	if rcmgr.LimitVal(3*maxconns) > defaultLimitConfig.
		ToPartialLimitConfig().System.ConnsInbound {
		changes.System.ConnsInbound = rcmgr.LimitVal(1 << bits.Len(3*maxconns))
		changes.System.ConnsOutbound = rcmgr.LimitVal(1 << bits.Len(3*maxconns))
		changes.System.Conns = rcmgr.LimitVal(1 << bits.Len(6*maxconns))
		changes.System.StreamsInbound = rcmgr.LimitVal(1 << bits.Len(36*maxconns))
		changes.System.StreamsOutbound = rcmgr.LimitVal(1 << bits.Len(216*maxconns))
		changes.System.Streams = rcmgr.LimitVal(1 << bits.Len(216*maxconns))

		if rcmgr.LimitVal(3*maxconns) > defaultLimitConfig.
			ToPartialLimitConfig().System.FD {
			changes.System.FD = rcmgr.LimitVal(1 << bits.Len(3*maxconns))
		}

		changes.ServiceDefault.StreamsInbound = rcmgr.LimitVal(
			1 << bits.Len(12*maxconns),
		)
		changes.ServiceDefault.StreamsOutbound = rcmgr.LimitVal(
			1 << bits.Len(48*maxconns),
		)
		changes.ServiceDefault.Streams = rcmgr.LimitVal(1 << bits.Len(48*maxconns))
		changes.ProtocolDefault.StreamsInbound = rcmgr.LimitVal(
			1 << bits.Len(12*maxconns),
		)
		changes.ProtocolDefault.StreamsOutbound = rcmgr.LimitVal(
			1 << bits.Len(48*maxconns),
		)
		changes.ProtocolDefault.Streams = rcmgr.LimitVal(1 << bits.Len(48*maxconns))
	}

	changedLimitConfig := changes.Build(defaultLimitConfig)

	limiter := rcmgr.NewFixedLimiter(changedLimitConfig)

	str, err := rcmgr.NewStatsTraceReporter()
	if err != nil {
		return nil, errors.Wrap(err, "resource manager")
	}

	rcmgr.MustRegisterWith(prometheus.DefaultRegisterer)

	// Metrics
	opts := append(
		[]rcmgr.Option{},
		rcmgr.WithTraceReporter(str),
	)

	resolver := madns.DefaultResolver
	var allowedMaddrs []ma.Multiaddr
	for _, pi := range allowed {
		for _, addr := range pi.Addrs {
			resolved, err := resolver.Resolve(context.Background(), addr)
			if err != nil {
				continue
			}
			allowedMaddrs = append(allowedMaddrs, resolved...)
		}
	}

	opts = append(opts, rcmgr.WithAllowlistedMultiaddrs(allowedMaddrs))

	mgr, err := rcmgr.NewResourceManager(limiter, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "resource manager")
	}

	return mgr, nil
}

func (b *BlossomSub) background(ctx context.Context) {
	refreshScores := time.NewTicker(DecayInterval)
	defer refreshScores.Stop()

	for {
		select {
		case <-refreshScores.C:
			b.refreshScores()
		case <-ctx.Done():
			return
		}
	}
}

func (b *BlossomSub) refreshScores() {
	b.peerScoreMx.Lock()

	now := time.Now()
	for p, pstats := range b.peerScore {
		if now.After(pstats.expire) {
			delete(b.peerScore, p)
			continue
		}

		pstats.score *= AppDecay
		if math.Abs(pstats.score) < .1 {
			pstats.score = 0
		}
	}

	b.peerScoreMx.Unlock()
}

func (b *BlossomSub) PublishToBitmask(bitmask []byte, data []byte) error {
	return b.ps.Publish(b.ctx, bitmask, data)
}

func (b *BlossomSub) Publish(address []byte, data []byte) error {
	bitmask := GetBloomFilter(address, 256, 3)
	return b.PublishToBitmask(bitmask, data)
}

func (b *BlossomSub) Subscribe(
	bitmask []byte,
	handler func(message *pb.Message) error,
) error {
	b.logger.Info("joining broadcast")
	bm, err := b.ps.Join(bitmask)
	if err != nil {
		b.logger.Error("join failed", zap.Error(err))
		return errors.Wrap(err, "subscribe")
	}

	b.logger.Info("subscribe to bitmask", zap.Binary("bitmask", bitmask))
	subs := []*blossomsub.Subscription{}
	for _, bit := range bm {
		sub, err := bit.Subscribe(blossomsub.WithBufferSize(b.p2pConfig.SubscriptionQueueSize))
		if err != nil {
			b.logger.Error("subscription failed", zap.Error(err))
			return errors.Wrap(err, "subscribe")
		}
		_, ok := b.bitmaskMap[string(bit.Bitmask())]
		if !ok {
			b.bitmaskMap[string(bit.Bitmask())] = bit
		}
		subs = append(subs, sub)
	}

	b.logger.Info(
		"begin streaming from bitmask",
		zap.Binary("bitmask", bitmask),
	)

	for _, sub := range subs {
		copiedBitmask := make([]byte, len(bitmask))
		copy(copiedBitmask[:], bitmask[:])
		sub := sub

		go func() {
			for {
				m, err := sub.Next(b.ctx)
				if err != nil {
					b.logger.Error(
						"got error when fetching the next message",
						zap.Error(err),
					)
				}
				if bytes.Equal(m.Bitmask, copiedBitmask) {
					if err = handler(m.Message); err != nil {
						b.logger.Debug("message handler returned error", zap.Error(err))
					}
				}
			}
		}()
	}

	return nil
}

func (b *BlossomSub) Unsubscribe(bitmask []byte, raw bool) {
	// TODO: Fix this, it is broken - the bitmask parameter is not sliced, and the
	// network is not pre-pended to the bitmask.
	networkBitmask := append([]byte{b.p2pConfig.Network}, bitmask...)
	bm, ok := b.bitmaskMap[string(networkBitmask)]
	if !ok {
		return
	}

	bm.Close()
}

func (b *BlossomSub) RegisterValidator(
	bitmask []byte, validator func(peerID peer.ID, message *pb.Message) ValidationResult, sync bool,
) error {
	validatorEx := func(
		ctx context.Context, peerID peer.ID, message *blossomsub.Message,
	) blossomsub.ValidationResult {
		switch v := validator(peerID, message.Message); v {
		case ValidationResultAccept:
			return blossomsub.ValidationAccept
		case ValidationResultReject:
			return blossomsub.ValidationReject
		case ValidationResultIgnore:
			return blossomsub.ValidationIgnore
		default:
			panic("unreachable")
		}
	}
	var _ blossomsub.ValidatorEx = validatorEx
	return b.ps.RegisterBitmaskValidator(bitmask, validatorEx, blossomsub.WithValidatorInline(sync))
}

func (b *BlossomSub) UnregisterValidator(bitmask []byte) error {
	return b.ps.UnregisterBitmaskValidator(bitmask)
}

func (b *BlossomSub) GetPeerID() []byte {
	return []byte(b.peerID)
}

func (b *BlossomSub) GetRandomPeer(bitmask []byte) ([]byte, error) {
	peers := b.ps.ListPeers(bitmask)
	if len(peers) == 0 {
		return nil, errors.Wrap(
			ErrNoPeersAvailable,
			"get random peer",
		)
	}
	b.logger.Debug("selecting from peers", zap.Any("peer_ids", peers))
	sel, err := rand.Int(rand.Reader, big.NewInt(int64(len(peers))))
	if err != nil {
		return nil, errors.Wrap(err, "get random peer")
	}

	return []byte(peers[sel.Int64()]), nil
}

func (b *BlossomSub) IsPeerConnected(peerId []byte) bool {
	peerID := peer.ID(peerId)
	connectedness := b.h.Network().Connectedness(peerID)
	return connectedness == network.Connected || connectedness == network.Limited
}

func (b *BlossomSub) Reachability() *wrapperspb.BoolValue {
	reachability := b.reachability.Load()
	if reachability == nil {
		return nil
	}
	switch *reachability {
	case network.ReachabilityPublic:
		return wrapperspb.Bool(true)
	case network.ReachabilityPrivate:
		return wrapperspb.Bool(false)
	default:
		return nil
	}
}

func initDHT(
	ctx context.Context,
	logger *zap.Logger,
	h host.Host,
	isBootstrapPeer bool,
	bootstrappers []peer.AddrInfo,
	network uint8,
) *dht.IpfsDHT {
	logger.Info("establishing dht")
	var mode dht.ModeOpt
	if isBootstrapPeer || network != 0 {
		mode = dht.ModeServer
	} else {
		mode = dht.ModeClient
	}
	opts := []dht.Option{
		dht.Mode(mode),
		dht.BootstrapPeers(bootstrappers...),
	}
	if network != 0 {
		opts = append(opts, dht.ProtocolPrefix(protocol.ID("/testnet")))
	}
	kademliaDHT, err := dht.New(
		ctx,
		h,
		opts...,
	)
	if err != nil {
		logger.Panic("error creating dht", zap.Error(err))
	}
	if err := kademliaDHT.Bootstrap(ctx); err != nil {
		logger.Panic("error bootstrapping dht", zap.Error(err))
	}
	return kademliaDHT
}

func (b *BlossomSub) Reconnect(peerId []byte) error {
	peer := peer.ID(peerId)
	info := b.h.Peerstore().PeerInfo(peer)
	b.h.ConnManager().Unprotect(info.ID, "bootstrap")
	time.Sleep(10 * time.Second)
	if err := b.h.Connect(b.ctx, info); err != nil {
		return errors.Wrap(err, "reconnect")
	}

	b.h.ConnManager().Protect(info.ID, "bootstrap")
	return nil
}

func (b *BlossomSub) Bootstrap(ctx context.Context) error {
	return b.bootstrap.Connect(ctx)
}

func (b *BlossomSub) DiscoverPeers(ctx context.Context) error {
	return b.discovery.Connect(ctx)
}

func (b *BlossomSub) GetPeerScore(peerId []byte) int64 {
	b.peerScoreMx.Lock()
	peerScore, ok := b.peerScore[string(peerId)]
	if !ok {
		b.peerScoreMx.Unlock()
		return 0
	}
	score := peerScore.score
	b.peerScoreMx.Unlock()
	return int64(score)
}

func (b *BlossomSub) SetPeerScore(peerId []byte, score int64) {
	b.peerScoreMx.Lock()
	b.peerScore[string(peerId)] = &appScore{
		score:  float64(score),
		expire: time.Now().Add(1 * time.Hour),
	}
	b.peerScoreMx.Unlock()
}

func (b *BlossomSub) AddPeerScore(peerId []byte, scoreDelta int64) {
	b.peerScoreMx.Lock()
	if _, ok := b.peerScore[string(peerId)]; !ok {
		b.peerScore[string(peerId)] = &appScore{
			score:  float64(scoreDelta),
			expire: time.Now().Add(1 * time.Hour),
		}
	} else {
		b.peerScore[string(peerId)] = &appScore{
			score:  b.peerScore[string(peerId)].score + float64(scoreDelta),
			expire: time.Now().Add(1 * time.Hour),
		}
	}
	b.peerScoreMx.Unlock()
}

func (b *BlossomSub) GetBitmaskPeers() map[string][]string {
	peers := map[string][]string{}

	// TODO: Fix this, it is broken - the bitmask parameter is not sliced, and the
	// network is not pre-pended to the bitmask.
	for _, k := range b.bitmaskMap {
		peers[fmt.Sprintf("%+x", k.Bitmask()[1:])] = []string{}

		for _, p := range k.ListPeers() {
			peers[fmt.Sprintf("%+x", k.Bitmask()[1:])] = append(
				peers[fmt.Sprintf("%+x", k.Bitmask()[1:])],
				p.String(),
			)
		}
	}

	return peers
}

func (b *BlossomSub) GetPeerstoreCount() int {
	return len(b.h.Peerstore().Peers())
}

func (b *BlossomSub) GetNetworkInfo() *protobufs.NetworkInfoResponse {
	resp := &protobufs.NetworkInfoResponse{}
	for _, p := range b.h.Network().Peers() {
		addrs := b.h.Peerstore().Addrs(p)
		multiaddrs := []string{}
		for _, a := range addrs {
			multiaddrs = append(multiaddrs, a.String())
		}
		resp.NetworkInfo = append(resp.NetworkInfo, &protobufs.NetworkInfo{
			PeerId:     []byte(p),
			Multiaddrs: multiaddrs,
			PeerScore:  b.ps.PeerScore(p),
		})
	}
	return resp
}

func (b *BlossomSub) GetNetworkPeersCount() int {
	return len(b.h.Network().Peers())
}

func (b *BlossomSub) GetMultiaddrOfPeerStream(
	ctx context.Context,
	peerId []byte,
) <-chan ma.Multiaddr {
	return b.h.Peerstore().AddrStream(ctx, peer.ID(peerId))
}

func (b *BlossomSub) GetMultiaddrOfPeer(peerId []byte) string {
	addrs := b.h.Peerstore().Addrs(peer.ID(peerId))
	if len(addrs) == 0 {
		return ""
	}

	return addrs[0].String()
}

func (b *BlossomSub) GetNetwork() uint {
	return uint(b.p2pConfig.Network)
}

func (b *BlossomSub) StartDirectChannelListener(
	key []byte,
	purpose string,
	server *grpc.Server,
) error {
	bind, err := gostream.Listen(
		b.h,
		protocol.ID(
			"/p2p/direct-channel/"+base58.Encode(key)+purpose,
		),
	)
	if err != nil {
		return errors.Wrap(err, "start direct channel listener")
	}

	return errors.Wrap(server.Serve(bind), "start direct channel listener")
}

type extraCloseConn struct {
	net.Conn
	extraClose func()
}

func (c *extraCloseConn) Close() error {
	err := c.Conn.Close()
	c.extraClose()
	return err
}

func (b *BlossomSub) GetDirectChannel(ctx context.Context, peerID []byte, purpose string) (
	cc *grpc.ClientConn, err error,
) {
	// Kind of a weird hack, but gostream can induce panics if the peer drops at
	// the time of connection, this avoids the problem.
	defer func() {
		if r := recover(); r != nil {
			cc = nil
			err = errors.New("connection failed")
		}
	}()

	id := peer.ID(peerID)

	// Open question: should we prefix this so a node can run both in mainnet and
	// testnet? Feels like a bad idea and would be preferable to discourage.
	cc, err = qgrpc.DialContext(
		ctx,
		"passthrough:///",
		grpc.WithContextDialer(
			func(ctx context.Context, _ string) (net.Conn, error) {
				// If we are not already connected to the peer, we will manually dial it
				// before opening the direct channel. We will close the peer connection
				// when the direct channel is closed.
				alreadyConnected := false
				switch connectedness := b.h.Network().Connectedness(id); connectedness {
				case network.Connected, network.Limited:
					alreadyConnected = true
				default:
					if err := b.h.Connect(ctx, peer.AddrInfo{ID: id}); err != nil {
						return nil, errors.Wrap(err, "connect")
					}
				}
				c, err := gostream.Dial(
					network.WithNoDial(ctx, "direct-channel"),
					b.h,
					id,
					protocol.ID(
						"/p2p/direct-channel/"+id.String()+purpose,
					),
				)
				if err != nil {
					return nil, errors.Wrap(err, "dial direct channel")
				}
				if alreadyConnected {
					return c, nil
				}
				return &extraCloseConn{
					Conn:       c,
					extraClose: func() { _ = b.h.Network().ClosePeer(id) },
				}, nil
			},
		),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, errors.Wrap(err, "dial context")
	}

	return cc, nil
}

func (b *BlossomSub) GetPublicKey() []byte {
	pub, _ := b.signKey.GetPublic().Raw()
	return pub
}

func (b *BlossomSub) SignMessage(msg []byte) ([]byte, error) {
	sig, err := b.signKey.Sign(msg)
	return sig, errors.Wrap(err, "sign message")
}

func toBlossomSubParams(p2pConfig *config.P2PConfig) blossomsub.BlossomSubParams {
	return blossomsub.BlossomSubParams{
		D:                         p2pConfig.D,
		Dlo:                       p2pConfig.DLo,
		Dhi:                       p2pConfig.DHi,
		Dscore:                    p2pConfig.DScore,
		Dout:                      p2pConfig.DOut,
		HistoryLength:             p2pConfig.HistoryLength,
		HistoryGossip:             p2pConfig.HistoryGossip,
		Dlazy:                     p2pConfig.DLazy,
		GossipFactor:              p2pConfig.GossipFactor,
		GossipRetransmission:      p2pConfig.GossipRetransmission,
		HeartbeatInitialDelay:     p2pConfig.HeartbeatInitialDelay,
		HeartbeatInterval:         p2pConfig.HeartbeatInterval,
		FanoutTTL:                 p2pConfig.FanoutTTL,
		PrunePeers:                p2pConfig.PrunePeers,
		PruneBackoff:              p2pConfig.PruneBackoff,
		UnsubscribeBackoff:        p2pConfig.UnsubscribeBackoff,
		Connectors:                p2pConfig.Connectors,
		MaxPendingConnections:     p2pConfig.MaxPendingConnections,
		ConnectionTimeout:         p2pConfig.ConnectionTimeout,
		DirectConnectTicks:        p2pConfig.DirectConnectTicks,
		DirectConnectInitialDelay: p2pConfig.DirectConnectInitialDelay,
		OpportunisticGraftTicks:   p2pConfig.OpportunisticGraftTicks,
		OpportunisticGraftPeers:   p2pConfig.OpportunisticGraftPeers,
		GraftFloodThreshold:       p2pConfig.GraftFloodThreshold,
		MaxIHaveLength:            p2pConfig.MaxIHaveLength,
		MaxIHaveMessages:          p2pConfig.MaxIHaveMessages,
		MaxIDontWantMessages:      p2pConfig.MaxIDontWantMessages,
		IWantFollowupTime:         p2pConfig.IWantFollowupTime,
		IDontWantMessageThreshold: p2pConfig.IDontWantMessageThreshold,
		IDontWantMessageTTL:       p2pConfig.IDontWantMessageTTL,
		SlowHeartbeatWarning:      0.1,
	}
}

func getNetworkNamespace(network uint8) string {
	var network_name string
	switch network {
	case 0:
		network_name = "mainnet"
	case 1:
		network_name = "testnet-primary"
	default:
		network_name = fmt.Sprintf("network-%d", network)
	}

	return ANNOUNCE_PREFIX + network_name
}
