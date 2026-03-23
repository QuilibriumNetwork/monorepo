package p2p

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/bits"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	libp2pconfig "github.com/libp2p/go-libp2p/config"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/discovery/util"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	routedhost "github.com/libp2p/go-libp2p/p2p/host/routed"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/libp2p/go-libp2p/p2p/net/gostream"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	"github.com/mr-tron/base58"
	ma "github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpcpeer "google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"source.quilibrium.com/quilibrium/monorepo/config"
	blossomsub "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/internal/observability"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p/internal"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	"source.quilibrium.com/quilibrium/monorepo/types/p2p"
	up2p "source.quilibrium.com/quilibrium/monorepo/utils/p2p"
)

const (
	DecayInterval = 10 * time.Minute
	AppDecay      = .9
)

// ConfigDir is a distinct type for the configuration directory path
// Used by Wire for dependency injection
type ConfigDir string

type appScore struct {
	expire time.Time
	score  float64
}

type BlossomSub struct {
	ps            *blossomsub.PubSub
	ctx           context.Context
	cancel        context.CancelFunc
	logger        *zap.Logger
	peerID        peer.ID
	derivedPeerID peer.ID
	bitmaskMap    map[string]*blossomsub.Bitmask
	// Track which bit slices belong to which original bitmasks, used to reference
	// count bitmasks for closed subscriptions
	subscriptionTracker map[string][][]byte
	// Track subscriptions per bitmask key so Unsubscribe can cancel them
	// before closing the bitmask (blossomsub refuses to close a bitmask
	// with open subscriptions).
	subscriptionsByBitmask map[string][]*blossomsub.Subscription
	subscriptionMutex      sync.RWMutex
	h                      host.Host
	signKey                crypto.PrivKey
	peerScore              map[string]*appScore
	peerScoreMx            sync.Mutex
	bootstrap              internal.PeerConnector
	discovery              internal.PeerConnector
	manualReachability     atomic.Pointer[bool]
	p2pConfig              config.P2PConfig
	bootstrapPeerIDs       map[peer.ID]struct{}
	dht                    *dht.IpfsDHT
	routingDiscovery       *routing.RoutingDiscovery
	reconnectFailures      int
	coreId                 uint
	configDir              ConfigDir
}

var _ p2p.PubSub = (*BlossomSub)(nil)
var ErrNoPeersAvailable = errors.New("no peers available")

var ANNOUNCE_PREFIX = "quilibrium-2.0.2-dusk-"
var connectivityServiceProtocolID = protocol.ID("/quilibrium/connectivity/1.0.0")

func getPeerID(p2pConfig *config.P2PConfig) peer.ID {
	peerPrivKey, err := hex.DecodeString(p2pConfig.PeerPrivKey)
	if err != nil {
		log.Panic("error unmarshaling peerkey", zap.Error(err))
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		log.Panic("error unmarshaling peerkey", zap.Error(err))
	}

	pub := privKey.GetPublic()
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		log.Panic("error getting peer id", zap.Error(err))
	}

	return id
}

// NewBlossomSubWithHost creates a new blossomsub instance with a pre-defined
// host. This method is intended for integration tests that need something
// more realistic for pubsub purposes, with a supplied simulator (see
// node/tests/simnet.go for utility methods to construct a flaky host)
func NewBlossomSubWithHost(
	p2pConfig *config.P2PConfig,
	engineConfig *config.EngineConfig,
	logger *zap.Logger,
	coreId uint,
	isBootstrapPeer bool,
	host host.Host,
	privKey crypto.PrivKey,
	bootstrapHosts []host.Host,
) *BlossomSub {
	ctx, cancel := context.WithCancel(context.Background())
	if coreId == 0 {
		logger = logger.With(zap.String("process", "master"))
	} else {
		logger = logger.With(zap.String(
			"process",
			fmt.Sprintf("worker %d", coreId),
		))
	}

	bs := &BlossomSub{
		ctx:                    ctx,
		cancel:                 cancel,
		logger:                 logger,
		bitmaskMap:             make(map[string]*blossomsub.Bitmask),
		subscriptionTracker:    make(map[string][][]byte),
		subscriptionsByBitmask: make(map[string][]*blossomsub.Subscription),
		signKey:                privKey,
		peerScore:              make(map[string]*appScore),
		p2pConfig:              *p2pConfig,
		bootstrapPeerIDs:       make(map[peer.ID]struct{}),
		coreId:                 coreId,
	}

	idService := internal.IDServiceFromHost(host)

	logger.Info("established peer id", zap.String("peer_id", host.ID().String()))

	bootstrappers := []peer.AddrInfo{}
	for _, bh := range bootstrapHosts {
		// manually construct the p2p string, kind of kludgy, but this is intended
		// for use with tests
		ai, err := peer.AddrInfoFromString(
			bh.Addrs()[0].String() + "/p2p/" + bh.ID().String(),
		)
		if err != nil {
			panic(fmt.Sprintf("error for addr %v, %+v:", bh.Addrs()[0], err))
		}
		bootstrappers = append(bootstrappers, *ai)
	}
	for _, b := range bootstrappers {
		bs.bootstrapPeerIDs[b.ID] = struct{}{}
	}
	kademliaDHT := initDHT(
		ctx,
		logger,
		host,
		isBootstrapPeer,
		bootstrappers,
		p2pConfig.Network,
	)
	host = routedhost.Wrap(host, kademliaDHT)

	routingDiscovery := routing.NewRoutingDiscovery(kademliaDHT)
	util.Advertise(ctx, routingDiscovery, getNetworkNamespace(p2pConfig.Network))

	minBootstrapPeers := min(len(bootstrappers), p2pConfig.MinBootstrapPeers)
	bootstrap := internal.NewPeerConnector(
		ctx,
		zap.NewNop(),
		host,
		idService,
		minBootstrapPeers,
		p2pConfig.BootstrapParallelism,
		internal.NewStaticPeerSource(bootstrappers, true),
	)
	if err := bootstrap.Connect(ctx); err != nil {
		logger.Panic("error connecting to bootstrap peers", zap.Error(err))
	}
	bs.bootstrap = bootstrap

	discovery := internal.NewPeerConnector(
		ctx,
		zap.NewNop(),
		host,
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
		logger.Named("peerMonitor"),
		host,
		p2pConfig.PingTimeout,
		p2pConfig.PingPeriod,
		p2pConfig.PingAttempts,
		nil,
	)

	var tracer *blossomsub.JSONTracer
	var err error
	if p2pConfig.TraceLogStdout {
		tracer, err = blossomsub.NewStdoutJSONTracer()
		if err != nil {
			panic(errors.Wrap(err, "error building stdout tracer"))
		}
	} else if p2pConfig.TraceLogFile != "" {
		tracer, err = blossomsub.NewJSONTracer(p2pConfig.TraceLogFile)
		if err != nil {
			logger.Panic("error building file tracer", zap.Error(err))
		}
	}

	blossomOpts := []blossomsub.Option{
		blossomsub.WithStrictSignatureVerification(true),
		blossomsub.WithValidateQueueSize(blossomsub.DefaultValidateQueueSize),
		blossomsub.WithValidateWorkers(1),
		blossomsub.WithPeerOutboundQueueSize(
			blossomsub.DefaultPeerOutboundQueueSize,
		),
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
			GossipThreshold:             -500,
			PublishThreshold:            -1000,
			GraylistThreshold:           -2500,
			AcceptPXThreshold:           1000,
			OpportunisticGraftThreshold: 3.5,
		},
	))
	blossomOpts = append(blossomOpts, observability.WithPrometheusRawTracer())
	if p2pConfig.Network == 0 {
		logger.Info("enabling blacklist for bootstrappers for blossomsub")
		blossomOpts = append(blossomOpts, blossomsub.WithPeerFilter(
			internal.NewStaticPeerFilter(
				[]peer.ID{},
				internal.PeerAddrInfosToPeerIDSlice(bootstrappers),
				true,
			),
		))
	}
	blossomOpts = append(blossomOpts, blossomsub.WithDiscovery(
		internal.NewPeerConnectorDiscovery(discovery),
	))
	blossomOpts = append(blossomOpts, blossomsub.WithMessageIdFn(
		func(pmsg *pb.Message) []byte {
			id := sha256.Sum256(pmsg.Data)
			return id[:]
		}),
	)

	params := toBlossomSubParams(p2pConfig)
	rt := blossomsub.NewBlossomSubRouter(host, params, bs.p2pConfig.Network)
	blossomOpts = append(blossomOpts, rt.WithDefaultTagTracer())
	pubsub, err := blossomsub.NewBlossomSubWithRouter(ctx, host, rt, blossomOpts...)
	if err != nil {
		logger.Panic("error creating pubsub", zap.Error(err))
	}

	peerID := host.ID()
	bs.dht = kademliaDHT
	bs.routingDiscovery = routingDiscovery
	bs.ps = pubsub
	bs.peerID = peerID
	bs.h = host
	bs.signKey = privKey
	bs.derivedPeerID = peerID

	go bs.background(ctx)

	bs.initConnectivityServices(isBootstrapPeer, bootstrappers)

	return bs
}

func NewBlossomSub(
	p2pConfig *config.P2PConfig,
	engineConfig *config.EngineConfig,
	logger *zap.Logger,
	coreId uint,
	configDir ConfigDir,
) *BlossomSub {
	ctx := context.Background()

	// Determine the appropriate listen address based on coreId
	var listenAddr string
	if coreId == 0 {
		logger = logger.With(zap.String("process", "master"))
		// For main node (coreId == 0), use the standard p2pConfig.ListenMultiaddr
		listenAddr = p2pConfig.ListenMultiaddr
	} else {
		logger = logger.With(zap.String(
			"process",
			fmt.Sprintf("worker %d", coreId),
		))

		// For data workers (coreId > 0), check if DataWorkerP2PMultiaddrs is
		// provided
		if engineConfig != nil && len(engineConfig.DataWorkerP2PMultiaddrs) > 0 &&
			int(coreId-1) < len(engineConfig.DataWorkerP2PMultiaddrs) {
			listenAddr = engineConfig.DataWorkerP2PMultiaddrs[coreId-1]
			logger.Info(
				"Using configured data worker P2P multiaddr",
				zap.String("multiaddr", listenAddr),
				zap.Uint("core_id", coreId),
			)
		} else if engineConfig != nil && engineConfig.DataWorkerBaseP2PPort > 0 {
			port := engineConfig.DataWorkerBaseP2PPort + uint16(coreId-1)

			listenAddr = fmt.Sprintf(engineConfig.DataWorkerBaseListenMultiaddr, port)
			logger.Info(
				"worker p2p listen address calculated",
				zap.String("multiaddr", listenAddr),
				zap.Uint("core_id", coreId),
				zap.Uint16("port", port),
			)
		} else {
			logger.Error(
				"no data worker configuration found",
				zap.Uint("core_id", coreId),
			)
			time.Sleep(120 * time.Second)
			panic("no data worker configuration found")
		}
	}

	opts := []libp2pconfig.Option{
		libp2p.ListenAddrStrings(listenAddr),
		libp2p.EnableNATService(),
		libp2p.NATPortMap(),
	}

	isBootstrapPeer := false

	if coreId == 0 {
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
	var derivedPeerId peer.ID
	if p2pConfig.PeerPrivKey != "" {
		peerPrivKey, err := hex.DecodeString(p2pConfig.PeerPrivKey)
		if err != nil {
			logger.Panic("error unmarshaling peerkey", zap.Error(err))
		}

		privKey, err = crypto.UnmarshalEd448PrivateKey(peerPrivKey)
		if err != nil {
			logger.Panic("error unmarshaling peerkey", zap.Error(err))
		}

		derivedPeerId, err = peer.IDFromPrivateKey(privKey)
		if err != nil {
			logger.Panic("error deriving peer id", zap.Error(err))
		}

		if coreId == 0 {
			opts = append(opts, libp2p.Identity(privKey))
		} else {
			// Derive a deterministic worker key from the peer key + core ID.
			// This gives each worker a stable, unique peer ID across restarts
			// (avoiding sybil detection) while still using the original peer
			// key for message signing.
			rawPriv, err := privKey.Raw()
			if err != nil {
				logger.Panic("error getting private key bytes", zap.Error(err))
			}
			shake := sha3.NewShake256()
			shake.Write(rawPriv)
			shake.Write([]byte(fmt.Sprintf("/worker/%d", coreId)))
			seed := make([]byte, 64)
			if _, err := shake.Read(seed); err != nil {
				logger.Panic("error deriving worker key seed", zap.Error(err))
			}
			workerKey, _, err := crypto.GenerateEd448Key(
				bytes.NewReader(seed),
			)
			if err != nil {
				logger.Panic("error generating worker peerkey", zap.Error(err))
			}

			opts = append(opts, libp2p.Identity(workerKey))
		}
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
			logger.Info(
				"adding direct peer",
				zap.String("peer", peerinfo.ID.String()),
			)
			directPeers = append(directPeers, *peerinfo)
		}
	}
	allowedPeers = append(allowedPeers, directPeers...)

	opts = append(
		opts,
		libp2p.SwarmOpts(),
	)

	if p2pConfig.LowWatermarkConnections != -1 &&
		p2pConfig.HighWatermarkConnections != -1 {
		cm, err := connmgr.NewConnManager(
			p2pConfig.LowWatermarkConnections,
			p2pConfig.HighWatermarkConnections,
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

		opts = append(opts, libp2p.ConnectionManager(cm))
		opts = append(opts, libp2p.ResourceManager(rm))
	}

	ctx, cancel := context.WithCancel(ctx)
	bootstrapPeerIDs := make(map[peer.ID]struct{}, len(bootstrappers))
	for _, b := range bootstrappers {
		bootstrapPeerIDs[b.ID] = struct{}{}
	}

	bs := &BlossomSub{
		ctx:                    ctx,
		cancel:                 cancel,
		logger:                 logger,
		bitmaskMap:             make(map[string]*blossomsub.Bitmask),
		subscriptionTracker:    make(map[string][][]byte),
		subscriptionsByBitmask: make(map[string][]*blossomsub.Subscription),
		signKey:                privKey,
		peerScore:              make(map[string]*appScore),
		p2pConfig:              *p2pConfig,
		bootstrapPeerIDs:       bootstrapPeerIDs,
		derivedPeerID:          derivedPeerId,
		coreId:                 coreId,
		configDir:              configDir,
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		logger.Panic("error constructing p2p", zap.Error(err))
	}
	idService := internal.IDServiceFromHost(h)

	logger.Info("established peer id", zap.String("peer_id", h.ID().String()))

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
		logger.Named("peerMonitor"),
		h,
		p2pConfig.PingTimeout,
		p2pConfig.PingPeriod,
		p2pConfig.PingAttempts,
		directPeers,
	)

	var tracer *blossomsub.JSONTracer
	if p2pConfig.TraceLogStdout {
		tracer, err = blossomsub.NewStdoutJSONTracer()
		if err != nil {
			panic(errors.Wrap(err, "error building stdout tracer"))
		}
	} else if p2pConfig.TraceLogFile != "" {
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

	GLOBAL_CONSENSUS_BITMASK := []byte{0x00}
	GLOBAL_FRAME_BITMASK := []byte{0x00, 0x00}
	GLOBAL_PROVER_BITMASK := []byte{0x00, 0x00, 0x00}
	GLOBAL_PEER_INFO_BITMASK := []byte{0x00, 0x00, 0x00, 0x00}
	GLOBAL_ALERT_BITMASK := bytes.Repeat([]byte{0x00}, 16)
	sets := getBitmaskSets(bytes.Repeat([]byte{0xff}, 32))
	sets = slices.Concat([][]byte{
		GLOBAL_CONSENSUS_BITMASK,
		GLOBAL_FRAME_BITMASK,
		GLOBAL_PROVER_BITMASK,
		GLOBAL_PEER_INFO_BITMASK,
		GLOBAL_ALERT_BITMASK,
	}, sets)
	bitmasksScoring := map[string]*blossomsub.BitmaskScoreParams{}
	for _, set := range sets {
		bitmasksScoring[string(set)] = &blossomsub.BitmaskScoreParams{
			SkipAtomicValidation:         false,
			BitmaskWeight:                0.1,
			TimeInMeshWeight:             0.00027,
			TimeInMeshQuantum:            time.Second,
			TimeInMeshCap:                1,
			FirstMessageDeliveriesWeight: 5,
			FirstMessageDeliveriesDecay: blossomsub.ScoreParameterDecay(
				10 * time.Minute,
			),
			FirstMessageDeliveriesCap:      10000,
			InvalidMessageDeliveriesWeight: -1000,
			InvalidMessageDeliveriesDecay:  blossomsub.ScoreParameterDecay(time.Hour),
		}
	}

	if p2pConfig.Network != 0 {
		blossomOpts = append(blossomOpts, blossomsub.WithPeerScore(
			&blossomsub.PeerScoreParams{
				SkipAtomicValidation:        false,
				Bitmasks:                    bitmasksScoring,
				BitmaskScoreCap:             0,
				IPColocationFactorWeight:    0,
				IPColocationFactorThreshold: 6,
				BehaviourPenaltyWeight:      -10,
				BehaviourPenaltyThreshold:   6,
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
				GossipThreshold:             -500,
				PublishThreshold:            -1000,
				GraylistThreshold:           -2500,
				AcceptPXThreshold:           1000,
				OpportunisticGraftThreshold: 3.5,
			},
		))

	} else {
		whitelist := []*net.IPNet{}
		for _, p := range directPeers {
			for _, i := range p.Addrs {
				ipnet, err := MultiaddrToIPNet(i)
				if err != nil {
					logger.Error(
						"could not convert direct peer for ip colocation whitelist",
						zap.String("peer_addr", i.String()),
						zap.Error(err),
					)
				}
				whitelist = append(whitelist, ipnet)
			}
		}
		blossomOpts = append(blossomOpts, blossomsub.WithPeerScore(
			&blossomsub.PeerScoreParams{
				SkipAtomicValidation:        false,
				Bitmasks:                    bitmasksScoring,
				BitmaskScoreCap:             0,
				IPColocationFactorWeight:    -100,
				IPColocationFactorThreshold: 6,
				IPColocationFactorWhitelist: whitelist,
				BehaviourPenaltyWeight:      -10,
				BehaviourPenaltyThreshold:   6,
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
				GossipThreshold:             -500,
				PublishThreshold:            -1000,
				GraylistThreshold:           -2500,
				AcceptPXThreshold:           1000,
				OpportunisticGraftThreshold: 3.5,
			},
		))
	}
	blossomOpts = append(blossomOpts,
		blossomsub.WithValidateQueueSize(p2pConfig.ValidateQueueSize),
		blossomsub.WithValidateWorkers(p2pConfig.ValidateWorkers),
		blossomsub.WithPeerOutboundQueueSize(p2pConfig.PeerOutboundQueueSize),
	)
	blossomOpts = append(blossomOpts, observability.WithPrometheusRawTracer())
	if p2pConfig.Network == 0 {
		logger.Info("enabling blacklist for bootstrappers for blossomsub")
		blossomOpts = append(blossomOpts, blossomsub.WithPeerFilter(
			internal.NewStaticPeerFilter(
				[]peer.ID{},
				internal.PeerAddrInfosToPeerIDSlice(bootstrappers),
				true,
			),
		))
	}
	blossomOpts = append(blossomOpts, blossomsub.WithDiscovery(
		internal.NewPeerConnectorDiscovery(discovery),
	))
	blossomOpts = append(blossomOpts, blossomsub.WithMessageIdFn(
		func(pmsg *pb.Message) []byte {
			id := sha256.Sum256(pmsg.Data)
			return id[:]
		}),
	)

	params := toBlossomSubParams(p2pConfig)
	rt := blossomsub.NewBlossomSubRouter(h, params, bs.p2pConfig.Network)
	blossomOpts = append(blossomOpts, rt.WithDefaultTagTracer())
	pubsub, err := blossomsub.NewBlossomSubWithRouter(ctx, h, rt, blossomOpts...)
	if err != nil {
		logger.Panic("error creating pubsub", zap.Error(err))
	}

	peerID := h.ID()
	bs.dht = kademliaDHT
	bs.routingDiscovery = routingDiscovery
	bs.ps = pubsub
	bs.peerID = peerID
	bs.h = h
	bs.signKey = privKey
	bs.initConnectivityServices(isBootstrapPeer, bootstrappers)

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
	// Run an immediate check so recovery doesn't wait for the first tick.
	b.checkAndReconnectPeers(ctx)

	refreshScores := time.NewTicker(DecayInterval)
	defer refreshScores.Stop()

	peerReconnectInterval := b.p2pConfig.PeerReconnectCheckInterval
	peerReconnect := time.NewTicker(peerReconnectInterval)
	defer peerReconnect.Stop()

	for {
		select {
		case <-refreshScores.C:
			b.refreshScores()
		case <-peerReconnect.C:
			b.checkAndReconnectPeers(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (b *BlossomSub) nonBootstrapPeerCount() int {
	count := 0
	for _, p := range b.h.Network().Peers() {
		if _, isBootstrap := b.bootstrapPeerIDs[p]; !isBootstrap {
			count++
		}
	}
	return count
}

func (b *BlossomSub) checkAndReconnectPeers(ctx context.Context) {
	peerCount := b.nonBootstrapPeerCount()
	if peerCount >= b.p2pConfig.MinBootstrapPeers {
		// Healthy peer count — reset consecutive failure counter so the
		// next drop starts with a soft recovery.
		b.reconnectFailures = 0
		return
	}

	b.logger.Warn(
		"low peer count, attempting recovery",
		zap.Int("current_peers", peerCount),
		zap.Int("min_peers", b.p2pConfig.MinBootstrapPeers),
		zap.Int("consecutive_failures", b.reconnectFailures),
	)

	// Re-bootstrap the DHT to refresh the routing table. At startup,
	// kademliaDHT.Bootstrap() populates the routing table by connecting to
	// bootstrap peers. Without calling it again here, the routing table can
	// go empty after all peers disconnect, making FindPeers unable to
	// discover anyone — leaving the node permanently stuck.
	if b.dht != nil {
		if err := b.dht.Bootstrap(ctx); err != nil {
			b.logger.Error("DHT re-bootstrap failed", zap.Error(err))
		}
	}

	// Re-advertise so other peers can find us through the DHT.
	if b.routingDiscovery != nil {
		util.Advertise(
			ctx,
			b.routingDiscovery,
			getNetworkNamespace(b.p2pConfig.Network),
		)
	}

	// Only clear stale peerstore addresses after several consecutive failed
	// recovery attempts.  On transient connectivity blips (common on
	// residential ISPs) the addresses are still valid and wiping them forces
	// a full DHT rediscovery that is much slower than reconnecting directly.
	// After 3 consecutive failures the addresses are likely genuinely stale,
	// so clearing them lets discovery start fresh.
	if b.reconnectFailures >= 3 {
		cleared := 0
		for _, p := range b.h.Peerstore().Peers() {
			if p == b.h.ID() {
				continue
			}
			if b.h.Network().Connectedness(p) != network.Connected &&
				b.h.Network().Connectedness(p) != network.Limited {
				b.h.Peerstore().ClearAddrs(p)
				cleared++
			}
		}
		if cleared > 0 {
			b.logger.Info(
				"cleared stale peerstore addresses after repeated failures",
				zap.Int("cleared", cleared),
			)
		}
	}

	if err := b.DiscoverPeers(ctx); err != nil {
		b.logger.Error("peer reconnect failed", zap.Error(err))
	}

	newCount := b.nonBootstrapPeerCount()
	if newCount >= b.p2pConfig.MinBootstrapPeers {
		b.reconnectFailures = 0
		b.logger.Info("peer reconnect succeeded", zap.Int("peers", newCount))
	} else {
		b.reconnectFailures++
		b.logger.Warn(
			"peer reconnect: still low peer count, will retry at next interval",
			zap.Int("peers", newCount),
			zap.Int("consecutive_failures", b.reconnectFailures),
		)
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
	err := b.ps.Publish(
		b.ctx,
		bitmask,
		data,
		blossomsub.WithSecretKeyAndPeerId(b.signKey, b.derivedPeerID),
	)
	if err != nil && errors.Is(err, blossomsub.ErrBitmaskClosed) &&
		b.p2pConfig.Network == 99 {
		// Ignore bitmask closed errors for devnet
		return nil
	}

	return errors.Wrap(
		errors.Wrapf(err, "bitmask: %x", bitmask),
		"publish to bitmask",
	)
}

func (b *BlossomSub) Publish(address []byte, data []byte) error {
	bitmask := up2p.GetBloomFilter(address, 256, 3)
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

	b.logger.Info(
		"subscribe to bitmask",
		zap.String("bitmask", hex.EncodeToString(bitmask)),
	)

	// Track the bit slices for this subscription
	b.subscriptionMutex.Lock()
	bitSlices := make([][]byte, 0, len(bm))
	for _, bit := range bm {
		sliceCopy := make([]byte, len(bit.Bitmask()))
		copy(sliceCopy, bit.Bitmask())
		bitSlices = append(bitSlices, sliceCopy)
	}
	b.subscriptionTracker[string(bitmask)] = bitSlices
	b.subscriptionMutex.Unlock()

	// If the bitmask count is greater than three, this is a broad subscribe
	// and the caller is expected to handle disambiguation of addresses
	exact := len(bm) <= 3

	subs := []*blossomsub.Subscription{}
	for _, bit := range bm {
		sub, err := bit.Subscribe(
			blossomsub.WithBufferSize(b.p2pConfig.SubscriptionQueueSize),
		)
		if err != nil {
			b.logger.Error("subscription failed", zap.Error(err))
			// Clean up on failure
			b.subscriptionMutex.Lock()
			delete(b.subscriptionTracker, string(bitmask))
			b.subscriptionMutex.Unlock()
			return errors.Wrap(err, "subscribe")
		}
		b.subscriptionMutex.Lock()
		_, ok := b.bitmaskMap[string(bit.Bitmask())]
		if !ok {
			b.bitmaskMap[string(bit.Bitmask())] = bit
		}
		b.subscriptionMutex.Unlock()
		subs = append(subs, sub)
	}

	b.logger.Info(
		"begin streaming from bitmask",
		zap.String("bitmask", hex.EncodeToString(bitmask)),
	)

	// Track subscriptions per bitmask for cleanup
	b.subscriptionMutex.Lock()
	b.subscriptionsByBitmask[string(bitmask)] = subs
	b.subscriptionMutex.Unlock()

	for _, sub := range subs {
		copiedBitmask := make([]byte, len(bitmask))
		copy(copiedBitmask[:], bitmask[:])
		sub := sub

		go func() {
			for {
				if !b.subscribeHandler(sub, copiedBitmask, exact, handler) {
					return
				}
			}
		}()
	}

	b.logger.Info(
		"successfully subscribed to bitmask",
		zap.String("bitmask", hex.EncodeToString(bitmask)),
	)

	return nil
}

// subscribeHandler processes a single message from the subscription.
// Returns true if the loop should continue, false if it should exit.
func (b *BlossomSub) subscribeHandler(
	sub *blossomsub.Subscription,
	copiedBitmask []byte,
	exact bool,
	handler func(message *pb.Message) error,
) bool {
	defer func() {
		if r := recover(); r != nil {
			b.logger.Error(
				"message handler panicked, recovering",
				zap.Any("panic", r),
				zap.String("stack", string(debug.Stack())),
			)
		}
	}()

	m, err := sub.Next(b.ctx)
	if err != nil {
		// Context cancelled or subscription closed - exit the loop
		b.logger.Debug(
			"subscription exiting",
			zap.Error(err),
		)
		return false
	}
	if m == nil {
		// Subscription closed
		return false
	}
	if bytes.Equal(m.Bitmask, copiedBitmask) || !exact {
		if err = handler(m.Message); err != nil {
			b.logger.Debug("message handler returned error", zap.Error(err))
		}
	}
	return true
}

func (b *BlossomSub) Unsubscribe(bitmask []byte, raw bool) {
	b.subscriptionMutex.Lock()
	defer b.subscriptionMutex.Unlock()

	bitmaskKey := string(bitmask)
	bitSlices, exists := b.subscriptionTracker[bitmaskKey]
	if !exists {
		b.logger.Warn(
			"attempted to unsubscribe from unknown bitmask",
			zap.String("bitmask", hex.EncodeToString(bitmask)),
		)
		return
	}

	b.logger.Info(
		"unsubscribing from bitmask",
		zap.String("bitmask", hex.EncodeToString(bitmask)),
	)

	// Cancel the subscription objects so the bitmask can be closed and the
	// subscription goroutines exit.
	if subs, ok := b.subscriptionsByBitmask[bitmaskKey]; ok {
		for _, sub := range subs {
			sub.Cancel()
		}
		delete(b.subscriptionsByBitmask, bitmaskKey)
	}

	// Check each bit slice to see if it's still needed by other subscriptions
	for _, bitSlice := range bitSlices {
		bitSliceKey := string(bitSlice)

		// Check if any other subscription is using this bit slice
		stillNeeded := false
		for otherKey, otherSlices := range b.subscriptionTracker {
			if otherKey == bitmaskKey {
				continue // Skip the subscription we're removing
			}

			for _, otherSlice := range otherSlices {
				if bytes.Equal(otherSlice, bitSlice) {
					stillNeeded = true
					break
				}
			}

			if stillNeeded {
				break
			}
		}

		// Only close the bitmask if no other subscription needs it
		if !stillNeeded {
			if bm, ok := b.bitmaskMap[bitSliceKey]; ok {
				b.logger.Debug(
					"closing bit slice",
					zap.String("bit_slice", hex.EncodeToString(bitSlice)),
				)
				bm.Close()
				delete(b.bitmaskMap, bitSliceKey)
			}
		} else {
			b.logger.Debug(
				"bit slice still needed by other subscription",
				zap.String("bit_slice", hex.EncodeToString(bitSlice)),
			)
		}
	}

	// Remove the subscription from tracker
	delete(b.subscriptionTracker, bitmaskKey)
}

func (b *BlossomSub) RegisterValidator(
	bitmask []byte,
	validator func(peerID peer.ID, message *pb.Message) p2p.ValidationResult,
	sync bool,
) error {
	validatorEx := func(
		ctx context.Context, peerID peer.ID, message *blossomsub.Message,
	) blossomsub.ValidationResult {
		switch v := validator(peerID, message.Message); v {
		case p2p.ValidationResultAccept:
			return blossomsub.ValidationAccept
		case p2p.ValidationResultReject:
			return blossomsub.ValidationReject
		case p2p.ValidationResultIgnore:
			return blossomsub.ValidationIgnore
		default:
			panic("unreachable")
		}
	}
	var _ blossomsub.ValidatorEx = validatorEx
	return b.ps.RegisterBitmaskValidator(
		bitmask,
		validatorEx,
		blossomsub.WithValidatorInline(sync),
	)
}

func (b *BlossomSub) UnregisterValidator(bitmask []byte) error {
	return b.ps.UnregisterBitmaskValidator(bitmask)
}

func (b *BlossomSub) GetPeerID() []byte {
	return []byte(b.derivedPeerID)
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
	if manual := b.manualReachability.Load(); manual != nil {
		return wrapperspb.Bool(*manual)
	}
	reachability := b.manualReachability.Load()
	if reachability == nil {
		return nil
	}
	return &wrapperspb.BoolValue{Value: *reachability}
}

func (b *BlossomSub) initConnectivityServices(
	isBootstrapPeer bool,
	bootstrappers []peer.AddrInfo,
) {
	if b.p2pConfig.Network != 0 {
		return
	}

	if b.h == nil {
		return
	}
	if isBootstrapPeer {
		b.startConnectivityService()
		return
	}
	clone := make([]peer.AddrInfo, len(bootstrappers))
	copy(clone, bootstrappers)
	b.blockUntilConnectivityTest(clone)
}

func (b *BlossomSub) startConnectivityService() {
	// Use raw TCP listener on port 8340
	listenAddr := "0.0.0.0:8340"

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		b.logger.Error("failed to start connectivity service", zap.Error(err))
		return
	}

	b.logger.Info("started connectivity service", zap.String("addr", listenAddr))

	server := grpc.NewServer()
	protobufs.RegisterConnectivityServiceServer(
		server,
		newConnectivityService(b.logger.Named("connectivityService"), b.h),
	)

	go func() {
		if err := server.Serve(listener); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			b.logger.Error("connectivity service exited", zap.Error(err))
		}
	}()

	go func() {
		<-b.ctx.Done()
		server.GracefulStop()
		_ = listener.Close()
	}()
}

func (b *BlossomSub) blockUntilConnectivityTest(bootstrappers []peer.AddrInfo) {
	if len(bootstrappers) == 0 {
		b.logger.Warn("connectivity test skipped, no bootstrap peers available")
		return
	}

	// Check if we have a recent successful connectivity check cached
	if b.isConnectivityCacheValid() {
		b.logger.Info("skipping connectivity test, recent successful check cached",
			zap.Uint("core_id", b.coreId))
		b.recordManualReachability(true)
		return
	}

	delay := time.NewTimer(10 * time.Second)
	defer delay.Stop()
	select {
	case <-delay.C:
	case <-b.ctx.Done():
		b.logger.Info("connectivity test cancelled before start, context done")
		return
	}

	backoff := 10 * time.Second
	for {
		if err := b.runConnectivityTest(b.ctx, bootstrappers); err == nil {
			// Write the cache on successful connectivity test
			b.writeConnectivityCache()
			return
		} else {
			b.logger.Warn("connectivity test failed, retrying", zap.Error(err))
		}

		wait := time.NewTimer(backoff)
		select {
		case <-wait.C:
			wait.Stop()
		case <-b.ctx.Done():
			wait.Stop()
			b.logger.Info("connectivity test cancelled, context done")
			return
		}
	}
}

func (b *BlossomSub) runConnectivityTest(
	ctx context.Context,
	bootstrappers []peer.AddrInfo,
) error {
	candidates := make([]peer.AddrInfo, 0, len(bootstrappers))
	for _, info := range bootstrappers {
		if info.ID == b.h.ID() {
			continue
		}
		if strings.Contains(info.Addrs[0].String(), "dns4") {
			candidates = append(candidates, info)
		}
	}
	if len(candidates) == 0 {
		return errors.New("connectivity test: no bootstrap peers available")
	}
	selection, err := rand.Int(rand.Reader, big.NewInt(int64(len(candidates))))
	if err != nil {
		return errors.Wrap(err, "connectivity test peer selection")
	}
	target := candidates[selection.Int64()]
	return b.invokeConnectivityTest(ctx, target)
}

func (b *BlossomSub) invokeConnectivityTest(
	ctx context.Context,
	target peer.AddrInfo,
) error {
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var targetAddr string
	for _, addr := range target.Addrs {
		host, err := addr.ValueForProtocol(ma.P_IP4)
		if err != nil {
			host, err = addr.ValueForProtocol(ma.P_IP6)
			if err != nil {
				host, err = addr.ValueForProtocol(ma.P_DNS4)
				if err != nil {
					continue
				}
			}
		}

		targetAddr = fmt.Sprintf("%s:8340", host)
		break
	}

	if targetAddr == "" {
		b.recordManualReachability(false)
		return errors.New(
			"connectivity test: no valid address found for bootstrap peer",
		)
	}

	b.logger.Debug(
		"connecting to bootstrap connectivity service",
		zap.String("target", targetAddr),
	)

	conn, err := grpc.NewClient(
		targetAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		b.recordManualReachability(false)
		return errors.Wrap(err, "connectivity test dial")
	}
	defer conn.Close()

	client := protobufs.NewConnectivityServiceClient(conn)
	req := &protobufs.ConnectivityTestRequest{
		PeerId:     []byte(b.h.ID()),
		Multiaddrs: b.collectConnectivityMultiaddrs(),
	}

	resp, err := client.TestConnectivity(dialCtx, req)
	if err != nil {
		b.recordManualReachability(false)
		return errors.Wrap(err, "connectivity test rpc")
	}

	b.recordManualReachability(resp.GetSuccess())
	if resp.GetSuccess() {
		b.logger.Info(
			"your node is reachable",
			zap.String("bootstrap_peer", target.ID.String()),
		)
		return nil
	}

	b.logger.Warn(
		"YOUR NODE IS NOT REACHABLE. CHECK YOUR FIREWALL AND PORT FORWARDING CONFIGURATION",
		zap.String("bootstrap_peer", target.ID.String()),
		zap.String("error", resp.GetErrorMessage()),
	)
	if resp.GetErrorMessage() != "" {
		return errors.New(resp.GetErrorMessage())
	}
	return errors.New("connectivity test failed")
}

func (b *BlossomSub) collectConnectivityMultiaddrs() []string {
	addrs := b.GetOwnMultiaddrs()
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	return out
}

func (b *BlossomSub) recordManualReachability(success bool) {
	state := new(bool)
	*state = success
	b.manualReachability.Store(state)
}

const connectivityCacheValidity = 7 * 24 * time.Hour // 1 week

// connectivityCachePath returns the path to the connectivity check cache file
// for this core. The file is stored in <configDir>/connectivity-check-<coreId>
func (b *BlossomSub) connectivityCachePath() string {
	return filepath.Join(
		string(b.configDir),
		fmt.Sprintf("connectivity-check-%d", b.coreId),
	)
}

// isConnectivityCacheValid checks if there's a valid (< 1 week old) connectivity
// cache file indicating a previous successful check
func (b *BlossomSub) isConnectivityCacheValid() bool {
	cachePath := b.connectivityCachePath()
	info, err := os.Stat(cachePath)
	if err != nil {
		// File doesn't exist or error accessing it
		return false
	}

	// Check if the file is less than 1 week old
	age := time.Since(info.ModTime())
	if age < connectivityCacheValidity {
		b.logger.Debug("connectivity cache is valid",
			zap.String("path", cachePath),
			zap.Duration("age", age))
		return true
	}

	b.logger.Debug("connectivity cache is stale",
		zap.String("path", cachePath),
		zap.Duration("age", age))
	return false
}

// writeConnectivityCache writes the connectivity cache file to indicate
// a successful connectivity check
func (b *BlossomSub) writeConnectivityCache() {
	cachePath := b.connectivityCachePath()

	// Ensure the directory exists
	if err := os.MkdirAll(filepath.Dir(cachePath), 0755); err != nil {
		b.logger.Warn("failed to create connectivity cache directory",
			zap.Error(err))
		return
	}

	// Write the cache file with the current timestamp
	timestamp := time.Now().Format(time.RFC3339)
	if err := os.WriteFile(cachePath, []byte(timestamp), 0644); err != nil {
		b.logger.Warn("failed to write connectivity cache",
			zap.String("path", cachePath),
			zap.Error(err))
		return
	}

	b.logger.Debug("wrote connectivity cache",
		zap.String("path", cachePath))
}

type connectivityService struct {
	protobufs.UnimplementedConnectivityServiceServer
	logger *zap.Logger
	host   host.Host
	ping   *ping.PingService
}

func newConnectivityService(
	logger *zap.Logger,
	h host.Host,
) *connectivityService {
	return &connectivityService{
		logger: logger,
		host:   h,
		ping:   ping.NewPingService(h),
	}
}

func (s *connectivityService) TestConnectivity(
	ctx context.Context,
	req *protobufs.ConnectivityTestRequest,
) (*protobufs.ConnectivityTestResponse, error) {
	resp := &protobufs.ConnectivityTestResponse{}
	peerID := peer.ID(req.GetPeerId())
	if peerID == "" {
		resp.ErrorMessage = "peer id required"
		return resp, nil
	}

	// Get the actual IP address from the gRPC peer context
	pr, ok := grpcpeer.FromContext(ctx)
	if !ok || pr.Addr == nil {
		resp.ErrorMessage = "unable to determine peer address from context"
		return resp, nil
	}

	// Extract the IP from the remote address
	remoteAddr := pr.Addr.String()
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		resp.ErrorMessage = fmt.Sprintf("invalid remote address: %v", err)
		return resp, nil
	}

	s.logger.Debug(
		"connectivity test from peer",
		zap.String("peer_id", peerID.String()),
		zap.String("remote_ip", host),
	)

	addrs := make([]ma.Multiaddr, 0, len(req.GetMultiaddrs()))
	for _, addrStr := range req.GetMultiaddrs() {
		maddr, err := ma.NewMultiaddr(addrStr)
		if err != nil {
			s.logger.Debug(
				"invalid multiaddr in connectivity request",
				zap.String("peer_id", peerID.String()),
				zap.String("multiaddr", addrStr),
				zap.Error(err),
			)
			continue
		}

		// Extract the port from the multiaddr but use the actual IP from the
		// connection
		port, err := maddr.ValueForProtocol(ma.P_TCP)
		if err != nil {
			// If it's not TCP, try UDP
			port, err = maddr.ValueForProtocol(ma.P_UDP)
			if err != nil {
				continue
			}
			// Build UDP multiaddr with actual IP
			newAddr, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/udp/%s/quic-v1", host, port))
			if err != nil {
				continue
			}
			addrs = append(addrs, newAddr)
			continue
		}

		// Build TCP multiaddr with actual IP
		newAddr, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%s", host, port))
		if err != nil {
			continue
		}
		addrs = append(addrs, newAddr)
	}

	if len(addrs) == 0 {
		resp.ErrorMessage = "no valid multiaddrs to test"
		return resp, nil
	}

	s.logger.Debug(
		"attempting to connect to peer",
		zap.String("peer_id", peerID.String()),
		zap.Any("addrs", addrs),
	)

	s.host.Peerstore().AddAddrs(peerID, addrs, peerstore.TempAddrTTL)

	connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err = s.host.Connect(connectCtx, peer.AddrInfo{
		ID:    peerID,
		Addrs: addrs,
	})
	if err != nil {
		resp.ErrorMessage = err.Error()
		return resp, nil
	}

	defer s.host.Network().ClosePeer(peerID)

	pingCtx, cancelPing := context.WithTimeout(ctx, 10*time.Second)
	defer cancelPing()

	select {
	case <-pingCtx.Done():
		resp.ErrorMessage = pingCtx.Err().Error()
		return resp, nil
	case result := <-s.ping.Ping(pingCtx, peerID):
		if result.Error != nil {
			resp.ErrorMessage = result.Error.Error()
			return resp, nil
		}
	}

	resp.Success = true
	return resp, nil
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
		logger.Warn("BOOTSTRAP PEER")
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

// GetOwnMultiaddrs returns our own multiaddresses as seen by the network
func (b *BlossomSub) GetOwnMultiaddrs() []ma.Multiaddr {
	allAddrs := make([]ma.Multiaddr, 0)

	// 1. Get listen addresses
	listenAddrs := b.h.Network().ListenAddresses()

	// 2. Get addresses from our own peerstore (observed addresses)
	selfAddrs := b.h.Peerstore().Addrs(b.h.ID())

	// 3. Get all addresses including identified ones
	identifiedAddrs := b.h.Addrs()

	// Combine and deduplicate
	addrMap := make(map[string]ma.Multiaddr)
	for _, addr := range listenAddrs {
		addrMap[addr.String()] = addr
	}
	for _, addr := range selfAddrs {
		addrMap[addr.String()] = addr
	}
	for _, addr := range identifiedAddrs {
		addrMap[addr.String()] = addr
	}

	// Convert back to slice
	for _, addr := range addrMap {
		allAddrs = append(allAddrs, addr)
	}

	return b.filterAndPrioritizeAddrs(allAddrs)
}

// filterAndPrioritizeAddrs filters and prioritizes addresses for external
// visibility
func (b *BlossomSub) filterAndPrioritizeAddrs(
	addrs []ma.Multiaddr,
) []ma.Multiaddr {
	var public, private, relay []ma.Multiaddr

	for _, addr := range addrs {
		// Skip localhost and unspecified addresses
		if b.isLocalOnlyAddr(addr) {
			continue
		}

		// Check if it's a relay address
		if b.isRelayAddr(addr) {
			relay = append(relay, addr)
		} else if b.isPublicAddr(addr) {
			public = append(public, addr)
		} else if b.isPrivateButRoutable(addr) {
			private = append(private, addr)
		}
	}

	// Return in priority order: public, private, relay
	result := make([]ma.Multiaddr, 0, len(public)+len(private)+len(relay))
	result = append(result, public...)
	result = append(result, private...)
	result = append(result, relay...)

	return result
}

// isLocalOnlyAddr checks if the address is localhost or unspecified
func (b *BlossomSub) isLocalOnlyAddr(addr ma.Multiaddr) bool {
	// Get the IP component
	ipComponent, err := addr.ValueForProtocol(ma.P_IP4)
	if err != nil {
		ipComponent, err = addr.ValueForProtocol(ma.P_IP6)
		if err != nil {
			return false
		}
	}

	ip := net.ParseIP(ipComponent)
	if ip == nil {
		return false
	}

	return ip.IsLoopback() || ip.IsUnspecified()
}

// isRelayAddr checks if this is a relay address
func (b *BlossomSub) isRelayAddr(addr ma.Multiaddr) bool {
	protocols := addr.Protocols()
	for _, p := range protocols {
		if p.Code == ma.P_CIRCUIT {
			return true
		}
	}
	return false
}

// isPublicAddr checks if this is a public/external address
func (b *BlossomSub) isPublicAddr(addr ma.Multiaddr) bool {
	ipComponent, err := addr.ValueForProtocol(ma.P_IP4)
	if err != nil {
		ipComponent, err = addr.ValueForProtocol(ma.P_IP6)
		if err != nil {
			return false
		}
	}

	ip := net.ParseIP(ipComponent)
	if ip == nil {
		return false
	}

	// Check if it's a globally routable IP
	return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified()
}

// isPrivateButRoutable checks if this is a private but potentially routable
// address
func (b *BlossomSub) isPrivateButRoutable(addr ma.Multiaddr) bool {
	ipComponent, err := addr.ValueForProtocol(ma.P_IP4)
	if err != nil {
		ipComponent, err = addr.ValueForProtocol(ma.P_IP6)
		if err != nil {
			return false
		}
	}

	ip := net.ParseIP(ipComponent)
	if ip == nil {
		return false
	}

	// Private but not localhost
	return ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified()
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

func (b *BlossomSub) GetDirectChannel(
	ctx context.Context,
	peerID []byte,
	purpose string,
) (
	cc *grpc.ClientConn, err error,
) {
	pi, err := b.dht.FindPeer(ctx, peer.ID(peerID))
	if err != nil {
		return nil, errors.Wrap(err, "get direct channel")
	}

	creds, err := NewPeerAuthenticator(
		b.logger,
		&b.p2pConfig,
		nil,
		nil,
		nil,
		nil,
		[][]byte{peerID},
		map[string]channel.AllowedPeerPolicyType{
			"quilibrium.node.proxy.pb.PubSubProxy": channel.OnlySelfPeer,
		},
		map[string]channel.AllowedPeerPolicyType{},
	).CreateClientTLSCredentials(peerID)
	if err != nil {
		return nil, errors.Wrap(err, "get direct channel")
	}

	var lastError error
	for _, addr := range pi.Addrs {
		var mga net.Addr
		b.logger.Debug(
			"attempting to get direct channel with peer",
			zap.String("peer", peer.ID(peerID).String()),
			zap.String("addr", addr.String()),
		)
		mga, lastError = mn.ToNetAddr(addr)
		if lastError != nil {
			b.logger.Debug(
				"skipping address",
				zap.String("addr", addr.String()),
				zap.Error(lastError),
			)
			continue
		}

		var cc *grpc.ClientConn
		cc, lastError = grpc.NewClient(
			mga.String(),
			grpc.WithTransportCredentials(creds),
		)
		if lastError != nil {
			b.logger.Debug(
				"could not connect",
				zap.String("addr", addr.String()),
				zap.Error(lastError),
			)
			continue
		}

		return cc, nil
	}

	return nil, errors.Wrap(lastError, "get direct channel")
}

func (b *BlossomSub) GetPublicKey() []byte {
	pub, _ := b.signKey.GetPublic().Raw()
	return pub
}

func (b *BlossomSub) SignMessage(msg []byte) ([]byte, error) {
	sig, err := b.signKey.Sign(msg)
	return sig, errors.Wrap(err, "sign message")
}

func toBlossomSubParams(
	p2pConfig *config.P2PConfig,
) blossomsub.BlossomSubParams {
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

// Close implements p2p.PubSub.
func (b *BlossomSub) Close() error {
	// Cancel context to signal all subscription goroutines to exit
	if b.cancel != nil {
		b.cancel()
	}

	// Cancel all subscriptions to unblock any pending Next() calls
	b.subscriptionMutex.Lock()
	for _, subs := range b.subscriptionsByBitmask {
		for _, sub := range subs {
			sub.Cancel()
		}
	}
	b.subscriptionsByBitmask = nil
	b.subscriptionMutex.Unlock()

	return nil
}

// SetShutdownContext implements p2p.PubSub. When the provided context is
// cancelled, the internal BlossomSub context will also be cancelled, allowing
// subscription loops to exit gracefully.
func (b *BlossomSub) SetShutdownContext(ctx context.Context) {
	go func() {
		select {
		case <-ctx.Done():
			b.logger.Debug("shutdown context cancelled, closing pubsub")
			b.Close()
		case <-b.ctx.Done():
			// Already closed
		}
	}()
}

// MultiaddrToIPNet converts a multiaddr containing /ip4 or /ip6
// into a *net.IPNet with a host mask (/32 or /128).
func MultiaddrToIPNet(m ma.Multiaddr) (*net.IPNet, error) {
	var (
		ip     net.IP
		ipBits int
	)

	// Walk components and grab the first IP we see.
	ma.ForEach(m, func(c ma.Component, err error) bool {
		if err != nil {
			return false
		}
		switch c.Protocol().Code {
		case ma.P_IP4:
			if ip == nil {
				ip = net.IP(c.RawValue()).To4()
				ipBits = 32
			}
			return false

		case ma.P_IP6:
			if ip == nil {
				ip = net.IP(c.RawValue()).To16()
				ipBits = 128
			}
			return false
		}
		return true
	})

	if ip == nil {
		return nil, fmt.Errorf("multiaddr has no ip4/ip6 component: %s", m)
	}

	mask := net.CIDRMask(ipBits, ipBits)

	return &net.IPNet{
		IP:   ip.Mask(mask),
		Mask: mask,
	}, nil
}

func getBitmaskSets(bitmask []byte) [][]byte {
	sliced := [][]byte{}
	if bytes.Equal(bitmask, make([]byte, len(bitmask))) {
		sliced = append(sliced, bitmask)
	} else {
		for i, b := range bitmask {
			if b == 0 {
				continue
			}

			// fast: one bit in byte
			if b&(b-1) == 0 {
				slice := make([]byte, len(bitmask))
				slice[i] = b
				sliced = append(sliced, slice)
				sliced = append(sliced, slices.Concat([]byte{0}, slice))
				sliced = append(sliced, slices.Concat([]byte{0, 0}, slice))
				sliced = append(sliced, slices.Concat([]byte{0, 0, 0}, slice))
				continue
			}

			for j := 7; j >= 0; j-- {
				if (b>>j)&1 == 1 {
					slice := make([]byte, len(bitmask))
					slice[i] = 1 << j
					sliced = append(sliced, slice)
					sliced = append(sliced, slices.Concat([]byte{0}, slice))
					sliced = append(sliced, slices.Concat([]byte{0, 0}, slice))
					sliced = append(sliced, slices.Concat([]byte{0, 0, 0}, slice))
				}
			}
		}
	}

	return sliced
}
