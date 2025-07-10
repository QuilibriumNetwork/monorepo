package config

import (
	"time"

	blossomsub "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub"
	qruntime "source.quilibrium.com/quilibrium/monorepo/utils/runtime"
)

const (
	defaultLowWatermarkConnections  = 160
	defaultHighWatermarkConnections = 192
	defaultGRPCServerRateLimit      = 10
	defaultMinBootstrapPeers        = 3
	defaultBootstrapParallelism     = 10
	defaultDiscoveryParallelism     = 50
	defaultDiscoveryPeerLookupLimit = 1000
	defaultPingTimeout              = 5 * time.Second
	defaultPingPeriod               = 30 * time.Second
	defaultPingAttempts             = 3
	defaultStreamListenMultiaddr    = "/ip4/0.0.0.0/tcp/8340"
)

type P2PConfig struct {
	D                         int           `yaml:"d"`
	DLo                       int           `yaml:"dLo"`
	DHi                       int           `yaml:"dHi"`
	DScore                    int           `yaml:"dScore"`
	DOut                      int           `yaml:"dOut"`
	HistoryLength             int           `yaml:"historyLength"`
	HistoryGossip             int           `yaml:"historyGossip"`
	DLazy                     int           `yaml:"dLazy"`
	GossipFactor              float64       `yaml:"gossipFactor"`
	GossipRetransmission      int           `yaml:"gossipRetransmission"`
	HeartbeatInitialDelay     time.Duration `yaml:"heartbeatInitialDelay"`
	HeartbeatInterval         time.Duration `yaml:"heartbeatInterval"`
	FanoutTTL                 time.Duration `yaml:"fanoutTTL"`
	PrunePeers                int           `yaml:"prunePeers"`
	PruneBackoff              time.Duration `yaml:"pruneBackoff"`
	UnsubscribeBackoff        time.Duration `yaml:"unsubscribeBackoff"`
	Connectors                int           `yaml:"connectors"`
	MaxPendingConnections     int           `yaml:"maxPendingConnections"`
	ConnectionTimeout         time.Duration `yaml:"connectionTimeout"`
	DirectConnectTicks        uint64        `yaml:"directConnectTicks"`
	DirectConnectInitialDelay time.Duration `yaml:"directConnectInitialDelay"`
	OpportunisticGraftTicks   uint64        `yaml:"opportunisticGraftTicks"`
	OpportunisticGraftPeers   int           `yaml:"opportunisticGraftPeers"`
	GraftFloodThreshold       time.Duration `yaml:"graftFloodThreshold"`
	MaxIHaveLength            int           `yaml:"maxIHaveLength"`
	MaxIHaveMessages          int           `yaml:"maxIHaveMessages"`
	MaxIDontWantMessages      int           `yaml:"maxIDontWantMessages"`
	IWantFollowupTime         time.Duration `yaml:"iWantFollowupTime"`
	IDontWantMessageThreshold int           `yaml:"iDontWantMessageThreshold"`
	IDontWantMessageTTL       int           `yaml:"iDontWantMessageTTL"`
	BootstrapPeers            []string      `yaml:"bootstrapPeers"`
	ListenMultiaddr           string        `yaml:"listenMultiaddr"`
	StreamListenMultiaddr     string        `yaml:"streamListenMultiaddr"`
	PeerPrivKey               string        `yaml:"peerPrivKey"`
	TraceLogFile              string        `yaml:"traceLogFile"`
	TraceLogStdout            bool          `yaml:"traceLogStdout"`
	Network                   uint8         `yaml:"network"`
	LowWatermarkConnections   int           `yaml:"lowWatermarkConnections"`
	HighWatermarkConnections  int           `yaml:"highWatermarkConnections"`
	DirectPeers               []string      `yaml:"directPeers"`
	GRPCServerRateLimit       int           `yaml:"grpcServerRateLimit"`
	MinBootstrapPeers         int           `yaml:"minBootstrapPeers"`
	BootstrapParallelism      int           `yaml:"bootstrapParallelism"`
	DiscoveryParallelism      int           `yaml:"discoveryParallelism"`
	DiscoveryPeerLookupLimit  int           `yaml:"discoveryPeerLookupLimit"`
	PingTimeout               time.Duration `yaml:"pingTimeout"`
	PingPeriod                time.Duration `yaml:"pingPeriod"`
	PingAttempts              int           `yaml:"pingAttempts"`
	ValidateQueueSize         int           `yaml:"validateQueueSize"`
	ValidateWorkers           int           `yaml:"validateWorkers"`
	SubscriptionQueueSize     int           `yaml:"subscriptionQueueSize"`
	PeerOutboundQueueSize     int           `yaml:"peerOutboundQueueSize"`
}

// WithDefaults returns a copy of the P2PConfig with any missing fields set to
// their default values.
func (c P2PConfig) WithDefaults() P2PConfig {
	cpy := c
	if cpy.D == 0 {
		cpy.D = blossomsub.BlossomSubD
	}
	if cpy.DLo == 0 {
		cpy.DLo = blossomsub.BlossomSubDlo
	}
	if cpy.DHi == 0 {
		cpy.DHi = blossomsub.BlossomSubDhi
	}
	if cpy.DScore == 0 {
		cpy.DScore = blossomsub.BlossomSubDscore
	}
	if cpy.DOut == 0 {
		cpy.DOut = blossomsub.BlossomSubDout
	}
	if cpy.HistoryLength == 0 {
		cpy.HistoryLength = blossomsub.BlossomSubHistoryLength
	}
	if cpy.HistoryGossip == 0 {
		cpy.HistoryGossip = blossomsub.BlossomSubHistoryGossip
	}
	if cpy.DLazy == 0 {
		cpy.DLazy = blossomsub.BlossomSubDlazy
	}
	if cpy.GossipFactor == 0 {
		cpy.GossipFactor = blossomsub.BlossomSubGossipFactor
	}
	if cpy.GossipRetransmission == 0 {
		cpy.GossipRetransmission = blossomsub.BlossomSubGossipRetransmission
	}
	if cpy.HeartbeatInitialDelay == 0 {
		cpy.HeartbeatInitialDelay = blossomsub.BlossomSubHeartbeatInitialDelay
	}
	if cpy.HeartbeatInterval == 0 {
		cpy.HeartbeatInterval = blossomsub.BlossomSubHeartbeatInterval
	}
	if cpy.FanoutTTL == 0 {
		cpy.FanoutTTL = blossomsub.BlossomSubFanoutTTL
	}
	if cpy.PrunePeers == 0 {
		cpy.PrunePeers = blossomsub.BlossomSubPrunePeers
	}
	if cpy.PruneBackoff == 0 {
		cpy.PruneBackoff = blossomsub.BlossomSubPruneBackoff
	}
	if cpy.UnsubscribeBackoff == 0 {
		cpy.UnsubscribeBackoff = blossomsub.BlossomSubUnsubscribeBackoff
	}
	if cpy.Connectors == 0 {
		cpy.Connectors = blossomsub.BlossomSubConnectors
	}
	if cpy.MaxPendingConnections == 0 {
		cpy.MaxPendingConnections = blossomsub.BlossomSubMaxPendingConnections
	}
	if cpy.ConnectionTimeout == 0 {
		cpy.ConnectionTimeout = blossomsub.BlossomSubConnectionTimeout
	}
	if cpy.DirectConnectTicks == 0 {
		cpy.DirectConnectTicks = blossomsub.BlossomSubDirectConnectTicks
	}
	if cpy.DirectConnectInitialDelay == 0 {
		cpy.DirectConnectInitialDelay =
			blossomsub.BlossomSubDirectConnectInitialDelay
	}
	if cpy.OpportunisticGraftTicks == 0 {
		cpy.OpportunisticGraftTicks =
			blossomsub.BlossomSubOpportunisticGraftTicks
	}
	if cpy.OpportunisticGraftPeers == 0 {
		cpy.OpportunisticGraftPeers =
			blossomsub.BlossomSubOpportunisticGraftPeers
	}
	if cpy.GraftFloodThreshold == 0 {
		cpy.GraftFloodThreshold = blossomsub.BlossomSubGraftFloodThreshold
	}
	if cpy.MaxIHaveLength == 0 {
		cpy.MaxIHaveLength = blossomsub.BlossomSubMaxIHaveLength
	}
	if cpy.MaxIHaveMessages == 0 {
		cpy.MaxIHaveMessages = blossomsub.BlossomSubMaxIHaveMessages
	}
	if cpy.MaxIDontWantMessages == 0 {
		cpy.MaxIDontWantMessages = blossomsub.BlossomSubMaxIDontWantMessages
	}
	if cpy.IWantFollowupTime == 0 {
		cpy.IWantFollowupTime = blossomsub.BlossomSubIWantFollowupTime
	}
	if cpy.IDontWantMessageThreshold == 0 {
		cpy.IDontWantMessageThreshold = blossomsub.BlossomSubIDontWantMessageThreshold
	}
	if cpy.IDontWantMessageTTL == 0 {
		cpy.IDontWantMessageTTL = blossomsub.BlossomSubIDontWantMessageTTL
	}
	if cpy.LowWatermarkConnections == 0 {
		cpy.LowWatermarkConnections = defaultLowWatermarkConnections
	}
	if cpy.HighWatermarkConnections == 0 {
		cpy.HighWatermarkConnections = defaultHighWatermarkConnections
	}
	if cpy.GRPCServerRateLimit == 0 {
		cpy.GRPCServerRateLimit = defaultGRPCServerRateLimit
	}
	if cpy.MinBootstrapPeers == 0 {
		cpy.MinBootstrapPeers = defaultMinBootstrapPeers
	}
	if cpy.BootstrapParallelism == 0 {
		cpy.BootstrapParallelism = defaultBootstrapParallelism
	}
	if cpy.DiscoveryParallelism == 0 {
		cpy.DiscoveryParallelism = defaultDiscoveryParallelism
	}
	if cpy.DiscoveryPeerLookupLimit == 0 {
		cpy.DiscoveryPeerLookupLimit = defaultDiscoveryPeerLookupLimit
	}
	if cpy.PingTimeout == 0 {
		cpy.PingTimeout = defaultPingTimeout
	}
	if cpy.PingPeriod == 0 {
		cpy.PingPeriod = defaultPingPeriod
	}
	if cpy.PingAttempts == 0 {
		cpy.PingAttempts = defaultPingAttempts
	}
	if cpy.StreamListenMultiaddr == "" {
		cpy.StreamListenMultiaddr = defaultStreamListenMultiaddr
	}
	if cpy.ValidateQueueSize == 0 {
		cpy.ValidateQueueSize = blossomsub.DefaultValidateQueueSize
	}
	if cpy.ValidateWorkers == 0 {
		cpy.ValidateWorkers = qruntime.WorkerCount(0, false, false)
	}
	if cpy.SubscriptionQueueSize == 0 {
		cpy.SubscriptionQueueSize = blossomsub.DefaultSubscriptionQueueSize
	}
	if cpy.PeerOutboundQueueSize == 0 {
		cpy.PeerOutboundQueueSize = blossomsub.DefaultPeerOutboundQueueSize
	}
	return cpy
}
