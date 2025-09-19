package config

import "time"

const (
	defaultMinimumPeersRequired               = 3
	priorDefaultDataWorkerBaseListenMultiaddr = "/ip4/127.0.0.1/tcp/%d"
	defaultDataWorkerBaseListenMultiaddr      = "/ip4/0.0.0.0/tcp/%d"
	defaultDataWorkerBaseP2PPort              = uint16(50000)
	defaultDataWorkerBaseStreamPort           = uint16(60000)
	defaultDataWorkerMemoryLimit              = int64(1792 * 1024 * 1024) // 1.75 GiB
	defaultSyncTimeout                        = 4 * time.Second
	defaultSyncCandidates                     = 8
	defaultSyncMessageReceiveLimit            = 1 * 1024 * 1024
	defaultSyncMessageSendLimit               = 600 * 1024 * 1024
	defaultRewardStrategy                     = "reward-greedy"
)

type FramePublishFragmentationReedSolomonConfig struct {
	// The number of data shards to use for Reed-Solomon encoding and decoding.
	DataShards int `yaml:"dataShards"`
	// The number of parity shards to use for Reed-Solomon encoding and decoding.
	ParityShards int `yaml:"parityShards"`
}

// WithDefaults returns a copy of the FramePublishFragmentationReedSolomonConfig
// with any missing fields set to
// their default values.
func (
	c FramePublishFragmentationReedSolomonConfig,
) WithDefaults() FramePublishFragmentationReedSolomonConfig {
	cpy := c
	if cpy.DataShards == 0 {
		cpy.DataShards = 224
	}
	if cpy.ParityShards == 0 {
		cpy.ParityShards = 32
	}
	return cpy
}

type FramePublishFragmentationConfig struct {
	// The algorithm to use for fragmenting and reassembling frames.
	// Options: "reed-solomon".
	Algorithm string `yaml:"algorithm"`
	// The configuration for Reed-Solomon fragmentation.
	ReedSolomon FramePublishFragmentationReedSolomonConfig `yaml:"reedSolomon"`
}

// WithDefaults returns a copy of the FramePublishFragmentationConfig with any
// missing fields set to their default values.
func (c FramePublishFragmentationConfig) WithDefaults() FramePublishFragmentationConfig {
	cpy := c
	if cpy.Algorithm == "" {
		cpy.Algorithm = "reed-solomon"
	}
	cpy.ReedSolomon = cpy.ReedSolomon.WithDefaults()
	return cpy
}

type FramePublishConfig struct {
	// The publish mode to use for the node.
	// Options: "full", "fragmented", "dual", "threshold".
	Mode string `yaml:"mode"`
	// The threshold for switching between full and fragmented frame publishing.
	Threshold int `yaml:"threshold"`
	// The configuration for frame fragmentation.
	Fragmentation FramePublishFragmentationConfig `yaml:"fragmentation"`
	// The size of the ballast added to a frame.
	// NOTE: This option exists solely for testing purposes and should not be
	// modified in production.
	BallastSize int `yaml:"ballastSize"`
}

// WithDefaults returns a copy of the FramePublishConfig with any missing fields
// set to their default values.
func (c FramePublishConfig) WithDefaults() FramePublishConfig {
	cpy := c
	if cpy.Mode == "" {
		cpy.Mode = "full"
	}
	if cpy.Threshold == 0 {
		cpy.Threshold = 1 * 1024 * 1024
	}
	cpy.Fragmentation = cpy.Fragmentation.WithDefaults()
	return cpy
}

type EngineConfig struct {
	ProvingKeyId         string `yaml:"provingKeyId"`
	Filter               string `yaml:"filter"`
	GenesisSeed          string `yaml:"genesisSeed"`
	MaxFrames            int64  `yaml:"maxFrames"`
	PendingCommitWorkers int64  `yaml:"pendingCommitWorkers"`
	MinimumPeersRequired int    `yaml:"minimumPeersRequired"`
	StatsMultiaddr       string `yaml:"statsMultiaddr"`
	// Sets the fmt.Sprintf format string to use as the listen multiaddrs for
	// data worker processes
	DataWorkerBaseListenMultiaddr string `yaml:"dataWorkerBaseListenMultiaddr"`
	// Sets the starting port number to use as the p2p port for data worker
	// processes, incrementing by 1 until n-1, n = cores.
	DataWorkerBaseP2PPort uint16 `yaml:"dataWorkerBaseP2PPort"`
	// Sets the starting port number to use as the stream port for data worker
	// processes, incrementing by 1 until n-1, n = cores.
	DataWorkerBaseStreamPort uint16 `yaml:"dataWorkerBaseStreamPort"`
	DataWorkerMemoryLimit    int64  `yaml:"dataWorkerMemoryLimit"`
	// Configuration to specify data worker p2p multiaddrs
	DataWorkerP2PMultiaddrs []string `yaml:"dataWorkerP2PMultiaddrs"`
	// Configuration to specify data worker stream multiaddrs
	DataWorkerStreamMultiaddrs []string `yaml:"dataWorkerStreamMultiaddrs"`
	// Number of data worker processes to spawn.
	DataWorkerCount int `yaml:"dataWorkerCount"`
	// Specific shard filters for the data workers.
	DataWorkerFilters             []string `yaml:"dataWorkerFilters"`
	MultisigProverEnrollmentPaths []string `yaml:"multisigProverEnrollmentPaths"`
	// Maximum wait time for a frame to be downloaded from a peer.
	SyncTimeout time.Duration `yaml:"syncTimeout"`
	// Number of candidate peers per category to sync with.
	SyncCandidates int `yaml:"syncCandidates"`
	// The configuration for the GRPC message limits.
	SyncMessageLimits GRPCMessageLimitsConfig `yaml:"syncMessageLimits"`
	// Enable proxy traffic from worker processes through master process
	EnableMasterProxy bool `yaml:"enableMasterProxy"`
	// Reward strategy: "reward-greedy" or "data-greedy"
	RewardStrategy string `yaml:"rewardStrategy"`
	// Archive mode: whether to hold historic frame data
	ArchiveMode bool `yaml:"archiveMode"`
	// Delegate address for rewards (hexadecimal string without 0x prefix)
	DelegateAddress string `yaml:"delegateAddress"`
	// Whether to allow GOMAXPROCS values above the number of physical cores.
	AllowExcessiveGOMAXPROCS bool `yaml:"allowExcessiveGOMAXPROCS"`
	// Blacklisted addresses
	Blacklist []string `yaml:"blacklist"`
	// Alert public key
	AlertKey string `yaml:"alertKey"`

	// Values used only for testing – do not override these in production, your
	// node will get kicked out
	Difficulty uint32
	// Hypergraph rebuild range start
	RebuildStart string
	// Hypergraph rebuild range end
	RebuildEnd string

	// EXPERIMENTAL: The configuration for frame publishing.
	FramePublish FramePublishConfig `yaml:"framePublish"`
}

// WithDefaults returns a copy of the EngineConfig with any missing fields set
// to their default values.
func (c EngineConfig) WithDefaults() EngineConfig {
	cpy := c
	if cpy.MinimumPeersRequired == 0 {
		cpy.MinimumPeersRequired = defaultMinimumPeersRequired
	}
	if cpy.DataWorkerBaseListenMultiaddr == "" ||
		cpy.DataWorkerBaseListenMultiaddr == priorDefaultDataWorkerBaseListenMultiaddr {
		cpy.DataWorkerBaseListenMultiaddr = defaultDataWorkerBaseListenMultiaddr
	}
	if cpy.DataWorkerBaseP2PPort == 0 {
		cpy.DataWorkerBaseP2PPort = defaultDataWorkerBaseP2PPort
	}
	if cpy.DataWorkerBaseStreamPort == 0 {
		cpy.DataWorkerBaseStreamPort = defaultDataWorkerBaseStreamPort
	}
	if cpy.DataWorkerMemoryLimit == 0 {
		cpy.DataWorkerMemoryLimit = defaultDataWorkerMemoryLimit
	}
	if cpy.SyncTimeout == 0 {
		cpy.SyncTimeout = defaultSyncTimeout
	}
	if cpy.SyncCandidates == 0 {
		cpy.SyncCandidates = defaultSyncCandidates
	}
	if cpy.RewardStrategy == "" {
		cpy.RewardStrategy = defaultRewardStrategy
	}
	cpy.SyncMessageLimits = cpy.SyncMessageLimits.WithDefaults(
		defaultSyncMessageReceiveLimit,
		defaultSyncMessageSendLimit,
	)
	cpy.FramePublish = cpy.FramePublish.WithDefaults()
	if cpy.Blacklist == nil {
		cpy.Blacklist = []string{}
	}
	if cpy.AlertKey == "" {
		cpy.AlertKey = "3ade80f96515e34caaf0c346b842d1f82d2841840f27e12826f4c14326a6bd15d13796c0421f8c440809fceb66c0a5c3c88f93deae16ee3100"
	}
	return cpy
}
