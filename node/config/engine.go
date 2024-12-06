package config

import "time"

type FramePublishFragmentationReedSolomonConfig struct {
	// The number of data shards to use for Reed-Solomon encoding and decoding.
	DataShards int `yaml:"dataShards"`
	// The number of parity shards to use for Reed-Solomon encoding and decoding.
	ParityShards int `yaml:"parityShards"`
}

// WithDefaults sets default values for any fields that are not set.
func (c FramePublishFragmentationReedSolomonConfig) WithDefaults() FramePublishFragmentationReedSolomonConfig {
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

// WithDefaults sets default values for any fields that are not set.
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

// WithDefaults sets default values for any fields that are not set.
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
	// Sets the starting port number to use as the listen port for data worker
	// processes, incrementing by 1 until n-1, n = cores. (Example: a 4 core
	// system, base listen port of 40000 will listen on 40000, 40001, 40002)
	DataWorkerBaseListenPort uint16 `yaml:"dataWorkerBaseListenPort"`
	DataWorkerMemoryLimit    int64  `yaml:"dataWorkerMemoryLimit"`
	// Alternative configuration path to manually specify data workers by multiaddr
	DataWorkerMultiaddrs []string `yaml:"dataWorkerMultiaddrs"`
	// Number of data worker processes to spawn.
	DataWorkerCount               int      `yaml:"dataWorkerCount"`
	MultisigProverEnrollmentPaths []string `yaml:"multisigProverEnrollmentPaths"`
	// Fully verifies execution, omit to enable light prover
	FullProver bool `yaml:"fullProver"`
	// Automatically merges coins after minting once a sufficient number has been
	// accrued
	AutoMergeCoins bool `yaml:"autoMergeCoins"`
	// Maximum wait time for a frame to be downloaded from a peer.
	SyncTimeout time.Duration `yaml:"syncTimeout"`
	// Number of candidate peers per category to sync with.
	SyncCandidates int `yaml:"syncCandidates"`

	// Values used only for testing – do not override these in production, your
	// node will get kicked out
	Difficulty uint32 `yaml:"difficulty"`
	// Whether to allow GOMAXPROCS values above the number of physical cores.
	AllowExcessiveGOMAXPROCS bool `yaml:"allowExcessiveGOMAXPROCS"`

	// EXPERIMENTAL: The configuration for frame publishing.
	FramePublish FramePublishConfig `yaml:"framePublish"`
}
