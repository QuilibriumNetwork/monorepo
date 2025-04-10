package utils

type ClientConfig struct {
	DataDir        string `yaml:"dataDir"`
	SymlinkPath    string `yaml:"symlinkPath"`
	SignatureCheck bool   `yaml:"signatureCheck"`
}

type NodeConfig struct {
	ClientConfig
	RewardsAddress     string `yaml:"rewardsAddress"`
	AutoUpdateInterval string `yaml:"autoUpdateInterval"`
}

const (
	DefaultAutoUpdateInterval = "*/10 * * * *"
)

type ReleaseType string

const (
	ReleaseTypeQClient ReleaseType = "qclient"
	ReleaseTypeNode    ReleaseType = "node"
)
