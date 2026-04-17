package utils

type ClientConfig struct {
	DataDir         string `yaml:"dataDir"`
	SymlinkPath     string `yaml:"symlinkPath"`
	SignatureCheck  bool   `yaml:"signatureCheck"`
	Quiet           bool   `yaml:"quiet"`
	PublicRpc       bool   `yaml:"publicRpc"`
	CustomRpc       string `yaml:"customRpc"`
	NodeSymlinkName string `yaml:"nodeSymlinkName"`
	NodeServiceName string `yaml:"nodeServiceName"`
	// NodeInstallDir is the root directory for the node binary tree and
	// environment file. Defaults to /var/quilibrium. The actual binaries
	// live under <NodeInstallDir>/bin/node/<version>/.
	NodeInstallDir string `yaml:"nodeInstallDir"`
	// NodeLogDir is the directory where node logs are written and rotated.
	// Defaults to /var/log/quilibrium.
	NodeLogDir string `yaml:"nodeLogDir"`
	// NodeSymlinkDir is the directory where the node binary symlink
	// (quilibrium-node) is created. Defaults to /usr/local/bin.
	NodeSymlinkDir string `yaml:"nodeSymlinkDir"`
	// NodeConfigsDir is the directory that holds named node configs.
	// Defaults to $HOME/.quilibrium/configs (resolved from the invoking
	// sudo user's home directory).
	NodeConfigsDir string `yaml:"nodeConfigsDir"`
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

type BridgedPeerJson struct {
	Amount     string `json:"amount"`
	Identifier string `json:"identifier"`
	Variant    string `json:"variant"`
}

type FirstRetroJson struct {
	PeerId string `json:"peerId"`
	Reward string `json:"reward"`
}

type SecondRetroJson struct {
	PeerId      string `json:"peerId"`
	Reward      string `json:"reward"`
	JanPresence bool   `json:"janPresence"`
	FebPresence bool   `json:"febPresence"`
	MarPresence bool   `json:"marPresence"`
	AprPresence bool   `json:"aprPresence"`
	MayPresence bool   `json:"mayPresence"`
}

type ThirdRetroJson struct {
	PeerId string `json:"peerId"`
	Reward string `json:"reward"`
}

type FourthRetroJson struct {
	PeerId string `json:"peerId"`
	Reward string `json:"reward"`
}
