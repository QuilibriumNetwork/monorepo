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
