package utils

type ClientConfig struct {
	DataDir        string `yaml:"dataDir"`
	SymlinkPath    string `yaml:"symlinkPath"`
	SignatureCheck bool   `yaml:"signatureCheck"`
}

type NodeConfig struct {
	ClientConfig
	DataDir string
	User    string
}

type ReleaseType string

const (
	ReleaseTypeQClient ReleaseType = "qclient"
	ReleaseTypeNode    ReleaseType = "node"
)
