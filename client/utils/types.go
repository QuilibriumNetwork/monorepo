package utils

type ClientConfig struct {
	Version     string
	DataDir     string
	SymlinkPath string
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
