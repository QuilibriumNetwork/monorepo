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
	// QClientInstallDir is the root directory for the qclient binary
	// tree. Defaults to /opt/quilibrium on Linux and
	// /usr/local/quilibrium on macOS. Binaries live under
	// <QClientInstallDir>/bin/qclient/<version>/. When empty, the
	// legacy cfg.DataDir is consulted for back-compat.
	QClientInstallDir string `yaml:"qclientInstallDir"`
	// NodeInstallDir is the root directory for the node binary tree.
	// Defaults to /opt/quilibrium on Linux and /usr/local/quilibrium on
	// macOS. The actual binaries live under
	// <NodeInstallDir>/bin/node/<version>/.
	NodeInstallDir string `yaml:"nodeInstallDir"`
	// NodeStateDir is the root directory for mutable node state
	// (currently the systemd EnvironmentFile). Defaults to
	// /var/lib/quilibrium on Linux and /usr/local/var/quilibrium on
	// macOS.
	NodeStateDir string `yaml:"nodeStateDir"`
	// NodeSymlinkDir is the directory where the node binary symlink
	// (quilibrium-node) is created. Defaults to /usr/local/bin.
	NodeSymlinkDir string `yaml:"nodeSymlinkDir"`
	// NodeConfigsDir is the directory that holds named node configs.
	// Defaults to $HOME/.quilibrium/configs (resolved from the invoking
	// sudo user's home directory).
	NodeConfigsDir string `yaml:"nodeConfigsDir"`

	// Backup holds S3-compatible node backup settings. Populate via
	// `qclient node backup config`.
	Backup NodeBackupConfig `yaml:"backup"`
}

// NodeBackupConfig holds S3-compatible object storage settings used by
// `qclient node backup`. Credentials are stored alongside the rest of
// the qclient configuration.
type NodeBackupConfig struct {
	Enabled         bool   `yaml:"enabled"`
	AccessKeyID     string `yaml:"accessKeyId"`
	SecretAccessKey string `yaml:"secretAccessKey"`
	Endpoint        string `yaml:"endpoint"`
	Bucket          string `yaml:"bucket"`
	// BucketPrefix is an optional key prefix inside the bucket, used
	// when the bucket is shared with other data and backups should be
	// namespaced (e.g. "quilibrium/backups"). All object keys and the
	// per-config manifest are written under this prefix. Leading and
	// trailing slashes are tolerated on input and normalized away.
	// Empty means "store at the bucket root" (current behavior).
	BucketPrefix string `yaml:"bucketPrefix"`
	Region       string `yaml:"region"`
	// UsePathStyle controls S3 path-style addressing
	// (bucket.host vs host/bucket). Most S3-compatible providers
	// require path-style; defaults to true.
	UsePathStyle bool `yaml:"usePathStyle"`
}

// Default values for NodeBackupConfig.
const (
	DefaultBackupEndpoint     = "https://qstorage.quilibrium.com"
	DefaultBackupRegion       = "q-world-1"
	DefaultBackupUsePathStyle = true
)

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
