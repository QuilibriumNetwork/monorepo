package utils

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	aliases "source.quilibrium.com/quilibrium/monorepo/alias"
	"source.quilibrium.com/quilibrium/monorepo/config"
)

var (
	NetworkConfigOverride  string
	DefaultNodeConfigName  = "node-quickstart"
	NodeServiceName        = "quilibrium-node"
	DefaultNodeServiceName = "quilibrium-node"
)

func GetPeerIDFromConfig(cfg *config.Config) peer.ID {
	peerPrivKey, err := hex.DecodeString(cfg.P2P.PeerPrivKey)
	if err != nil {
		panic(errors.Wrap(err, "error unmarshaling peerkey"))
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		panic(errors.Wrap(err, "error unmarshaling peerkey"))
	}

	pub := privKey.GetPublic()
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		panic(errors.Wrap(err, "error getting peer id"))
	}

	return id
}

func GetPrivKeyFromConfig(cfg *config.Config) (crypto.PrivKey, error) {
	peerPrivKey, err := hex.DecodeString(cfg.P2P.PeerPrivKey)
	if err != nil {
		panic(errors.Wrap(err, "error unmarshaling peerkey"))
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	return privKey, err
}

func IsExistingNodeVersion(version string) bool {
	return FileExists(filepath.Join(GetNodeBinaryDir(), version))
}

// GetNodeServiceName returns the user-configured systemd/launchd service name,
// falling back to DefaultNodeServiceName when unset or when the config cannot
// be read. It is used for Linux systemd unit operations; callers that must
// reference the fixed binary/package name (e.g. the /usr/local/bin symlink,
// the macOS launchd label, or cleanup of legacy logrotate configs)
// should continue to use DefaultNodeServiceName directly.
func GetNodeServiceName() string {
	cfg, err := LoadClientConfig()
	if err != nil || cfg == nil || cfg.NodeServiceName == "" {
		return DefaultNodeServiceName
	}
	return cfg.NodeServiceName
}

func CheckForSystemd() bool {
	// Check if systemctl command exists
	_, err := exec.LookPath("systemctl")
	return err == nil
}

// GetNodeConfigHomeDir is retained as a thin wrapper over
// GetNodeConfigsDir so older callers continue to compile. New code should
// call GetNodeConfigsDir directly.
func GetNodeConfigHomeDir() string {
	return GetNodeConfigsDir()
}

// GetDefaultNodeConfigSymlink returns the path of the "default" symlink that
// the node follows to locate its active configuration directory.
func GetDefaultNodeConfigSymlink() string {
	return filepath.Join(GetNodeConfigHomeDir(), "default")
}

func GetDefaultNodeConfigDir() (string, error) {
	name := DefaultNodeConfigName
	if NetworkConfigOverride != "" {
		name = NetworkConfigOverride
	}
	configPath := filepath.Join(GetNodeConfigHomeDir(), name)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// if it doesn't exist
		// check if the .config directory exists in the current working directory
		altConfigPath := filepath.Join(".", ".config")
		if _, err := os.Stat(altConfigPath); !os.IsNotExist(err) {
			return altConfigPath, nil
		}

		if NetworkConfigOverride != "" {
			return "", fmt.Errorf(
				"network config directory does not exist: %s", configPath,
			)
		}

		fmt.Printf("Default node config directory does not exist, creating it\n")
		// if neither exists, create it
		CreateDefaultNodeConfig(DefaultNodeConfigName)
		return configPath, nil
	}
	// Check if the config path is a symlink
	realPath, err := filepath.EvalSymlinks(configPath)
	if err != nil {
		// If there's an error evaluating symlinks, return the original path
		return configPath, err
	}
	// If it is a symlink, return the real path
	return realPath, nil
}

func LoadAliasStore(cfg *config.Config) (aliasStore *aliases.Store, err error) {
	if cfg.Alias != nil && cfg.Alias.AliasFile != nil &&
		cfg.Alias.AliasFile.Path != "" {
		aliasStore, err = aliases.Load(cfg.Alias.AliasFile.Path)
		if err != nil && cfg.Alias.AliasFile.CreateIfMissing {
			aliasStore, err = aliases.NewOnDisk(cfg.Alias.AliasFile.Path)
			if err != nil {
				return nil, errors.Wrap(err, "load alias store")
			}
		} else if err != nil {
			return nil, errors.Wrap(err, "load alias store")
		}
	}

	return aliasStore, err
}

func LoadDefaultNodeConfig() (*config.Config, error) {
	// check for the symlinked default config
	configDir, err := GetDefaultNodeConfigDir()
	if err != nil {
		return nil, err
	}

	return config.LoadConfig(configDir, "", false)
}

func LoadNodeConfig(configDirectory string) (*config.Config, error) {
	if configDirectory == "default" {
		return LoadDefaultNodeConfig()
	}

	resolved, err := ResolveNodeConfigDir(configDirectory)
	if err != nil {
		return nil, err
	}

	return config.LoadConfig(resolved, "", false)
}

// ResolveNodeConfigDir resolves the value passed to --config into an absolute
// filesystem path, without creating anything on disk. It accepts either a
// named config (looked up under ~/.quilibrium/configs/<name>) or a direct
// path (absolute or relative to the current working directory). The resolved
// directory must exist and contain both config.yml and keys.yml, otherwise an
// error is returned explaining what was checked.
func ResolveNodeConfigDir(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("config directory not specified")
	}

	namedPath := filepath.Join(GetNodeConfigHomeDir(), value)
	if info, err := os.Stat(namedPath); err == nil && info.IsDir() {
		if !HasNodeConfigFiles(namedPath) {
			return "", fmt.Errorf(
				"%s: %s", ErrNotValidConfigDirMessage, namedPath,
			)
		}
		return namedPath, nil
	}

	if info, err := os.Stat(value); err == nil {
		if !info.IsDir() {
			return "", fmt.Errorf(
				"config path is not a directory: %s", value,
			)
		}
		abs, err := filepath.Abs(value)
		if err != nil {
			abs = value
		}
		if !HasNodeConfigFiles(abs) {
			return "", fmt.Errorf(
				"%s: %s", ErrNotValidConfigDirMessage, abs,
			)
		}
		return abs, nil
	}

	return "", fmt.Errorf(
		"config directory not found: %q (looked for a named config at %s "+
			"and as a filesystem path)",
		value, namedPath,
	)
}

// HasNodeConfigFiles checks if a directory contains both config.yml and
// keys.yml files
func HasNodeConfigFiles(dirPath string) bool {
	configPath := filepath.Join(dirPath, "config.yml")
	keysPath := filepath.Join(dirPath, "keys.yml")

	// Check if both files exist
	configExists := false
	keysExists := false

	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		configExists = true
	}

	if _, err := os.Stat(keysPath); !os.IsNotExist(err) {
		keysExists = true
	}

	return configExists && keysExists
}

func SetDefaultNodeConfig(configName string) error {
	NodeConfigDir := GetNodeConfigHomeDir()
	configDir := filepath.Join(NodeConfigDir, configName)

	userLookup, err := GetCurrentSudoUser()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting current user: %v\n", err)
		os.Exit(1)
	}

	if err := ValidateAndCreateDir(configDir, userLookup); err != nil {
		return err
	}

	// Construct the source directory path
	sourceDir := filepath.Join(NodeConfigDir, configName)

	// Check if source directory exists
	if _, err := os.Stat(sourceDir); os.IsNotExist(err) {
		fmt.Printf("Config directory does not exist: %s\n", sourceDir)
		os.Exit(1)
	}

	// Check if the source directory has both config.yml and keys.yml files
	if !HasNodeConfigFiles(sourceDir) {
		fmt.Printf(ErrNotValidConfigDirMessage+": %s\n", sourceDir)
		os.Exit(1)
	}

	// Construct the default directory path
	defaultDir := filepath.Join(NodeConfigDir, "default")

	// Create the symlink
	if err := CreateSymlink(sourceDir, defaultDir); err != nil {
		fmt.Printf("Failed to create symlink: %s\n", err)
		os.Exit(1)
	}

	return nil
}

func CreateDefaultNodeConfig(name string) (*config.Config, error) {
	userLookup, err := GetCurrentSudoUser()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting current user: %v\n", err)
		os.Exit(1)
	}

	// create the config directory
	configsDir := GetNodeConfigHomeDir()
	configPath := filepath.Join(configsDir, name)
	ValidateAndCreateDir(configPath, userLookup)

	// create the default config files
	nodeConfig, err := config.LoadConfig(configPath, "", false)
	if err != nil {
		return nil, err
	}

	// make sure the config directory is owned by the current user
	ChownPath(configPath, userLookup, true)

	// now set the default config alias for use in qclient commands
	SetDefaultNodeConfig(name)

	return nodeConfig, nil
}
