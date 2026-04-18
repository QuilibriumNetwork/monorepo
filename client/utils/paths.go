package utils

import (
	"fmt"
	"os"
	"path/filepath"
)

// Default install-time paths. These are the values used when the client
// config does not specify an override. They intentionally match the
// original hard-coded locations so upgrading users see no behavior change.
const (
	DefaultNodeInstallDir = "/var/quilibrium"
	// DefaultNodeLogRelDir is the directory name for file logs under each
	// node config directory (the folder containing config.yml) when
	// logger.path is populated by qclient defaults.
	DefaultNodeLogRelDir = ".logs"
	DefaultNodeSymlinkDir = "/usr/local/bin"
	// DefaultNodeConfigsSubdir is the subdirectory of the user's home
	// directory where node configs live when no override is set.
	DefaultNodeConfigsSubdir = ".quilibrium/configs"
)

// loadConfigOrDefault returns the persisted client config, or a zero-value
// config if loading fails. Path accessors are best-effort: callers should
// always get a usable default even when the config file is missing or
// temporarily unreadable.
func loadConfigOrDefault() *ClientConfig {
	cfg, err := LoadClientConfig()
	if err != nil || cfg == nil {
		return &ClientConfig{}
	}
	return cfg
}

// GetNodeInstallDir returns the configured node install root, or the
// default /var/quilibrium when unset.
func GetNodeInstallDir() string {
	cfg := loadConfigOrDefault()
	if cfg.NodeInstallDir != "" {
		return cfg.NodeInstallDir
	}
	return DefaultNodeInstallDir
}

// GetNodeBinaryDir returns the directory that holds versioned node binary
// subdirectories, e.g. <install>/bin/node/.
func GetNodeBinaryDir() string {
	return filepath.Join(GetNodeInstallDir(), "bin", string(ReleaseTypeNode))
}

// GetNodeEnvFilePath returns the path to the systemd EnvironmentFile used
// by the node service, e.g. <install>/quilibrium.env.
func GetNodeEnvFilePath() string {
	return filepath.Join(GetNodeInstallDir(), "quilibrium.env")
}

// DefaultNodeLogDirForConfig returns the default logger directory for a
// node config located at configDir (the directory containing config.yml),
// i.e. <configDir>/.logs. This is the value qclient writes into the node
// config's logger.path when creating/installing a config.
func DefaultNodeLogDirForConfig(configDir string) string {
	return filepath.Join(configDir, DefaultNodeLogRelDir)
}

// GetNodeSymlinkDir returns the directory where the node binary symlink is
// created, defaulting to /usr/local/bin.
func GetNodeSymlinkDir() string {
	cfg := loadConfigOrDefault()
	if cfg.NodeSymlinkDir != "" {
		return cfg.NodeSymlinkDir
	}
	return DefaultNodeSymlinkDir
}

// GetNodeSymlinkPath returns the full path of the node binary symlink,
// e.g. /usr/local/bin/quilibrium-node. The symlink file name itself is
// always the fixed DefaultNodeServiceName so that existing shell usage
// of `quilibrium-node` keeps working regardless of the service name.
func GetNodeSymlinkPath() string {
	return filepath.Join(GetNodeSymlinkDir(), DefaultNodeServiceName)
}

// GetNodeConfigsDir returns the configured node configs directory, or the
// default $HOME/.quilibrium/configs resolved against the invoking (sudo)
// user's home. The directory is created on demand.
func GetNodeConfigsDir() string {
	cfg := loadConfigOrDefault()
	if cfg.NodeConfigsDir != "" {
		ensureDirExistsForSudoUser(cfg.NodeConfigsDir)
		return cfg.NodeConfigsDir
	}

	userLookup, err := GetCurrentSudoUser()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting current user: %v\n", err)
		os.Exit(1)
	}
	path := filepath.Join(userLookup.HomeDir, DefaultNodeConfigsSubdir)
	ensureDirExistsForSudoUser(path)
	return path
}

// ensureDirExistsForSudoUser creates the given path if missing, owned by
// the invoking sudo user when available.
func ensureDirExistsForSudoUser(path string) {
	if _, err := os.Stat(path); err == nil {
		return
	}
	userLookup, err := GetCurrentSudoUser()
	if err != nil {
		// Fall back to best-effort mkdir without chown.
		_ = os.MkdirAll(path, 0755)
		return
	}
	_ = ValidateAndCreateDir(path, userLookup)
}
