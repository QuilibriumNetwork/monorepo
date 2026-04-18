package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Default install-time paths. These intentionally follow the FHS on
// Linux and Homebrew-style conventions on macOS so binaries, state,
// and symlinks land in the locations users expect for a system-wide
// install managed by sudo + systemd/launchd.
const (
	// LegacyNodeInstallDir is the pre-FHS-split install root. It is
	// kept only for detecting legacy installs so we can warn the user;
	// new installs should not land here.
	LegacyNodeInstallDir = "/var/quilibrium"

	// DefaultNodeLogRelDir is the directory name for file logs under
	// each node config directory (the folder containing config.yml)
	// when logger.path is populated by qclient defaults.
	DefaultNodeLogRelDir = ".logs"

	// DefaultNodeConfigsSubdir is the subdirectory of the user's home
	// directory where node configs live when no override is set.
	DefaultNodeConfigsSubdir = ".quilibrium/configs"
)

// DefaultNodeInstallDir returns the OS-appropriate default root for
// node binaries: /opt/quilibrium on Linux (FHS), /usr/local/quilibrium
// on macOS (Homebrew-style). Unknown GOOS falls back to the Linux
// default.
func DefaultNodeInstallDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/usr/local/quilibrium"
	default:
		return "/opt/quilibrium"
	}
}

// DefaultNodeStateDir returns the OS-appropriate default root for
// mutable node state (env file, future state/spool): /var/lib/quilibrium
// on Linux (FHS), /usr/local/var/quilibrium on macOS.
func DefaultNodeStateDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/usr/local/var/quilibrium"
	default:
		return "/var/lib/quilibrium"
	}
}

// DefaultNodeSymlinkDir returns the directory where the node symlink
// is created. /usr/local/bin on both Linux and macOS.
func DefaultNodeSymlinkDir() string {
	return "/usr/local/bin"
}

// DefaultQClientInstallDir returns the OS-appropriate default root for
// the qclient binary tree: /opt/quilibrium on Linux, /usr/local/quilibrium
// on macOS. Matches the node install root so both trees live together.
func DefaultQClientInstallDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/usr/local/quilibrium"
	default:
		return "/opt/quilibrium"
	}
}

// LegacyQClientBinaryDir is the pre-FHS-split qclient binary root. Kept
// only for detecting legacy installs so we can warn the user.
const LegacyQClientBinaryDir = "/var/quilibrium/bin/qclient"

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
// OS-appropriate default when unset.
func GetNodeInstallDir() string {
	cfg := loadConfigOrDefault()
	if cfg.NodeInstallDir != "" {
		return cfg.NodeInstallDir
	}
	return DefaultNodeInstallDir()
}

// GetNodeStateDir returns the configured node state root, or the
// OS-appropriate default when unset. The env file and any future
// mutable node state live here.
func GetNodeStateDir() string {
	cfg := loadConfigOrDefault()
	if cfg.NodeStateDir != "" {
		return cfg.NodeStateDir
	}
	return DefaultNodeStateDir()
}

// GetNodeBinaryDir returns the directory that holds versioned node binary
// subdirectories, e.g. <install>/bin/node/.
func GetNodeBinaryDir() string {
	return filepath.Join(GetNodeInstallDir(), "bin", string(ReleaseTypeNode))
}

// GetNodeEnvFilePath returns the path to the systemd EnvironmentFile
// used by the node service, e.g. <state>/quilibrium.env.
func GetNodeEnvFilePath() string {
	return filepath.Join(GetNodeStateDir(), "quilibrium.env")
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
	return DefaultNodeSymlinkDir()
}

// GetNodeSymlinkPath returns the full path of the node binary symlink,
// e.g. /usr/local/bin/quilibrium-node. The symlink file name itself is
// always the fixed DefaultNodeServiceName so that existing shell usage
// of `quilibrium-node` keeps working regardless of the service name.
func GetNodeSymlinkPath() string {
	return filepath.Join(GetNodeSymlinkDir(), DefaultNodeServiceName)
}

// GetQClientInstallDir returns the configured qclient install root.
// Resolution order: cfg.QClientInstallDir → legacy cfg.DataDir's parent
// (for back-compat with configs that pre-date QClientInstallDir and
// still pin DataDir to /var/quilibrium/bin/qclient) → OS-appropriate
// default.
func GetQClientInstallDir() string {
	cfg := loadConfigOrDefault()
	if cfg.QClientInstallDir != "" {
		return cfg.QClientInstallDir
	}
	// cfg.DataDir historically points at <install>/bin/qclient. If it
	// is set, reverse-derive the install root so existing configs
	// keep working without rewrites.
	if cfg.DataDir != "" {
		// Expect layout <install>/bin/qclient; strip the trailing
		// "bin/qclient" when present.
		dir := filepath.Clean(cfg.DataDir)
		parent := filepath.Dir(dir)          // <install>/bin
		grandparent := filepath.Dir(parent)  // <install>
		if filepath.Base(dir) == string(ReleaseTypeQClient) && filepath.Base(parent) == "bin" {
			return grandparent
		}
	}
	return DefaultQClientInstallDir()
}

// GetQClientBinaryDir returns the directory that holds versioned
// qclient binary subdirectories, e.g. <install>/bin/qclient.
func GetQClientBinaryDir() string {
	return filepath.Join(GetQClientInstallDir(), "bin", string(ReleaseTypeQClient))
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
		_ = os.MkdirAll(path, 0755)
		return
	}
	_ = ValidateAndCreateDir(path, userLookup)
}
