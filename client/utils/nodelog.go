package utils

import (
	"fmt"
	"os"
	"path/filepath"

	"source.quilibrium.com/quilibrium/monorepo/config"
)

// Default rotation knobs used when qclient populates a node config's
// logger block at create/install time. These are safe middle-of-the-road
// values — users can override them with `qclient node config set
// logger.maxSize 50` etc.
const (
	DefaultLoggerMaxSize    = 100 // megabytes per file before rotation
	DefaultLoggerMaxBackups = 5   // rotated files to keep
	DefaultLoggerMaxAge     = 30  // days to keep rotated files
	DefaultLoggerCompress   = true
)

// ResolvedNodeLog describes where a given node config writes its logs.
// When FileBased is false, the node is logging to stdout and callers
// should fall back to the system log (journalctl on Linux, launchd
// StandardOutPath on macOS).
type ResolvedNodeLog struct {
	// ConfigName is the name of the node config (e.g. "node-quickstart")
	// whose logger block was resolved. Empty for an ad-hoc path.
	ConfigName string
	// ConfigDir is the absolute directory of the node config this
	// resolution is for (contains config.yml).
	ConfigDir string
	// FileBased is true when the node config has a logger block with a
	// non-empty path; callers can then read LogDir / MasterLogFile.
	FileBased bool
	// LogDir is the logger.path from the node config. Valid only when
	// FileBased is true.
	LogDir string
}

// MasterLogFile returns the conventional path to the node's primary
// (coreId=0) log file inside LogDir, matching what the node's logger
// actually writes (utils/logging.filenameForCore).
func (r ResolvedNodeLog) MasterLogFile() string {
	if !r.FileBased {
		return ""
	}
	return filepath.Join(r.LogDir, "master.log")
}

// ResolveActiveNodeLog resolves the log destination for the node's
// currently-active (default) config. It never creates or mutates files
// on disk; if the default config isn't present it returns an error.
func ResolveActiveNodeLog() (ResolvedNodeLog, error) {
	dir, err := GetDefaultNodeConfigDir()
	if err != nil {
		return ResolvedNodeLog{}, err
	}
	return resolveNodeLogForDir(dir)
}

// ResolveNodeLogByName resolves the log destination for the named node
// config under the configs directory.
func ResolveNodeLogByName(name string) (ResolvedNodeLog, error) {
	dir := filepath.Join(GetNodeConfigHomeDir(), name)
	if _, err := os.Stat(dir); err != nil {
		return ResolvedNodeLog{}, fmt.Errorf(
			"node config %q not found at %s", name, dir,
		)
	}
	return resolveNodeLogForDir(dir)
}

// ResolveAllNodeLogDirs returns every log directory referenced by an
// installed node config that currently has a logger block. This is used
// by uninstall/clean helpers that need to sweep log files across every
// known config.
func ResolveAllNodeLogDirs() []string {
	configsDir := GetNodeConfigHomeDir()
	entries, err := os.ReadDir(configsDir)
	if err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	dirs := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "default" {
			continue
		}
		resolved, err := resolveNodeLogForDir(filepath.Join(configsDir, e.Name()))
		if err != nil || !resolved.FileBased {
			continue
		}
		if _, ok := seen[resolved.LogDir]; ok {
			continue
		}
		seen[resolved.LogDir] = struct{}{}
		dirs = append(dirs, resolved.LogDir)
	}
	return dirs
}

func resolveNodeLogForDir(configDir string) (ResolvedNodeLog, error) {
	abs, err := filepath.EvalSymlinks(configDir)
	if err != nil {
		abs = configDir
	}
	name := filepath.Base(abs)

	cfg, err := config.NewConfig(filepath.Join(abs, "config.yml"))
	if err != nil {
		return ResolvedNodeLog{
			ConfigName: name,
			ConfigDir:  abs,
			FileBased:  false,
		}, nil
	}
	if cfg == nil || cfg.Logger == nil || cfg.Logger.Path == "" {
		return ResolvedNodeLog{
			ConfigName: name,
			ConfigDir:  abs,
			FileBased:  false,
		}, nil
	}
	return ResolvedNodeLog{
		ConfigName: name,
		ConfigDir:  abs,
		FileBased:  true,
		LogDir:     cfg.Logger.Path,
	}, nil
}

// EnsureNodeConfigLogger makes sure the config.yml at configDir has a
// logger block pointing at DefaultNodeLogDirForConfig(configDir). If a
// logger block already exists, the function leaves it untouched and
// returns the existing path. The returned boolean reports whether the
// config was modified on disk.
func EnsureNodeConfigLogger(configDir string) (string, bool, error) {
	abs, err := filepath.EvalSymlinks(configDir)
	if err != nil {
		abs = configDir
	}

	cfg, err := config.NewConfig(filepath.Join(abs, "config.yml"))
	if err != nil {
		return "", false, fmt.Errorf("loading node config at %s: %w", abs, err)
	}
	if cfg.Logger != nil && cfg.Logger.Path != "" {
		return cfg.Logger.Path, false, nil
	}
	if cfg.Logger == nil {
		cfg.Logger = &config.LogConfig{}
	}
	cfg.Logger.Path = DefaultNodeLogDirForConfig(abs)
	if cfg.Logger.MaxSize == 0 {
		cfg.Logger.MaxSize = DefaultLoggerMaxSize
	}
	if cfg.Logger.MaxBackups == 0 {
		cfg.Logger.MaxBackups = DefaultLoggerMaxBackups
	}
	if cfg.Logger.MaxAge == 0 {
		cfg.Logger.MaxAge = DefaultLoggerMaxAge
	}
	if !cfg.Logger.Compress {
		cfg.Logger.Compress = DefaultLoggerCompress
	}

	if err := config.SaveConfig(abs, cfg); err != nil {
		return "", false, fmt.Errorf("saving node config at %s: %w", abs, err)
	}
	return cfg.Logger.Path, true, nil
}
