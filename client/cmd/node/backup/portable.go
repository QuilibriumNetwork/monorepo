package backup

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	nodeconfig "source.quilibrium.com/quilibrium/monorepo/config"
)

// pathMap is an ordered list of (old, new) path prefix substitutions
// used to translate absolute paths recorded on the backup source host
// to equivalent paths on the restore destination host. Order matters:
// more specific prefixes (longer) are applied before less specific
// ones so that a configs dir nested inside $HOME is rewritten via the
// configs-dir entry instead of the broader $HOME entry.
type pathMap struct {
	entries []pathMapEntry
}

type pathMapEntry struct {
	old string
	new string
}

func (m *pathMap) add(oldP, newP string) {
	oldP = strings.TrimRight(oldP, string(filepath.Separator))
	newP = strings.TrimRight(newP, string(filepath.Separator))
	if oldP == "" || newP == "" || oldP == newP {
		return
	}
	for _, e := range m.entries {
		if e.old == oldP {
			return
		}
	}
	m.entries = append(m.entries, pathMapEntry{old: oldP, new: newP})
}

// finalize sorts entries by descending length of the old prefix so
// longest-match wins during apply.
func (m *pathMap) finalize() {
	sort.SliceStable(m.entries, func(i, j int) bool {
		return len(m.entries[i].old) > len(m.entries[j].old)
	})
}

// apply returns (rewritten, true) if any prefix matched p, otherwise
// (p, false). Matching is by path component boundary: "/a/b" matches
// "/a/b" and "/a/b/c" but not "/a/boom".
func (m *pathMap) apply(p string) (string, bool) {
	if p == "" {
		return p, false
	}
	for _, e := range m.entries {
		if p == e.old {
			return e.new, true
		}
		if strings.HasPrefix(p, e.old+string(filepath.Separator)) ||
			strings.HasPrefix(p, e.old+"/") {
			rest := p[len(e.old):]
			return e.new + rest, true
		}
	}
	return p, false
}

// buildPathMap constructs the default automatic path map by diffing the
// manifest's recorded source-host paths against the destination host's
// equivalents, and then overlays the user-supplied --path-map flags.
// Returns the map plus the destination configDir for the restored
// config (used when rewriting the "files/" half of object keys).
func buildPathMap(mf *manifest, userMaps []string) (*pathMap, string, error) {
	pm := &pathMap{}

	dstConfigsDir := utils.GetNodeConfigsDir()
	dstConfigDir := filepath.Join(dstConfigsDir, mf.ConfigName)
	dstStateDir := utils.GetNodeStateDir()
	dstInstallDir := utils.GetNodeInstallDir()
	dstHome := currentHomeDir()

	// Per-config dir is the most specific entry and must win when the
	// old configs dir happened to be nested under the old home.
	if mf.ConfigDir != "" {
		pm.add(mf.ConfigDir, dstConfigDir)
	}
	if mf.ConfigsDir != "" {
		pm.add(mf.ConfigsDir, dstConfigsDir)
	}
	if mf.NodeStateDir != "" {
		pm.add(mf.NodeStateDir, dstStateDir)
	}
	if mf.NodeInstallDir != "" {
		pm.add(mf.NodeInstallDir, dstInstallDir)
	}
	if mf.Home != "" && dstHome != "" {
		pm.add(mf.Home, dstHome)
	}

	// User-supplied maps take precedence over auto-detected ones. We
	// achieve "precedence" by inserting them first and having apply()
	// be longest-match, but also by replacing any auto entry with the
	// same key.
	for _, raw := range userMaps {
		oldP, newP, err := parsePathMap(raw)
		if err != nil {
			return nil, "", err
		}
		// If the user overrides an auto entry, drop the auto one.
		filtered := pm.entries[:0]
		for _, e := range pm.entries {
			if e.old != oldP {
				filtered = append(filtered, e)
			}
		}
		pm.entries = filtered
		pm.add(oldP, newP)
	}

	pm.finalize()
	return pm, dstConfigDir, nil
}

// parsePathMap parses a single "OLD=NEW" argument.
func parsePathMap(raw string) (string, string, error) {
	idx := strings.Index(raw, "=")
	if idx <= 0 || idx == len(raw)-1 {
		return "", "", fmt.Errorf("expected OLD=NEW, got %q", raw)
	}
	oldP := strings.TrimSpace(raw[:idx])
	newP := strings.TrimSpace(raw[idx+1:])
	if !filepath.IsAbs(oldP) || !filepath.IsAbs(newP) {
		return "", "", fmt.Errorf("path-map entries must be absolute paths: %q", raw)
	}
	return oldP, newP, nil
}

// destPathFor returns the local filesystem destination for a given
// backup entry, honoring the configName-prefix-relative object key to
// remap files/ entries into the destination configDir, and applying
// prefix remapping to absolute/ entries.
//
// - Entries under "<prefix>/files/<rel>" land at
//   filepath.Join(dstConfigDir, rel).
// - Entries under "<prefix>/absolute/<abs-without-leading-slash>" are
//   run through the path map; unmapped paths fall back to LocalPath.
// - Version 1 manifests (no host context) always fall back to
//   LocalPath unless an entry is remapped by a user --path-map.
func destPathFor(mf *manifest, bf *backupFile, pm *pathMap, dstConfigDir string) (string, bool) {
	configName := strings.TrimSuffix(mf.ConfigName, "/")
	key := bf.ObjectKey

	// An optional bucket prefix may precede "<configName>/". Locate
	// the "<configName>/files/" or "<configName>/absolute/" segment
	// anywhere in the key so both prefixed and un-prefixed backups
	// classify correctly.
	filesMarker := "/" + configName + "/files/"
	if strings.HasPrefix(key, configName+"/files/") && mf.Version >= 2 {
		rel := strings.TrimPrefix(key, configName+"/files/")
		return filepath.Join(dstConfigDir, filepath.FromSlash(rel)), true
	}
	if idx := strings.Index(key, filesMarker); idx >= 0 && mf.Version >= 2 {
		rel := key[idx+len(filesMarker):]
		return filepath.Join(dstConfigDir, filepath.FromSlash(rel)), true
	}

	// For absolute/ entries, or for any entry in a v1 manifest, try
	// the prefix map against LocalPath.
	if mapped, ok := pm.apply(bf.LocalPath); ok {
		return mapped, true
	}
	return bf.LocalPath, false
}

// rewriteRestoredConfig opens the restored config.yml at configDir,
// rewrites any embedded absolute paths through pm, and saves it back.
// The rewrite only affects path-bearing fields (logger.path,
// alias.aliasFile.path, key.keyManagerFile.path, db.path,
// db.workerPaths, db.workerPathPrefix). Paths that do not match any
// mapping entry are left untouched so operator-pinned absolute paths
// outside the managed roots survive restore.
//
// Returns the list of fields that were actually changed (for human
// output), or a non-nil error if load/save fails. A missing config.yml
// is not an error: cross-platform restore may legitimately skip the
// config half.
func rewriteRestoredConfig(configDir string, pm *pathMap) ([]string, error) {
	cfgPath := filepath.Join(configDir, "config.yml")
	cfg, err := nodeconfig.NewConfig(cfgPath)
	if err != nil {
		return nil, err
	}

	var changed []string
	rewrite := func(label string, p *string) {
		if p == nil || *p == "" {
			return
		}
		if mapped, ok := pm.apply(*p); ok {
			*p = mapped
			changed = append(changed, label)
		}
	}

	if cfg.Logger != nil {
		rewrite("logger.path", &cfg.Logger.Path)
	}
	if cfg.Alias != nil && cfg.Alias.AliasFile != nil {
		rewrite("alias.aliasFile.path", &cfg.Alias.AliasFile.Path)
	}
	if cfg.Key != nil && cfg.Key.KeyStoreFile != nil {
		rewrite("key.keyManagerFile.path", &cfg.Key.KeyStoreFile.Path)
	}
	if cfg.DB != nil {
		rewrite("db.path", &cfg.DB.Path)
		rewrite("db.workerPathPrefix", &cfg.DB.WorkerPathPrefix)
		for i := range cfg.DB.WorkerPaths {
			rewrite(fmt.Sprintf("db.workerPaths[%d]", i), &cfg.DB.WorkerPaths[i])
		}
	}

	if len(changed) == 0 {
		return nil, nil
	}

	if err := nodeconfig.SaveConfig(configDir, cfg); err != nil {
		return nil, fmt.Errorf("save rewritten config: %w", err)
	}
	return changed, nil
}

// crossOSNote returns a short human-readable note to print when the
// source and destination OS differ, or an empty string otherwise.
func crossOSNote(mf *manifest) string {
	if mf.HostOS == "" || mf.HostOS == runtime.GOOS {
		return ""
	}
	return fmt.Sprintf("Cross-OS restore detected: backup taken on %s, restoring on %s",
		mf.HostOS, runtime.GOOS)
}
