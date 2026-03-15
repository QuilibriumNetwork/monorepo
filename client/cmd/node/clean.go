package node

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var (
	cleanAll  bool
	cleanLogs bool
	cleanNode bool
)

// CleanCmd represents the clean command
var NodeCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Clean old node files",
	Long: `Clean old versions of the node, signatures, and logs.

This command provides utilities for cleaning up your Quilibrium node:
- Remove old logs
- Remove old node binary versions and signatures
- Remove all of the above

Examples:
    qclient node clean --logs # remove just the logs
    qclient node clean --node # remove all old node binary versions, including signatures
    qclient node clean --all # remove all logs, old node binaries and signatures

To remove the current version of the node, use 'qclient node uninstall'`,
	Run: func(cmd *cobra.Command, args []string) {
		if !cleanAll && !cleanLogs && !cleanNode {
			cmd.Help()
			return
		}

		if cleanAll || cleanLogs {
			cleanNodeLogs()
		}

		if cleanAll || cleanNode {
			cleanNodeBinaries()
		}
	},
}

// cleanNodeLogs removes all log files from the node's log directory
func cleanNodeLogs() {
	if err := utils.CheckAndRequestSudo("Cleaning logs requires root privileges"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	logDir := utils.LogPath
	entries, err := os.ReadDir(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No logs directory found.")
		} else {
			fmt.Fprintf(os.Stderr, "Error reading log directory: %v\n", err)
		}
		return
	}

	removed := 0
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".log") || strings.HasSuffix(name, ".log.gz") {
			path := filepath.Join(logDir, name)
			if err := os.Remove(path); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not remove %s: %v\n", name, err)
				continue
			}
			removed++
		}
	}

	fmt.Printf("Removed %d log file(s) from %s\n", removed, logDir)
}

// cleanNodeBinaries removes old node binary versions and signatures,
// keeping the currently symlinked version.
func cleanNodeBinaries() {
	if err := utils.CheckAndRequestSudo("Cleaning binaries requires root privileges"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	// Determine which version is currently active via the symlink
	currentVersion := ""
	target, err := os.Readlink(utils.DefaultNodeSymlinkPath)
	if err == nil {
		// target looks like /var/quilibrium/bin/node/<version>/node-<version>-<os>-<arch>
		dir := filepath.Dir(target)
		currentVersion = filepath.Base(dir)
	}

	entries, err := os.ReadDir(utils.NodeDataPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No node binaries directory found.")
		} else {
			fmt.Fprintf(os.Stderr, "Error reading binary directory: %v\n", err)
		}
		return
	}

	removed := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if entry.Name() == currentVersion {
			continue
		}
		path := filepath.Join(utils.NodeDataPath, entry.Name())
		if err := os.RemoveAll(path); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not remove %s: %v\n", entry.Name(), err)
			continue
		}
		removed++
	}

	fmt.Printf("Removed %d old version(s) from %s\n", removed, utils.NodeDataPath)
	if currentVersion != "" {
		fmt.Printf("Kept current version: %s\n", currentVersion)
	}
}

// RemoveNodeBinary removes a specific version's binary directory.
func RemoveNodeBinary(version string) error {
	// Determine which version is currently active via the symlink
	target, err := os.Readlink(utils.DefaultNodeSymlinkPath)
	if err == nil {
		dir := filepath.Dir(target)
		currentVersion := filepath.Base(dir)
		if version == currentVersion {
			return fmt.Errorf("cannot remove currently active version %s; use 'node uninstall' instead", version)
		}
	}

	versionDir := filepath.Join(utils.NodeDataPath, version)
	if _, err := os.Stat(versionDir); os.IsNotExist(err) {
		return fmt.Errorf("version %s not found in %s", version, utils.NodeDataPath)
	}

	return os.RemoveAll(versionDir)
}

func init() {
	NodeCleanCmd.Flags().BoolVar(&cleanAll, "all", false, "Remove all logs, old node binaries and signatures")
	NodeCleanCmd.Flags().BoolVar(&cleanLogs, "logs", false, "Remove all logs")
	NodeCleanCmd.Flags().BoolVar(&cleanNode, "node", false, "Remove all old node binary versions, including signatures")
}
