package node

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var (
	Version string
)

// NodeLinkCmd represents the command to manage node binary symlinks
var NodeLinkCmd = &cobra.Command{
	Use:   "link",
	Short: "Create a symlink for a specific node version",
	Long: `Create a symlink for a specific node version in /usr/local/bin/.
If no version is provided, it will use the latest version found.

Examples:
  # Link the latest version downloaded
  qclient node link

  # Link a specific version
  qclient node link --version 2.1.0
`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			Version = args[0]
		} else {
			Version = "latest"
		}

		if err := NodeCreateSymlink(); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating symlink: %v\n", err)
			os.Exit(1)
		}
	},
}

// createNodeSymlink creates a symlink for the node binary in /usr/local/bin/
func NodeCreateSymlink() error {

	if Version == "latest" {
		// Find the highest version number in the node binary directory
		latestVersion, err := findLatestNodeVersion()
		if err != nil {
			return fmt.Errorf("failed to find latest node version: %w", err)
		}

		if latestVersion == "" {
			return fmt.Errorf("no node versions found in %s", utils.NodeDataPath)
		}
		Version = latestVersion
	}

	// Construct the path to the binary with the highest version
	normalizedBinaryName := fmt.Sprintf("node-%s-%s-%s", Version, OsType, Arch)
	nodeBinaryPath := filepath.Join(utils.NodeDataPath, Version, normalizedBinaryName)

	// Check if the binary exists
	if _, err := os.Stat(nodeBinaryPath); os.IsNotExist(err) {
		return fmt.Errorf("node binary not found at %s", nodeBinaryPath)
	}

	// Check if we need sudo privileges for creating symlink in system directory
	symlinkPath := filepath.Join("/usr/local/bin", utils.NodeServiceName)
	if err := utils.CheckAndRequestSudo(fmt.Sprintf("Creating symlink at %s requires root privileges", symlinkPath)); err != nil {
		return fmt.Errorf("failed to get sudo privileges: %w", err)
	}

	// Create symlink using the utils package
	if err := utils.CreateSymlink(nodeBinaryPath, symlinkPath); err != nil {
		return fmt.Errorf("failed to create symlink: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Created symlink for node binary version %s at %s\n", Version, symlinkPath)
	return nil
}

// findHighestNodeVersion finds the highest version number in the node binary directory
func findLatestNodeVersion() (string, error) {
	// Read the directory contents
	entries, err := os.ReadDir(utils.NodeDataPath)
	if err != nil {
		return "", fmt.Errorf("failed to read node data directory %s: %w", utils.NodeDataPath, err)
	}

	var versions []string
	for _, entry := range entries {
		if entry.IsDir() {
			versions = append(versions, entry.Name())
		}
	}

	if len(versions) == 0 {
		return "", nil
	}

	// Sort versions to find the highest one
	sort.Slice(versions, func(i, j int) bool {
		return compareVersions(versions[i], versions[j]) < 0
	})

	return versions[len(versions)-1], nil
}

// compareVersions compares two version strings
func compareVersions(v1, v2 string) int {
	v1Parts := strings.Split(strings.TrimPrefix(v1, "v"), ".")
	v2Parts := strings.Split(strings.TrimPrefix(v2, "v"), ".")

	for i := 0; i < len(v1Parts) && i < len(v2Parts); i++ {
		num1, err1 := strconv.Atoi(v1Parts[i])
		num2, err2 := strconv.Atoi(v2Parts[i])

		if err1 != nil || err2 != nil {
			return strings.Compare(v1Parts[i], v2Parts[i])
		}

		if num1 != num2 {
			return num1 - num2
		}
	}

	return len(v1Parts) - len(v2Parts)
}

func init() {
	// Add version flag to the command
	NodeLinkCmd.Flags().StringVarP(&Version, "version", "v", "highest", "Display the version of the node binary")
}
