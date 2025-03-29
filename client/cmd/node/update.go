package node

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

// updateNodeCmd represents the command to update the Quilibrium node
var updateNodeCmd = &cobra.Command{
	Use:   "update [version]",
	Short: "Update Quilibrium node",
	Long: `Update Quilibrium node to a specified version or the latest version.
If no version is specified, the latest version will be installed.

Examples:
  # Update to the latest version
  qclient node update

  # Update to a specific version
  qclient node update 2.1.0`,
	Args: cobra.RangeArgs(0, 1),
	Run: func(cmd *cobra.Command, args []string) {
		// Get system information and validate

		// Determine version to install
		version := determineVersion(args)

		fmt.Fprintf(os.Stdout, "Updating Quilibrium node for %s-%s, version: %s\n", osType, arch, version)

		// Update the node
		updateNode(version)
	},
}

func init() {

}

// updateNode handles the node update process
func updateNode(version string) {
	// Check if we need sudo privileges
	if err := utils.CheckAndRequestSudo(fmt.Sprintf("Updating node at %s requires root privileges", installPath)); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	// Create version-specific installation directory
	versionDir := filepath.Join(installPath, "node", version)
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating installation directory: %v\n", err)
		return
	}

	// Create data directory
	versionDataDir := filepath.Join(dataPath, "node", version)
	if err := os.MkdirAll(versionDataDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating data directory: %v\n", err)
		return
	}

	// Construct the expected filename for the specified version
	// Remove 'v' prefix if present for filename construction
	versionWithoutV := strings.TrimPrefix(version, "v")
	fileName := fmt.Sprintf("node-%s-%s-%s", versionWithoutV, osType, arch)

	// Download the release directly
	nodeBinaryPath := filepath.Join(dataPath, version, fileName)
	err := utils.DownloadRelease(utils.ReleaseTypeNode, versionWithoutV)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading version %s: %v\n", version, err)
		fmt.Fprintf(os.Stderr, "The specified version %s does not exist for %s-%s\n", version, osType, arch)
		// Clean up the created directories since installation failed
		os.RemoveAll(versionDir)
		os.RemoveAll(versionDataDir)
		return
	}

	// Download signature files
	if err := utils.DownloadReleaseSignatures(utils.ReleaseTypeNode, versionWithoutV); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to download signature files: %v\n", err)
		fmt.Fprintf(os.Stdout, "Continuing with installation...\n")
	}

	// Ensure log rotation is set up
	if err := setupLogRotation(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to set up log rotation: %v\n", err)
	}

	// Successfully downloaded the specific version
	finishInstallation(nodeBinaryPath, version)
}
