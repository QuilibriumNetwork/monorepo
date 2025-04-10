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

		fmt.Fprintf(os.Stdout, "Updating Quilibrium node for %s-%s, version: %s\n", OsType, Arch, version)

		// Update the node
		updateNode(version)
	},
}

func init() {

}

// updateNode handles the node update process
func updateNode(version string) {
	// Check if we need sudo privileges
	if err := utils.CheckAndRequestSudo(fmt.Sprintf("Updating node at %s requires root privileges", utils.NodeDataPath)); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	// Create new binary version directory
	versionDataDir := filepath.Join(utils.NodeDataPath, version)
	if err := utils.ValidateAndCreateDir(versionDataDir, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating data directory: %v\n", err)
		return
	}

	// Construct the expected filename for the specified version
	// Remove 'v' prefix if present for filename construction
	versionWithoutV := strings.TrimPrefix(version, "v")

	if IsExistingNodeVersion(versionWithoutV) {
		fmt.Fprintf(os.Stderr, "Error: Node version %s already exists\n", versionWithoutV)
		os.Exit(1)
	}

	// Download the release directly
	err := utils.DownloadRelease(utils.ReleaseTypeNode, versionWithoutV)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading version %s: %v\n", version, err)
		fmt.Fprintf(os.Stderr, "The specified version %s does not exist for %s-%s\n", version, OsType, Arch)
		// Clean up the created directories since installation failed
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
	finishInstallation(version)
}
