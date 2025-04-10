package node

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

// installCmd represents the command to install the Quilibrium node
var installCmd = &cobra.Command{
	Use:   "install [version]",
	Short: "Install Quilibrium node",
	Long: `Install Quilibrium node binary.
If no version is specified, the latest version will be installed.


Examples:
  # Install the latest version
  qclient node install

  # Install a specific version
  qclient node install 2.1.0

  # Install without creating a dedicated user
  qclient node install --no-create-user`,
	Args: cobra.RangeArgs(0, 1),
	Run: func(cmd *cobra.Command, args []string) {
		// Get system information and validate
		osType, arch, err := utils.GetSystemInfo()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}

		if !utils.IsSudo() {
			fmt.Println("This command must be run with sudo: sudo qclient node install")
			os.Exit(1)
		}

		// Determine version to install
		version := determineVersion(args)

		fmt.Fprintf(os.Stdout, "Installing Quilibrium node for %s-%s, version: %s\n", osType, arch, version)

		// Install the node
		installNode(version)
	},
}

func init() {
	// Add the install command to the node command
	NodeCmd.AddCommand(installCmd)
}

// installNode installs the Quilibrium node
func installNode(version string) {
	// Create installation directory
	if err := utils.ValidateAndCreateDir(utils.NodeDataPath, NodeUser); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating installation directory: %v\n", err)
		return
	}

	// Download and install the node
	if version == "latest" {
		latestVersion, err := utils.GetLatestVersion(utils.ReleaseTypeNode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting latest version: %v\n", err)
			return
		}

		version = latestVersion
		fmt.Fprintf(os.Stdout, "Found latest version: %s\n", version)
	}

	if IsExistingNodeVersion(version) {
		fmt.Fprintf(os.Stderr, "Error: Node version %s already exists\n", version)
		os.Exit(1)
	}

	if err := installByVersion(version); err != nil {
		fmt.Fprintf(os.Stderr, "Error installing specific version: %v\n", err)
		os.Exit(1)
	}

	createService()

	finishInstallation(version)
}

// installByVersion installs a specific version of the Quilibrium node
func installByVersion(version string) error {
	// Create version-specific directory
	user, err := user.Lookup(utils.DefaultNodeUser)
	if err != nil {
		os.Exit(1)
	}
	versionDir := filepath.Join(utils.NodeDataPath, version)
	if err := utils.ValidateAndCreateDir(versionDir, user); err != nil {
		return fmt.Errorf("failed to create version directory: %w", err)
	}

	// Download the release
	if err := utils.DownloadRelease(utils.ReleaseTypeNode, version); err != nil {
		return fmt.Errorf("failed to download release: %w", err)
	}

	// Download signature files
	if err := utils.DownloadReleaseSignatures(utils.ReleaseTypeNode, version); err != nil {
		return fmt.Errorf("failed to download signature files: %w", err)
	}

	return nil
}
