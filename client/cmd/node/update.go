package node

import (
	"fmt"
	"os"

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

		if utils.IsExistingNodeVersion(version) {
			fmt.Fprintf(os.Stderr, "Error: Node version %s already exists\n", version)
			os.Exit(1)
		}

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

	InstallNode(version)
}
