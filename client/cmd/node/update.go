package node

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var (
	restart bool
)

// updateNodeCmd represents the command to update the Quilibrium node
var NodeUpdateCmd = &cobra.Command{
	Use:   "update [version] [--restart|-r]",
	Short: "Update the Quilibrium node version",
	Long: `Update Quilibrium node to a specified version or the latest version.
If no version is specified, the latest version will be installed.

Examples:
  # Update to the latest version
  qclient node update

  # Update to a specific version
  qclient node update 2.1.0
  
  # Update to the latest version and restart the node
  qclient node update --restart`,
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

		if restart {
			restartNode()
		}
	},
}

func restartNode() {
	fmt.Println("Restarting Quilibrium node service...")
	if err := exec.Command("qclient", "node", "service", "restart").Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error restarting node service: %v\n", err)
		return
	}
	fmt.Println("Node service restarted successfully.")
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

func init() {
	NodeUpdateCmd.Flags().BoolVarP(&restart, "restart", "r", false, "Restart the node after updating")
}
