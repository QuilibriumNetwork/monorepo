package node

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

// infoCmd represents the info command
var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Get information about the Quilibrium node",
	Long: `Get information about the Quilibrium node.
Available subcommands:
  latest-version    Get the latest available version of Quilibrium node

Examples:
  # Get the latest version
  qclient node info latest-version`,
}

// latestVersionCmd represents the latest-version command
var latestVersionCmd = &cobra.Command{
	Use:   "latest-version",
	Short: "Get the latest available version of Quilibrium node",
	Long: `Get the latest available version of Quilibrium node by querying the releases API.
This command fetches the version information from https://releases.quilibrium.com/release.`,
	Run: func(cmd *cobra.Command, args []string) {
		version, err := utils.GetLatestVersion(utils.ReleaseTypeNode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}
		fmt.Fprintf(os.Stdout, "Latest available version: %s\n", version)
	},
}

func init() {
	// Add the latest-version subcommand to the info command
	infoCmd.AddCommand(latestVersionCmd)

	// Add the info command to the node command
	NodeCmd.AddCommand(infoCmd)
}
