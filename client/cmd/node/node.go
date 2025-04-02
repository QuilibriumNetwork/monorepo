package node

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var (
	// Base URL for Quilibrium releases
	baseReleaseURL = "https://releases.quilibrium.com"

	// Default symlink path for the node binary
	defaultSymlinkPath = "/usr/local/bin/quilibrium-node"

	// Default installation directory base path
	installPath = "/opt/quilibrium"

	// Default data directory paths
	dataPath = "/var/lib/quilibrium"

	logPath = "/var/log/quilibrium"

	// Default user to run the node
	nodeUser = "quilibrium"

	serviceName = "quilibrium-node"

	// Default config file name
	defaultConfigFileName = "node.yaml"

	osType string
	arch   string
)

// NodeCmd represents the node command
var NodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Quilibrium node commands",
	Long:  `Run Quilibrium node commands.`,
}

func init() {
	// Add subcommands
	NodeCmd.AddCommand(installCmd)
	NodeCmd.AddCommand(updateNodeCmd)
	NodeCmd.AddCommand(nodeServiceCmd)

	localOsType, localArch, err := utils.GetSystemInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	osType = localOsType
	arch = localArch
}
