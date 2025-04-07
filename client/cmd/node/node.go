package node

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
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

	configDirectory string
	NodeConfig      *config.Config
	publicRPC       bool = false
	LightNode       bool = false
)

// NodeCmd represents the node command
var NodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Quilibrium node commands",
	Long:  `Run Quilibrium node commands.`,
	Run: func(cmd *cobra.Command, args []string) {
		// These commands handle their own configuration
		_, err := os.Stat(configDirectory)
		if os.IsNotExist(err) {
			fmt.Printf("config directory doesn't exist: %s\n", configDirectory)
			os.Exit(1)
		}

		NodeConfig, err = LoadConfig(configDirectory)
		if err != nil {
			fmt.Printf("invalid config directory: %s\n", configDirectory)
			os.Exit(1)
		}

		if publicRPC {
			fmt.Println("Public RPC enabled, using light node")
			LightNode = true
		}

		if !LightNode && NodeConfig.ListenGRPCMultiaddr == "" {
			fmt.Println("No ListenGRPCMultiaddr found in config, using light node")
			LightNode = true
		}
	},
}

func init() {
	NodeCmd.PersistentFlags().StringVar(&configDirectory, "config", ".config", "config directory (default is .config/)")
	NodeCmd.PersistentFlags().BoolVar(&publicRPC, "public-rpc", false, "Use public RPC for node operations")

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
