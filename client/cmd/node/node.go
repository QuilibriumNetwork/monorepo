package node

import (
	"fmt"
	"os"
	"os/user"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

var (
	// Base URL for Quilibrium releases
	baseReleaseURL = "https://releases.quilibrium.com"

	// Default symlink path for the node binary
	defaultSymlinkPath = "/usr/local/bin/quilibrium-node"
	logPath            = "/var/log/quilibrium"

	// Default user to run the node
	nodeUser = "quilibrium"

	ServiceName = "quilibrium-node"

	ConfigDirs      = "/home/quilibrium/configs"
	NodeConfigToRun = "/home/quilibrium/configs/default"

	// Default config file name
	defaultConfigFileName = "node.yaml"

	osType string
	arch   string

	configDirectory string
	NodeConfig      *config.Config
	NodeUser        *user.User
)

// NodeCmd represents the node command
var NodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Quilibrium node commands",
	Long:  `Run Quilibrium node commands.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		var userLookup *user.User
		var err error
		userLookup, err = user.Lookup(nodeUser)
		if err != nil {
			userLookup, err = InstallQuilibriumUser()
			if err != nil {
				fmt.Printf("error installing quilibrium user: %s\n", err)
				os.Exit(1)
			}
		}
		NodeUser = userLookup
	},
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
	},
}

func init() {
	NodeCmd.PersistentFlags().StringVar(&configDirectory, "config", ".config", "config directory (default is .config/)")

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
