package node

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/spf13/cobra"
	clientNodeConfig "source.quilibrium.com/quilibrium/monorepo/client/cmd/node/config"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

var (
	// Base URL for Quilibrium releases
	baseReleaseURL = "https://releases.quilibrium.com"

	// Default symlink path for the node binary
	defaultSymlinkPath = "/usr/local/bin/quilibrium-node"
	logPath            = "/var/log/quilibrium"

	ServiceName = "quilibrium-node"

	OsType string
	Arch   string

	configDirectory string
	NodeConfig      *config.Config

	NodeUser        *user.User
	ConfigDirs      string
	NodeConfigToRun string
)

// NodeCmd represents the node command
var NodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Quilibrium node commands",
	Long:  `Run Quilibrium node commands.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Store reference to parent's PersistentPreRun to call it first
		parent := cmd.Parent()
		if parent != nil && parent.PersistentPreRun != nil {
			parent.PersistentPreRun(parent, args)
		}

		// Then run the node-specific initialization
		var userLookup *user.User
		var err error
		userLookup, err = utils.GetCurrentSudoUser()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting current user: %v\n", err)
			os.Exit(1)
		}
		NodeUser = userLookup
		ConfigDirs = filepath.Join(userLookup.HomeDir, ".quilibrium", "configs")
		NodeConfigToRun = filepath.Join(userLookup.HomeDir, ".quilibrium", "configs", "default")
	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	NodeCmd.PersistentFlags().StringVar(&configDirectory, "config", ".config", "config directory (default is .config/)")

	// Add subcommands
	NodeCmd.AddCommand(installCmd)
	NodeCmd.AddCommand(clientNodeConfig.ConfigCmd)
	NodeCmd.AddCommand(updateNodeCmd)
	NodeCmd.AddCommand(nodeServiceCmd)

	localOsType, localArch, err := utils.GetSystemInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	OsType = localOsType
	Arch = localArch
}
