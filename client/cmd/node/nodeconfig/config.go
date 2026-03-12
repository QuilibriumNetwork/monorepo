package nodeconfig

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/config"
)

var (
	NodeUser        *user.User
	ConfigDirs      string
	NodeConfigToRun string
	SetDefault      bool
	NodeConfig      *config.Config
)

// ConfigCmd represents the node config command
var NodeConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage node configuration",
	Long: `Manage Quilibrium node configuration.
	
This command provides utilities for configuring your Quilibrium node, such as:
- Setting configuration values
- Setting default configuration
- Creating default configuration
- Importing configuration
`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Store reference to parent's PersistentPreRun to call it first
		parent := cmd.Parent()
		if parent != nil && parent.PersistentPreRun != nil {
			parent.PersistentPreRun(parent, args)
		}

		// Check if the config directory exists
		user, err := utils.GetCurrentSudoUser()
		if err != nil {
			fmt.Println("Error getting current user:", err)
			os.Exit(1)
		}
		ConfigDirs = filepath.Join(user.HomeDir, ".quilibrium", "configs")
	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	NodeConfigCmd.AddCommand(NodeConfigAssignRewardsCmd)
	NodeConfigCmd.AddCommand(NodeConfigCreateCmd)
	NodeConfigCmd.AddCommand(NodeConfigImportCmd)
	NodeConfigCmd.AddCommand(NodeConfigSetCmd)
	NodeConfigCmd.AddCommand(NodeConfigSwitchCmd)
}
