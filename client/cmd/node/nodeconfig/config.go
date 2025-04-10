package nodeconfig

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var (
	NodeUser        *user.User
	ConfigDirs      string
	NodeConfigToRun string
	SetDefault      bool
)

// ConfigCmd represents the node config command
var ConfigCmd = &cobra.Command{
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
		// Check if the config directory exists
		user, err := utils.GetCurrentSudoUser()
		if err != nil {
			fmt.Println("Error getting current user:", err)
			os.Exit(1)
		}
		ConfigDirs = filepath.Join(user.HomeDir, ".quilibrium", "configs")
		NodeConfigToRun = filepath.Join(user.HomeDir, ".quilibrium", "configs", "default")
		if utils.FileExists(ConfigDirs) {
			utils.ValidateAndCreateDir(ConfigDirs, user)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	importCmd.Flags().BoolVarP(&SetDefault, "default", "d", false, "Select this config as the default")
	ConfigCmd.AddCommand(importCmd)

	ConfigCmd.AddCommand(SwitchConfigCmd)

	createCmd.Flags().BoolVarP(&SetDefault, "default", "d", false, "Select this config as the default")
	ConfigCmd.AddCommand(createCmd)
	ConfigCmd.AddCommand(setCmd)

}
