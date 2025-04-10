package config

import (
	"github.com/spf13/cobra"
	clientNode "source.quilibrium.com/quilibrium/monorepo/client/cmd/node"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
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
		if utils.FileExists(clientNode.ConfigDirs) {
			utils.ValidateAndCreateDir(clientNode.ConfigDirs, clientNode.NodeUser)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// GetConfigSubCommands returns all the configuration subcommands
func GetConfigSubCommands() []*cobra.Command {
	// This function can be used by other packages to get all config subcommands
	// It can be expanded in the future to return additional subcommands as they are added

	return []*cobra.Command{
		importCmd,
		setCmd,
		setDefaultCmd,
		createDefaultCmd,
	}
}

func init() {
	// Add subcommands to the config command
	// These subcommands will register themselves in their own init() functions

	// Register the config command to the node command
	clientNode.NodeCmd.AddCommand(ConfigCmd)
}

// GetRootConfigCmd returns the root config command
// This is a utility function that can be used by other packages to get the config command
// and its subcommands
func GetRootConfigCmd() *cobra.Command {
	// Return the config command that is defined in import.go
	return ConfigCmd
}

// RegisterConfigCommand registers a subcommand to the root config command
func RegisterConfigCommand(cmd *cobra.Command) {
	ConfigCmd.AddCommand(cmd)
}
