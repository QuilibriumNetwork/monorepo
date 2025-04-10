package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	clientNode "source.quilibrium.com/quilibrium/monorepo/client/cmd/node"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var setDefaultCmd = &cobra.Command{
	Use:   "set-default [name]",
	Short: "Set a configuration as the default",
	Long: `Set a configuration as the default by creating a symlink.
	
Example:
  qclient node config set-default mynode
	
This will symlink /home/quilibrium/configs/mynode to /home/quilibrium/configs/default`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]

		// Construct the source directory path
		sourceDir := filepath.Join(clientNode.ConfigDirs, name)

		// Check if source directory exists
		if _, err := os.Stat(sourceDir); os.IsNotExist(err) {
			fmt.Printf("Config directory does not exist: %s\n", sourceDir)
			os.Exit(1)
		}

		// Check if the source directory has both config.yml and keys.yml files
		if !HasConfigFiles(sourceDir) {
			fmt.Printf("Source directory does not contain both config.yml and keys.yml files: %s\n", sourceDir)
			os.Exit(1)
		}

		// Construct the default directory path
		defaultDir := filepath.Join(clientNode.ConfigDirs, "default")

		// Create the symlink
		if err := utils.CreateSymlink(sourceDir, defaultDir); err != nil {
			fmt.Printf("Failed to create symlink: %s\n", err)
			os.Exit(1)
		}

		fmt.Printf("Successfully set %s as the default configuration\n", name)
	},
}

func init() {
	ConfigCmd.AddCommand(setDefaultCmd)
}
