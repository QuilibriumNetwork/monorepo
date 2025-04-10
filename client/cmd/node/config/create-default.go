package config

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	clientNode "source.quilibrium.com/quilibrium/monorepo/client/cmd/node"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var createDefaultCmd = &cobra.Command{
	Use:   "create-default [name]",
	Short: "Create a default configuration",
	Long: `Create a default configuration by running quilibrium-node with --peer-id and 
--config flags, then symlink it to the default configuration.

Example:
  qclient node config create-default
  qclient node config create-default myconfig

The first example will create a new configuration at ConfigsDir/default-config and symlink it to ConfigsDir/default.
The second example will create a new configuration at ConfigsDir/myconfig and symlink it to ConfigsDir/default.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Check if running as root
		if os.Geteuid() != 0 {
			fmt.Println("Error: This command requires root privileges.")
			fmt.Println("Please run with sudo or as root.")
			os.Exit(1)
		}
		// Determine the config name (default-config or user-provided)
		configName := "default-config"
		if len(args) > 0 {
			configName = args[0]

			// Check if trying to use "default" which is reserved for the symlink
			if configName == "default" {
				fmt.Println("Error: 'default' is reserved for the symlink. Please use a different name.")
				os.Exit(1)
			}
		}

		// Construct the configuration directory path
		configDir := filepath.Join(clientNode.ConfigDirs, configName)

		// Create directory if it doesn't exist
		if err := os.MkdirAll(configDir, 0755); err != nil {
			fmt.Printf("Failed to create config directory: %s\n", err)
			os.Exit(1)
		}

		// Run quilibrium-node command to generate config
		// this is a hack to get the config files to be created
		// TODO: fix this
		// to fix this, we need to extrapolate the Node's config and keystore construction
		// and reuse it for this command
		nodeCmd := exec.Command("sudo", "quilibrium-node", "--peer-id", "--config", configDir)
		nodeCmd.Stdout = os.Stdout
		nodeCmd.Stderr = os.Stderr

		fmt.Printf("Running quilibrium-node to generate configuration in %s...\n", configName)
		if err := nodeCmd.Run(); err != nil {
			fmt.Printf("Failed to run quilibrium-node: %s\n", err)
			os.Exit(1)
		}

		// Check if the configuration was created successfully
		if !HasConfigFiles(configDir) {
			fmt.Printf("Failed to generate configuration files in: %s\n", configDir)
			os.Exit(1)
		}

		// Construct the default directory path
		defaultDir := filepath.Join(clientNode.ConfigDirs, "default")

		// Create the symlink
		if err := utils.CreateSymlink(configDir, defaultDir); err != nil {
			fmt.Printf("Failed to create symlink: %s\n", err)
			os.Exit(1)
		}

		fmt.Printf("Successfully created %s configuration and symlinked to default\n", configName)
	},
}

func init() {
	ConfigCmd.AddCommand(createDefaultCmd)
}
