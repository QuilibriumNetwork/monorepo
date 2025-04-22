package nodeconfig

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var NodeConfigCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a default configuration file set for a node",
	Long: fmt.Sprintf(`Create a default configuration by running quilibrium-node with --peer-id and --config flags, then symlink it to the default configuration.

Example:
  qclient node config create
  qclient node config create myconfig

  qclient node config create myconfig --default

The first example will create a new configuration at %s/default-config.
The second example will create a new configuration at %s/myconfig.
The third example will create a new configuration at %s/myconfig and symlink it so the node will use it.`,
		ConfigDirs, ConfigDirs, ConfigDirs),
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Determine the config name (default-config or user-provided)
		var configName string
		if len(args) > 0 {
			configName = args[0]
		} else {
			// Prompt for a name if none provided
			fmt.Print("Enter a name for the configuration (cannot be 'default'): ")
			fmt.Scanln(&configName)

			if configName == "" {
				configName = "default-config"
			}
		}

		// Check if trying to use "default" which is reserved for the symlink
		if configName == "default" {
			fmt.Println("Error: 'default' is reserved for the symlink. Please use a different name.")
			os.Exit(1)
		}

		utils.CreateDefaultNodeConfig(configName)

		// Construct the expected configuration directory path
		configDir := filepath.Join(ConfigDirs, configName)
		// Check if the configuration was created successfully
		if !utils.HasNodeConfigFiles(configDir) {
			fmt.Printf("Failed to generate configuration files in: %s\n", configDir)
			os.Exit(1)
		}

		if SetDefault {
			// Create the symlink
			if err := utils.CreateSymlink(configDir, NodeConfigToRun); err != nil {
				fmt.Printf("Failed to create symlink: %s\n", err)
				os.Exit(1)
			}

			fmt.Printf("Successfully created %s configuration and symlinked to default\n", configName)
		} else {
			fmt.Printf("Successfully created %s configuration\n", configName)
		}
		fmt.Println("The keys.yml file will only contain 'null:' until the node is started.")
	},
}

func init() {
	NodeConfigCreateCmd.Flags().BoolVarP(&SetDefault, "default", "d", false, "Select this config as the default")
}
