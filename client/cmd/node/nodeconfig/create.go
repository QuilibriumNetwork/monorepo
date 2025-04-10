package nodeconfig

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var createCmd = &cobra.Command{
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

		// Construct the configuration directory path
		configDir := filepath.Join(ConfigDirs, configName)

		// Create directory if it doesn't exist
		if err := utils.ValidateAndCreateDir(configDir, NodeUser); err != nil {
			fmt.Printf("Failed to create config directory: %s\n", err)
			os.Exit(1)
		}

		// Run quilibrium-node command to generate config
		// this is a hack to get the config files to be created
		// TODO: fix this
		// to fix this, we need to extrapolate the Node's config and keystore construction
		// and reuse it for this command
		nodeCmd := exec.Command("quilibrium-node", "--peer-id", "--config", configDir)
		nodeCmd.Stdout = os.Stdout
		nodeCmd.Stderr = os.Stderr

		fmt.Printf("Running quilibrium-node to generate configuration in %s...\n", configName)
		if err := nodeCmd.Run(); err != nil {
			// Check if the error is due to the command not being found
			if exitErr, ok := err.(*exec.ExitError); ok {
				fmt.Printf("Error running quilibrium-node: %s\n", exitErr)
			} else if _, ok := err.(*exec.Error); ok {
				fmt.Printf("Error: quilibrium-node command not found. Please ensure it is installed and in your PATH.\n")
			} else {
				fmt.Printf("Error: %s\n", err)
			}
			os.RemoveAll(configDir)
			os.Exit(1)
		}

		// Check if the configuration was created successfully
		if !HasConfigFiles(configDir) {
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
