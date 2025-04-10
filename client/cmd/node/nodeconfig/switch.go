package nodeconfig

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var SwitchConfigCmd = &cobra.Command{
	Use:   "switch [name]",
	Short: "Switch the config to be run by the node",
	Long: fmt.Sprintf(`Switch the configuration to be run by the node by creating a symlink.
	
Example:
  qclient node config switch mynode
	
This will symlink %s/mynode to %s`, ConfigDirs, NodeConfigToRun),
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var name string
		if len(args) > 0 {
			name = args[0]
		} else {
			// List available configurations
			configs, err := ListConfigurations()
			if err != nil {
				fmt.Printf("Error listing configurations: %s\n", err)
				os.Exit(1)
			}

			if len(configs) == 0 {
				fmt.Println("No configurations found. Create one with 'qclient node config create'")
				os.Exit(1)
			}

			fmt.Println("Available configurations:")
			for i, config := range configs {
				fmt.Printf("%d. %s\n", i+1, config)
			}

			// Prompt for choice
			var choice int
			fmt.Print("Enter the number of the configuration to set as default: ")
			_, err = fmt.Scanf("%d", &choice)
			if err != nil || choice < 1 || choice > len(configs) {
				fmt.Println("Invalid choice. Please enter a valid number.")
				os.Exit(1)
			}

			name = configs[choice-1]
		}

		// Construct the source directory path
		sourceDir := filepath.Join(ConfigDirs, name)

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
		defaultDir := filepath.Join(ConfigDirs, "default")

		// Create the symlink
		if err := utils.CreateSymlink(sourceDir, defaultDir); err != nil {
			fmt.Printf("Failed to create symlink: %s\n", err)
			os.Exit(1)
		}

		fmt.Printf("Successfully set %s as the default configuration\n", name)
	},
}
