package nodeconfig

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var NodeConfigSwitchCmd = &cobra.Command{
	Use:   "switch [name]",
	Short: "Switch the config to be run by the node",
	Long: fmt.Sprintf(`Switch the configuration to be run by the node by creating a symlink.
	
Example:
  qclient node config switch mynode
	
This will symlink %s/mynode to %s`, ConfigDirs, NodeConfigToRun),
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var name string
		if len(args) > 0 && len(args[0]) == 1 {

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

		if name == "default" {
			fmt.Println("Invalid configuration name. The 'default' is reserved for the default configuration.")
			os.Exit(1)
		}

		err := utils.SetDefaultNodeConfig(name)
		if err != nil {
			fmt.Printf("Error setting default config: %s\n", err)
			os.Exit(1)
		}

		fmt.Printf("Successfully set %s as the default configuration\n", name)
	},
}
