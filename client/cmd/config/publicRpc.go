package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var ClientConfigPublicRpcCmd = &cobra.Command{
	Use:   "public-rpc [true|false]",
	Short: "Set public RPC setting",
	Long: `Set the public RPC setting in the client configuration.
When enabled, the client will use a public RPC endpoint instead of a local node (default is false).
Use 'true' to enable or 'false' to disable. If no argument is provided, it toggles the current setting.`,
	Run: func(cmd *cobra.Command, args []string) {
		config, err := utils.LoadClientConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			os.Exit(1)
		}

		if len(args) > 0 {
			// Set the public RPC based on the provided argument
			value := strings.ToLower(args[0])
			if value == "true" {
				config.PublicRpc = true
			} else if value == "false" {
				config.PublicRpc = false
			} else {
				// If the value is not true or false, print error message and exit
				fmt.Printf("Error: Invalid value '%s'. Please use 'true' or 'false'.\n", value)
				os.Exit(1)
			}
		} else {
			// Toggle the public RPC setting if no arguments are provided
			config.PublicRpc = !config.PublicRpc
		}

		// Save the updated config
		if err := utils.SaveClientConfig(config); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			os.Exit(1)
		}

		status := "enabled"
		if !config.PublicRpc {
			status = "disabled"
		}
		fmt.Printf("Public RPC has been set to %s and will be persisted across future commands unless reset.\n", status)
	},
}
