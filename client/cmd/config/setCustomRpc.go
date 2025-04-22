package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var ClientConfigSetCustomRpcCmd = &cobra.Command{
	Use:   "set-custom-rpc [url|clear]",
	Short: "Set custom RPC URL",
	Long: `Set a custom RPC URL in the client configuration.
This URL will be used when public RPC is enabled.
Provide a valid URL to set as the custom RPC endpoint. If the argument is "clear", it clears the custom RPC setting.`,
	Run: func(cmd *cobra.Command, args []string) {
		config, err := utils.LoadClientConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			os.Exit(1)
		}

		if len(args) > 0 {
			// Set the custom RPC URL based on the provided argument
			customRpc := args[0]
			if customRpc == "clear" {
				config.CustomRpc = ""
			} else if err := ValidateCustomRpc(customRpc); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			config.CustomRpc = customRpc

		} else {
			// Clear the custom RPC URL if no arguments are provided
			fmt.Printf("Error: No argument provided. Please provide a valid URL or 'clear' to clear the custom RPC setting.\n")
			os.Exit(1)
		}

		// Save the updated config
		if err := utils.SaveClientConfig(config); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Custom RPC URL set to: %s\n", args[0])

		fmt.Println("Custom RPC setting will be persisted across future commands unless reset.")
	},
}

func ValidateCustomRpc(customRpc string) error {
	if customRpc == "" {
		return fmt.Errorf("custom RPC URL cannot be empty")
	}

	if !strings.Contains(customRpc, ".") || !strings.Contains(customRpc, ":") {
		return fmt.Errorf("custom RPC URL must be in format domain:port (e.g. example.com:8080)")
	}

	return nil
}
