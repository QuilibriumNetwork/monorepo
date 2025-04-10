package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var signatureCheckCmd = &cobra.Command{
	Use:   "signature-check [true|false]",
	Short: "Set signature check setting",
	Long: `Set the signature check setting in the client configuration.
When disabled, signature verification will be bypassed (not recommended for production use).
Use 'true' to enable or 'false' to disable. If no argument is provided, it toggles the current setting.`,
	Run: func(cmd *cobra.Command, args []string) {
		config, err := utils.LoadClientConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			os.Exit(1)
		}

		if len(args) > 0 {
			// Set the signature check based on the provided argument
			value := strings.ToLower(args[0])
			if value == "true" {
				config.SignatureCheck = true
			} else if value == "false" {
				config.SignatureCheck = false
			} else {
				// If the value is not true or false, print error message and exit
				fmt.Printf("Error: Invalid value '%s'. Please use 'true' or 'false'.\n", value)
				os.Exit(1)
			}
		} else {
			// Toggle the signature check setting if no arguments are provided
			config.SignatureCheck = !config.SignatureCheck
		}

		// Save the updated config
		if err := utils.SaveClientConfig(config); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			os.Exit(1)
		}

		status := "enabled"
		if !config.SignatureCheck {
			status = "disabled"
		}
		fmt.Printf("Signature check has been set to %s and will be persisted across future commands unless reset.\n", status)
	},
}

func init() {
	ConfigCmd.AddCommand(signatureCheckCmd)
}
