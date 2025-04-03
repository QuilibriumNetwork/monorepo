package config

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var toggleSignatureCheckCmd = &cobra.Command{
	Use:   "toggle-signature-check",
	Short: "Toggle signature check setting",
	Long: `Toggle the signature check setting in the client configuration.
When disabled, signature verification will be bypassed (not recommended for production use).`,
	Run: func(cmd *cobra.Command, args []string) {
		config, err := utils.LoadClientConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			os.Exit(1)
		}

		// Toggle the signature check setting
		config.SignatureCheck = !config.SignatureCheck

		// Save the updated config
		if err := utils.SaveClientConfig(config); err != nil {
			fmt.Printf("Error saving config: %v\n", err)
			os.Exit(1)
		}

		status := "enabled"
		if !config.SignatureCheck {
			status = "disabled"
		}
		fmt.Printf("Signature check has been %s\n", status)
	},
}

func init() {
	ConfigCmd.AddCommand(toggleSignatureCheckCmd)
}
