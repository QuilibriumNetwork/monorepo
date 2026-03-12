package config

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var ClientConfigPrintCmd = &cobra.Command{
	Use:   "print",
	Short: "Print the current configuration",
	Run: func(cmd *cobra.Command, args []string) {
		config, err := utils.LoadClientConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config: %v\n", err)
			os.Exit(1)
		}

		// Print the config in a readable format
		fmt.Printf("Data Directory: %s\n", config.DataDir)
		fmt.Printf("Symlink Path: %s\n", config.SymlinkPath)
		fmt.Printf("Signature Check: %v\n", config.SignatureCheck)
		fmt.Printf("Public RPC: %v\n", config.PublicRpc)
	},
}
