package config

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var ClientConfig *utils.ClientConfig

var ConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Performs a QClient configuration operation",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		parent := cmd.Parent()
		if parent != nil && parent.PersistentPreRun != nil {
			parent.PersistentPreRun(parent, args)
		}

		var err error
		ClientConfig, err = utils.LoadClientConfig()
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	ConfigCmd.AddCommand(ClientConfigPrintCmd)
	ConfigCmd.AddCommand(ClientConfigCreateDefaultConfigCmd)
	ConfigCmd.AddCommand(ClientConfigPublicRpcCmd)
	ConfigCmd.AddCommand(ClientConfigSetCustomRpcCmd)
	ConfigCmd.AddCommand(ClientConfigSignatureCheckCmd)
	ConfigCmd.AddCommand(ClientConfigAliasCmd)
}
