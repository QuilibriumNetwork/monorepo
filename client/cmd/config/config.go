package config

import (
	"github.com/spf13/cobra"
)

var ConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Performs a QClient configuration operation",
}

func init() {
	ConfigCmd.AddCommand(ClientConfigPrintCmd)
	ConfigCmd.AddCommand(ClientConfigCreateDefaultConfigCmd)
	ConfigCmd.AddCommand(ClientConfigPublicRpcCmd)
	ConfigCmd.AddCommand(ClientConfigSetCustomRpcCmd)
	ConfigCmd.AddCommand(ClientConfigSignatureCheckCmd)
}
