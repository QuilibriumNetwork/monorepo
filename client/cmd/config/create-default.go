package config

import (
	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var ClientConfigCreateDefaultConfigCmd = &cobra.Command{
	Use:   "create-default",
	Short: "Create a default configuration file",
	Run: func(cmd *cobra.Command, args []string) {
		utils.CreateDefaultConfig()
	},
}
