package token

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

var LightNode bool = false
var publicRPC bool = false
var NodeConfig *config.Config
var configDirectory string

var TokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Performs a token operation",
	Run: func(cmd *cobra.Command, args []string) {

		// These commands handle their own configuration
		_, err := os.Stat(configDirectory)
		if os.IsNotExist(err) {
			fmt.Printf("config directory doesn't exist: %s\n", configDirectory)
			os.Exit(1)
		}

		NodeConfig, err = config.LoadConfig(configDirectory, "", false)
		if err != nil {
			fmt.Printf("invalid config directory: %s\n", configDirectory)
			os.Exit(1)
		}

		if publicRPC {
			fmt.Println("Public RPC enabled, using light node")
			LightNode = true
		}

		if !LightNode && NodeConfig.ListenGRPCMultiaddr == "" {
			fmt.Println("No ListenGRPCMultiaddr found in config, using light node")
			LightNode = true
		}
	},
}

func init() {
	TokenCmd.PersistentFlags().BoolVar(&publicRPC, "public-rpc", false, "Use public RPC for token operations")
	TokenCmd.PersistentFlags().StringVar(&configDirectory, "config", ".config", "config directory (default is .config/)")
}
