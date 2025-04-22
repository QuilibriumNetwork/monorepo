package token

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

var LightNode bool = false
var PublicRPC bool = false
var NodeConfig *config.Config
var ConfigDirectory string
var ClientConfig *utils.ClientConfig

var TokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Performs a token operation",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		var err error
		ClientConfig, err = utils.LoadClientConfig()
		if err != nil {
			fmt.Printf("error loading client config: %s\n", err)
			os.Exit(1)
		}

		fmt.Println("Loading node config...")
		if ConfigDirectory != "" {
			NodeConfig, err = utils.LoadNodeConfig(ConfigDirectory)
		} else {
			NodeConfig, err = utils.LoadDefaultNodeConfig()
		}

		if err != nil {
			if err.Error() == utils.ErrConfigNotFoundErrorMessage {
				fmt.Println("Config not found, creating default configuration...")
				nodeConfig, err := utils.CreateDefaultNodeConfig(utils.DefaultNodeConfigName)
				if err != nil {
					fmt.Printf("error creating default node config: %s\n", err)
					os.Exit(1)
				}
				NodeConfig = nodeConfig
			} else {
				fmt.Printf("error loading node config: %s\n", err)
				os.Exit(1)
			}
		}

		if PublicRPC {
			fmt.Println("Public RPC enabled, using light node")
			LightNode = true
		}

		if ClientConfig.PublicRpc {
			fmt.Println("Public RPC enabled, using light node")
			LightNode = true
		}

		if !LightNode && (NodeConfig.ListenGRPCMultiaddr == "" || ClientConfig.PublicRpc) {
			fmt.Println("No ListenGRPCMultiaddr found in config, using light node")
			LightNode = true
		}
	},
}

func init() {
	TokenCmd.PersistentFlags().BoolVar(&PublicRPC, "public-rpc", false, "Use public RPC for token operations")
	viper.BindPFlag("public-rpc", TokenCmd.PersistentFlags().Lookup("public-rpc"))

	TokenCmd.PersistentFlags().StringVar(&ConfigDirectory, "config", "", "Path to the config directory")
	viper.BindPFlag("config", TokenCmd.PersistentFlags().Lookup("config"))

	TokenCmd.AddCommand(AcceptCmd)
	TokenCmd.AddCommand(MintCmd)
	TokenCmd.AddCommand(MergeCmd)
	TokenCmd.AddCommand(TransferCmd)
	TokenCmd.AddCommand(AccountCmd)
	TokenCmd.AddCommand(RejectCmd)
	TokenCmd.AddCommand(CoinsCmd)
	TokenCmd.AddCommand(MutualReceiveCmd)
	TokenCmd.AddCommand(MutualTransferCmd)
	TokenCmd.AddCommand(BalanceCmd)

	SplitCmd.Flags().IntVarP(&parts, "parts", "p", 1, "number of parts to split the coin into")
	SplitCmd.Flags().StringVarP(&partAmount, "part-amount", "a", "", "amount of each part")
	TokenCmd.AddCommand(SplitCmd)
}
