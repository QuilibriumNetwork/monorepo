package token

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
)

var LightNode bool = false
var PublicRPC bool = false
var NodeConfig *config.Config
var ConfigDirectory string
var ClientConfig *utils.ClientConfig
var KeyManager *keys.FileKeyManager

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
				nodeConfig, err := utils.CreateDefaultNodeConfig(
					utils.DefaultNodeConfigName,
				)
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

		fmt.Println(utils.GetPeerIDFromConfig(NodeConfig).String())

		logger, _ := zap.NewProduction()
		KeyManager = keys.NewFileKeyManager(
			NodeConfig,
			&bls48581.Bls48581KeyConstructor{},
			&bulletproofs.Decaf448KeyConstructor{},
			logger,
		)

		if PublicRPC {
			fmt.Println("Public RPC enabled, using light node")
			LightNode = true
		}

		if ClientConfig.PublicRpc {
			fmt.Println("Public RPC enabled, using light node")
			LightNode = true
		}

		if !LightNode &&
			(NodeConfig.ListenGRPCMultiaddr == "" || ClientConfig.PublicRpc) {
			fmt.Println("No ListenGRPCMultiaddr found in config, using light node")
			LightNode = true
		}
	},
}

func init() {
	TokenCmd.PersistentFlags().BoolVar(
		&PublicRPC,
		"public-rpc",
		false,
		"Use public RPC for token operations",
	)
	viper.BindPFlag("public-rpc", TokenCmd.PersistentFlags().Lookup("public-rpc"))

	TokenCmd.PersistentFlags().StringVar(
		&ConfigDirectory,
		"config",
		"",
		"Path to the config directory",
	)
	viper.BindPFlag("config", TokenCmd.PersistentFlags().Lookup("config"))

	TokenCmd.AddCommand(AcceptCmd)
	TokenCmd.AddCommand(MintCmd)
	TokenCmd.AddCommand(MergeCmd)

	TransferCmd.Flags().StringVarP(
		&expiration,
		"expiration",
		"e",
		"",
		"Expiration time for the transfer",
	)
	TokenCmd.AddCommand(TransferCmd)
	TokenCmd.AddCommand(AccountCmd)
	TokenCmd.AddCommand(RejectCmd)
	TokenCmd.AddCommand(CoinsCmd)
	TokenCmd.AddCommand(BalanceCmd)

	SplitCmd.Flags().IntVarP(
		&parts,
		"parts",
		"p",
		1,
		"number of parts to split the coin into",
	)
	SplitCmd.Flags().StringVarP(
		&partAmount,
		"part-amount",
		"a",
		"",
		"amount of each part",
	)
	TokenCmd.AddCommand(SplitCmd)
}
