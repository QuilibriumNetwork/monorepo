package node

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	logCmd "source.quilibrium.com/quilibrium/monorepo/client/cmd/node/log"
	configCmd "source.quilibrium.com/quilibrium/monorepo/client/cmd/node/nodeconfig"
	proverCmd "source.quilibrium.com/quilibrium/monorepo/client/cmd/node/prover"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/config"
)

var (
	OsType string
	Arch   string

	ConfigDirectory string
	NodeConfig      *config.Config

	NodeUser        *user.User
	ConfigDirs      string
	NodeConfigToRun string
)

// NodeCmd represents the node command
var NodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Quilibrium node commands",
	Long:  `Run Quilibrium node commands.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Store reference to parent's PersistentPreRun to call it first
		parent := cmd.Parent()
		if parent != nil && parent.PersistentPreRun != nil {
			parent.PersistentPreRun(parent, args)
		}

		// Then run the node-specific initialization
		var userLookup *user.User
		var err error
		userLookup, err = utils.GetCurrentSudoUser()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting current user: %v\n", err)
			os.Exit(1)
		}
		NodeUser = userLookup
		ConfigDirs = filepath.Join(userLookup.HomeDir, ".quilibrium", "configs")
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
		proverCmd.NodeConfig = NodeConfig
	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	NodeCmd.PersistentFlags().StringVar(&ConfigDirectory, "config", "", "config directory")
	viper.BindPFlag("config", NodeCmd.PersistentFlags().Lookup("config"))

	// Add subcommands
	NodeCmd.AddCommand(configCmd.NodeConfigCmd)
	NodeCmd.AddCommand(proverCmd.ProverCmd)
	NodeCmd.AddCommand(NodeAutoUpdateCmd)
	NodeCmd.AddCommand(NodeCleanCmd)
	NodeCmd.AddCommand(NodeInfoCmd)
	NodeCmd.AddCommand(NodeInstallCmd)
	NodeCmd.AddCommand(NodeServiceCmd)
	NodeCmd.AddCommand(NodeUpdateCmd)
	NodeCmd.AddCommand(NodeUninstallCmd)
	NodeCmd.AddCommand(NodeLinkCmd)
	NodeCmd.AddCommand(logCmd.LogCmd)

	OsType = utils.OsType
	Arch = utils.Arch
}
