package nodeconfig

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/config"
)

var NodeConfigSetCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Set a configuration value",
	Long: `Set a configuration value in the node config.yml file.
	
	To specify a config other than the default, use the --config flag.
Example:
  qclient node config set mynode engine.statsMultiaddr /dns/stats.quilibrium.com/tcp/443
  
  qclient node config set --config mynode engine.statsMultiaddr /dns/stats.quilibrium.com/tcp/443
`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]
		value := args[1]

		// Update the config based on the key
		switch key {
		case "engine.statsMultiaddr":
			NodeConfig.Engine.StatsMultiaddr = value
		case "p2p.listenMultiaddr":
			NodeConfig.P2P.ListenMultiaddr = value
		case "listenGrpcMultiaddr":
			NodeConfig.ListenGRPCMultiaddr = value
		case "listenRestMultiaddr":
			NodeConfig.ListenRestMultiaddr = value
		default:
			fmt.Printf("Unsupported configuration key: %s\n", key)
			fmt.Println("Supported keys: engine.statsMultiaddr, p2p.listenMultiaddr, listenGrpcMultiaddr, listenRestMultiaddr")
			os.Exit(1)
		}

		// Save the updated config
		if err := config.SaveConfig(NodeConfigToRun, NodeConfig); err != nil {
			fmt.Printf("Failed to save config: %s\n", err)
			os.Exit(1)
		}

		fmt.Printf("Successfully updated %s to %s in %s\n", key, value, NodeConfigToRun)
	},
}
