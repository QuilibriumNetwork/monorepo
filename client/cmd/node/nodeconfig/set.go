package nodeconfig

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

var setCmd = &cobra.Command{
	Use:   "set [name] [key] [value]",
	Short: "Set a configuration value",
	Long: `Set a configuration value in the node config.yml file.
	
Example:
  qclient node config set mynode engine.statsMultiaddr /dns/stats.quilibrium.com/tcp/443
`,
	Args: cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		key := args[1]
		value := args[2]

		// Construct the config directory path
		configDir := filepath.Join(ConfigDirs, name)
		configFile := filepath.Join(configDir, "config.yml")

		// Check if config directory exists
		if _, err := os.Stat(configDir); os.IsNotExist(err) {
			fmt.Printf("Config directory does not exist: %s\n", configDir)
			os.Exit(1)
		}

		// Check if config file exists
		if _, err := os.Stat(configFile); os.IsNotExist(err) {
			fmt.Printf("Config file does not exist: %s\n", configFile)
			os.Exit(1)
		}

		// Load the config
		cfg, err := config.LoadConfig(configDir, "", false)
		if err != nil {
			fmt.Printf("Failed to load config: %s\n", err)
			os.Exit(1)
		}

		// Update the config based on the key
		switch key {
		case "engine.statsMultiaddr":
			cfg.Engine.StatsMultiaddr = value
		case "p2p.listenMultiaddr":
			cfg.P2P.ListenMultiaddr = value
		case "listenGrpcMultiaddr":
			cfg.ListenGRPCMultiaddr = value
		case "listenRestMultiaddr":
			cfg.ListenRestMultiaddr = value
		case "engine.autoMergeCoins":
			if value == "true" {
				cfg.Engine.AutoMergeCoins = true
			} else if value == "false" {
				cfg.Engine.AutoMergeCoins = false
			} else {
				fmt.Printf("Invalid value for %s: must be 'true' or 'false'\n", key)
				os.Exit(1)
			}
		default:
			fmt.Printf("Unsupported configuration key: %s\n", key)
			fmt.Println("Supported keys: engine.statsMultiaddr, p2p.listenMultiaddr, listenGrpcMultiaddr, listenRestMultiaddr, engine.autoMergeCoins")
			os.Exit(1)
		}

		// Save the updated config
		if err := config.SaveConfig(configDir, cfg); err != nil {
			fmt.Printf("Failed to save config: %s\n", err)
			os.Exit(1)
		}

		fmt.Printf("Successfully updated %s to %s in %s\n", key, value, configFile)
	},
}
