package nodeconfig

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/config"
)

var rewardsAddress string
var resetRewards bool

var NodeConfigAssignRewardsCmd = &cobra.Command{
	Use:   "assign-rewards <config-name> [target-config-name]",
	Short: "Assign rewards to a config",
	Long: `Assign rewards from a config to another config or address.

When a rewards address is set, the node will direct rewards to that address
instead of its own default address.

Examples:
  # Assign rewards from my-config to the address found in my-other-config
  qclient node config assign-rewards my-config my-other-config

  # Assign rewards to a specific address
  qclient node config assign-rewards my-config --address 0x1234...

  # Reset rewards to the node's default address
  qclient node config assign-rewards my-config --reset`,
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		configName := args[0]
		configPath := filepath.Join(ConfigDirs, configName)

		// Load the source config
		cfg, err := config.LoadConfig(configPath, "", false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config %q: %v\n", configName, err)
			return
		}

		var address string

		if resetRewards {
			// Reset to default (empty string)
			address = ""
			fmt.Printf("Resetting rewards address for %s to default (self)\n", configName)
		} else if rewardsAddress != "" {
			// Use the provided address
			addr := strings.TrimPrefix(rewardsAddress, "0x")
			addrBytes, err := hex.DecodeString(addr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Invalid address hex: %v\n", err)
				return
			}
			address = hex.EncodeToString(addrBytes)
			fmt.Printf("Assigning rewards for %s to address: %s\n", configName, address)
		} else if len(args) == 2 {
			// Look up address from target config
			targetConfigName := args[1]
			targetConfigPath := filepath.Join(ConfigDirs, targetConfigName)

			targetCfg, err := config.LoadConfig(targetConfigPath, "", false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading target config %q: %v\n", targetConfigName, err)
				return
			}

			peerID := utils.GetPeerIDFromConfig(targetCfg)
			address = hex.EncodeToString([]byte(peerID))
			fmt.Printf("Found address from %s: %s\n", targetConfigName, address)
		} else {
			fmt.Println("No target specified. Use --address, --reset, or provide a target config name.")
			fmt.Println()
			fmt.Println("Usage:")
			fmt.Println("  qclient node config assign-rewards <config-name> <target-config-name>")
			fmt.Println("  qclient node config assign-rewards <config-name> --address <address>")
			fmt.Println("  qclient node config assign-rewards <config-name> --reset")
			return
		}

		// Update and save config
		cfg.Engine.RewardsAddress = address

		if err := config.SaveConfig(configPath, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
			return
		}

		fmt.Println()
		fmt.Println("Summary:")
		fmt.Printf("  Config: %s\n", configName)
		if address == "" {
			fmt.Println("  Rewards address: default (self)")
		} else {
			fmt.Printf("  Rewards address: %s\n", address)
		}
		fmt.Println()
		fmt.Printf("Successfully updated %s\n", configName)
	},
}

func init() {
	NodeConfigAssignRewardsCmd.Flags().StringVar(&rewardsAddress, "address", "", "Reward address to assign")
	NodeConfigAssignRewardsCmd.Flags().BoolVar(&resetRewards, "reset", false, "Reset rewards to default address")
}
