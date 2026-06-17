package config

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var ClientConfigPrintCmd = &cobra.Command{
	Use:   "print",
	Short: "Print the current configuration",
	Run: func(cmd *cobra.Command, args []string) {
		config, err := utils.LoadClientConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config: %v\n", err)
			os.Exit(1)
		}

		// Print the config in a readable format
		fmt.Printf("QClient Install Dir: %s\n", utils.GetQClientInstallDir())
		fmt.Printf("  QClient Binary Dir: %s\n", utils.GetQClientBinaryDir())
		fmt.Printf("Symlink Path: %s\n", config.SymlinkPath)
		fmt.Printf("Signature Check: %v\n", config.SignatureCheck)
		fmt.Printf("Quiet: %v\n", config.Quiet)
		fmt.Printf("Public RPC: %v\n", config.PublicRpc)
		serviceName := config.NodeServiceName
		if serviceName == "" {
			serviceName = utils.DefaultNodeServiceName
		}
		fmt.Printf("Node Service Name: %s\n", serviceName)

		fmt.Printf("Node Install Dir: %s\n", utils.GetNodeInstallDir())
		fmt.Printf("  Node Binary Dir: %s\n", utils.GetNodeBinaryDir())
		fmt.Printf("Node State Dir:   %s\n", utils.GetNodeStateDir())
		fmt.Printf("  Node Env File:   %s\n", utils.GetNodeEnvFilePath())
		// Node log location lives in the node config's logger.path, not
		// the client config. Show the active one for convenience.
		if resolved, err := utils.ResolveActiveNodeLog(); err == nil {
			if resolved.FileBased {
				fmt.Printf("Node Log Dir:     %s (from %s/config.yml)\n",
					resolved.LogDir, resolved.ConfigDir)
			} else {
				fmt.Printf("Node Log Dir:     (none; active config %q has no logger block, node logs to system log)\n",
					resolved.ConfigName)
			}
		}
		fmt.Printf("Node Symlink Dir: %s\n", utils.GetNodeSymlinkDir())
		fmt.Printf("  Node Symlink:   %s\n", utils.GetNodeSymlinkPath())
		fmt.Printf("Node Configs Dir: %s\n", utils.GetNodeConfigsDir())
	},
}
