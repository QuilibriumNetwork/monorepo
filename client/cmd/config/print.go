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
		fmt.Printf("Data Directory: %s\n", config.DataDir)
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
		fmt.Printf("  Node Env File:   %s\n", utils.GetNodeEnvFilePath())
		fmt.Printf("Node Log Dir:     %s\n", utils.GetNodeLogDir())
		fmt.Printf("Node Symlink Dir: %s\n", utils.GetNodeSymlinkDir())
		fmt.Printf("  Node Symlink:   %s\n", utils.GetNodeSymlinkPath())
		fmt.Printf("Node Configs Dir: %s\n", utils.GetNodeConfigsDir())
	},
}
