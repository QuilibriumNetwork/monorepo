package node

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var (
	LatestVersion bool
)

// infoCmd represents the info command
var NodeInfoCmd = &cobra.Command{
	Use:   "info [config-name]",
	Short: "Get information about the Quilibrium node",
	Long: `Get information about the Quilibrium node.

Examples:
  # Prints the latest node version available for download
  qclient node info --latest-version`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			NodeGetInfo(args[0])
		} else {
			NodeGetInfo("default")
		}
	},
}

func NodeGetInfo(configName string) {
	configPath := filepath.Join(ConfigDirs, configName)
	if !utils.FileExists(configPath) {
		fmt.Fprintf(os.Stderr, "Error: Config file %s not found\n", configPath)
		os.Exit(1)
	}

	fmt.Printf("Fetching node information for config: %s (%s)\n", configName, configPath)

	// Execute the command and capture output
	output, err := exec.Command(utils.NodeServiceName, "--node-info", "--config", configPath).Output()
	if err != nil {
		fmt.Println(string(output))
		fmt.Fprintf(os.Stderr, "Error executing node info command: %v\n", err)
		os.Exit(1)
	}

	// Print the output from the command
	fmt.Println(output)
}

// latestVersionCmd represents the latest-version command
func NodeGetLatestVersion() {
	version, err := utils.GetLatestVersion(utils.ReleaseTypeNode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stdout, "Latest available version: %s\n", version)
}

func init() {
	// Add the latest-version subcommand to the info command
	NodeInfoCmd.Flags().BoolVarP(&LatestVersion, "latest-version", "l", false, "Get the latest available version of Quilibrium node")
}
