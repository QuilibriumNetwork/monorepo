package node

// TODO: Implement a clean command that will remove old versions of the node,
//  signatures, and logs
// qlient node clean
// qlient node clean --all (all logs, old node binaries and signatures)
// qlient node clean --logs (remove all logs)
// qlient node clean --node (remove all old node binary versions, including signatures)

// to remove even current versions, they must run 'qclient node uninstall'

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var (
	cleanAll  bool
	cleanLogs bool
	cleanNode bool
)

// CleanCmd represents the clean command
var NodeCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Clean old node files",
	Long: `Clean old versions of the node, signatures, and logs.

This command provides utilities for cleaning up your Quilibrium node:
- Remove old logs
- Remove old node binary versions and signatures
- Remove all of the above

Examples:
    qclient node clean --logs # remove just the logs
    qclient node clean --node # remove all old node binary versions, including signatures
    qclient node clean --all # remove all logs, old node binaries and signatures

To remove the current version of the node, use 'qclient node uninstall'`,
	Run: func(cmd *cobra.Command, args []string) {
		if !cleanAll && !cleanLogs && !cleanNode {
			cmd.Help()
			return
		}

		if cleanAll || cleanLogs {
			cleanNodeLogs()
		}

		if cleanAll || cleanNode {
			cleanNodeBinaries()
		}
	},
}

// cleanNodeLogs removes all log files from the node's log directory
func cleanNodeLogs() {
	user, err := utils.GetCurrentSudoUser()
	if err != nil {
		fmt.Println("Error getting current user:", err)
		return
	}

	logDir := filepath.Join(user.HomeDir, ".quilibrium", "logs")
	if !utils.FileExists(logDir) {
		fmt.Println("No logs directory found.")
		return
	}

	// TODO: Implement actual log cleaning logic
	fmt.Println("Cleaning logs from:", logDir)
	fmt.Println("Log cleaning functionality not yet implemented.")
}

// cleanNodeBinaries removes old node binary versions and signatures
func cleanNodeBinaries() {
	// TODO: Implement binary and signature cleaning logic
	fmt.Println("Cleaning old node binaries and signatures.")
	fmt.Println("Binary cleaning functionality not yet implemented.")
}

func RemoveNodeBinary(version string) error {
	user, err := utils.GetCurrentSudoUser()
	if err != nil {
		return fmt.Errorf("error getting current user: %w", err)
	}

	binDir := filepath.Join(user.HomeDir, ".quilibrium", "bin")
	if !utils.FileExists(binDir) {
		return fmt.Errorf("no bin directory found")
	}
	return nil
}

func init() {
	NodeCleanCmd.Flags().BoolVar(&cleanAll, "all", false, "Remove all logs, old node binaries and signatures")
	NodeCleanCmd.Flags().BoolVar(&cleanLogs, "logs", false, "Remove all logs")
	NodeCleanCmd.Flags().BoolVar(&cleanNode, "node", false, "Remove all old node binary versions, including signatures")
}
