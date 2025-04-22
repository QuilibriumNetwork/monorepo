package node

// TODO: Implement a command to uninstall the current and previous versions
// of the node and all files, not including user data
// this should NEVER delete the user data, only the node files and logs

// prompt the user for confirmation or a --force flag to skip the confirmation

// qlient node uninstall
// qlient node uninstall --force (skip the confirmation)

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	Force bool
)

// uninstallNodeCmd represents the command to uninstall the Quilibrium node
var NodeUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall Quilibrium node",
	Long: `Uninstalls the Quilibrium node and associated files, excluding user data.
This command will prompt for confirmation unless the --force flag is used.

Examples:
  # Uninstall with confirmation prompt
  qclient node uninstall

  # Uninstall without confirmation
  qclient node uninstall --force`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Node uninstall command is not yet implemented.")
	},
}

func init() {
	NodeUninstallCmd.Flags().BoolVar(&Force, "force", false, "Skip confirmation prompt for uninstallation")
}
