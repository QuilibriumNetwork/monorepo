package token

import (
	"fmt"

	"github.com/spf13/cobra"
)

var RejectCmd = &cobra.Command{
	Use:   "reject",
	Short: "Rejects the pending transaction",
	Long: `Rejects a pending transfer:
	
	reject <PendingTransaction>
	
	PendingTransaction - the address of the pending transfer
	`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("command not yet available")
	},
}
