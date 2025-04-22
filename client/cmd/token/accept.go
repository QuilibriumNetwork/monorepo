package token

import (
	"fmt"

	"github.com/spf13/cobra"
)

var AcceptCmd = &cobra.Command{
	Use:   "accept",
	Short: "Accepts a pending transfer",
	Long: `Accepts a pending transfer:
	
	accept <PendingTransaction>
	
	PendingTransaction - the address of the pending transfer
	`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("command not yet available")
	},
}
