package token

import (
	"fmt"

	"github.com/spf13/cobra"
)

var mutualReceiveCmd = &cobra.Command{
	Use:   "mutual-receive",
	Short: "Initiates a mutual receive",
	Long: `Initiates a mutual receive:
	
	mutual-receive <ExpectedAmount>
	
	ExpectedAmount - the amount expected in the transfer
	`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("command not yet available")
	},
}

func init() {
	TokenCmd.AddCommand(mutualReceiveCmd)
}
