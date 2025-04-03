package token

import (
	"fmt"

	"github.com/spf13/cobra"
)

var mutualTransferCmd = &cobra.Command{
	Use:   "mutual-transfer",
	Short: "Initiates a mutual transfer",
	Long: `Initiates a mutual transfer:
	
	mutual-transfer <Rendezvous> (<Amount>|<OfCoin>)
	
	Rendezvous - the rendezvous point to connect to the recipient
	Amount – the amount to send, splitting/merging and sending as needed
	OfCoin – the address of the coin to send in whole

	Either Amount or OfCoin must be specified
	`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("command not yet available")
	},
}

func init() {
	TokenCmd.AddCommand(mutualTransferCmd)
}
