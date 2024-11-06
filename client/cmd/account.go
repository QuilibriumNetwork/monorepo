package cmd

import (
	"fmt"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/spf13/cobra"
)

var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Shows the account address of the managing account",
	Run: func(cmd *cobra.Command, args []string) {
		peerId := GetPeerIDFromConfig(NodeConfig)
		addr, err := poseidon.HashBytes([]byte(peerId))
		if err != nil {
			panic(err)
		}

		addrBytes := addr.FillBytes(make([]byte, 32))
		fmt.Printf("Account: 0x%x\n", addrBytes)
	},
}

func init() {
	tokenCmd.AddCommand(accountCmd)
}
