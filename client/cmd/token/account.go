package token

import (
	"fmt"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var AccountCmd = &cobra.Command{
	Use:   "account",
	Short: "Shows the account address of the managing account",
	Run: func(cmd *cobra.Command, args []string) {
		account, err := utils.GetAccountFromNodeConfig(NodeConfig)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Account: 0x%x\n", account)
	},
}
