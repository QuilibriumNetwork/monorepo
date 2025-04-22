package token

import (
	"github.com/spf13/cobra"
)

var MintCmd = &cobra.Command{
	Use:   "mint",
	Short: "Performs a mint operation",
}

func init() {
	TokenCmd.AddCommand(MintCmd)
}
