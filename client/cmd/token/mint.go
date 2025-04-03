package token

import (
	"github.com/spf13/cobra"
)

var mintCmd = &cobra.Command{
	Use:   "mint",
	Short: "Performs a mint operation",
}

func init() {
	TokenCmd.AddCommand(mintCmd)
}
