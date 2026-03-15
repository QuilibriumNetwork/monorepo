package hypergraph

import (
	"github.com/spf13/cobra"
)

var HypergraphCmd = &cobra.Command{
	Use:   "hypergraph",
	Short: "Hypergraph operations",
	Long:  `Commands for interacting with the hypergraph.`,
}

func init() {
	HypergraphCmd.AddCommand(GetCmd)
	HypergraphCmd.AddCommand(PutCmd)
	HypergraphCmd.AddCommand(RemoveCmd)
}
