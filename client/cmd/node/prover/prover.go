package prover

import (
	"github.com/spf13/cobra"
	clientNode "source.quilibrium.com/quilibrium/monorepo/client/cmd/node"
)

var ConfigDirectory string

var ProverCmd = &cobra.Command{
	Use:   "prover",
	Short: "Performs a configuration operation for given prover info",
	Run:   func(cmd *cobra.Command, args []string) {},
}

func init() {
	ProverCmd.PersistentFlags().StringVar(&ConfigDirectory, "config", ".config", "config directory (default is .config/)")
	ProverCmd.AddCommand(proverPauseCmd)
	ProverCmd.AddCommand(proverConfigMergeCmd)
	clientNode.NodeCmd.AddCommand(ProverCmd)
}
