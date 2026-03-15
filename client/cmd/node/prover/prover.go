package prover

import (
	"github.com/spf13/cobra"
)

var ConfigDirectory string

var ProverCmd = &cobra.Command{
	Use:   "prover",
	Short: "Performs a configuration operation for given prover info",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	ProverCmd.AddCommand(NodeProverPauseCmd)
	ProverCmd.AddCommand(NodeProverConfigMergeCmd)
	ProverCmd.AddCommand(NodeProverStatusCmd)
	ProverCmd.AddCommand(NodeProverLeaveCmd)
	ProverCmd.AddCommand(NodeProverDelegateCmd)
	ProverCmd.AddCommand(NodeProverShardsCmd)
	ProverCmd.AddCommand(NodeProverShardInfoCmd)
	ProverCmd.AddCommand(NodeProverResumeCmd)
	ProverCmd.AddCommand(NodeProverConfirmCmd)
	ProverCmd.AddCommand(NodeProverRejectCmd)
	ProverCmd.AddCommand(NodeProverJoinCmd)
	ProverCmd.AddCommand(NodeProverAltShardUpdateCmd)
	ProverCmd.AddCommand(NodeProverManageCmd)
}
