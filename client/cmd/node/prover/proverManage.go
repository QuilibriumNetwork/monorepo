package prover

import (
	"fmt"
	"os"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"
)

var NodeProverManageCmd = &cobra.Command{
	Use:   "manage",
	Short: "Interactive prover shard management TUI",
	Long: `Opens an interactive terminal UI for managing prover shard allocations.

Shows your current allocations and all available shards in two panels.
Use Tab to switch panels and action keys to join, leave, confirm, reject,
pause, or resume shards.

Key bindings:
  Tab        Switch panel focus
  Up/k       Move cursor up
  Down/j     Move cursor down
  J (shift)  Join selected shard (Available panel)
  l          Leave selected allocation (Active only)
  c          Confirm selected allocation (Pending only)
  r          Reject selected allocation (Pending only)
  p          Pause selected allocation (Active only)
  u          Resume selected allocation (Paused only)
  R          Force refresh data
  q/Ctrl+C   Quit
`,
	Run: func(cmd *cobra.Command, args []string) {
		client, conn, err := getNodeClient()
		if err != nil {
			fmt.Printf("Failed to connect: %v\n", err)
			os.Exit(1)
		}
		defer conn.Close()

		m := newManageModel(client)
		p := tea.NewProgram(m)
		if _, err := p.Run(); err != nil {
			fmt.Printf("Error running TUI: %v\n", err)
			os.Exit(1)
		}
	},
}
