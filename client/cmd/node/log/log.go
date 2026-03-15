package log

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var (
	lines  int
	follow bool
)

var LogCmd = &cobra.Command{
	Use:   "log",
	Short: "View and manage node logs",
	Long: `View and manage Quilibrium node logs.

Examples:
  qclient node log view
  qclient node log view --lines 200
  qclient node log view --follow
  qclient node log clean`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var LogViewCmd = &cobra.Command{
	Use:   "view",
	Short: "View node logs",
	Long: `View the Quilibrium node log file.

Examples:
  qclient node log view              # show last 100 lines
  qclient node log view --lines 200  # show last 200 lines
  qclient node log view --follow     # follow log output`,
	Run: func(cmd *cobra.Command, args []string) {
		logFile := filepath.Join(utils.LogPath, "quilibrium-node.log")

		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Log file not found: %s\n", logFile)
			return
		}

		if follow {
			tailFollow(logFile)
		} else {
			tailLines(logFile)
		}
	},
}

func tailLines(logFile string) {
	cmd := exec.Command("tail", "-n", strconv.Itoa(lines), logFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading log file: %v\n", err)
		return
	}
	fmt.Print(string(output))
}

func tailFollow(logFile string) {
	cmd := exec.Command("tail", "-n", strconv.Itoa(lines), "-f", logFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting log follow: %v\n", err)
		return
	}

	// Handle signals to clean up the tail process
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		cmd.Process.Kill()
	}()

	cmd.Wait()
}

func init() {
	LogViewCmd.Flags().IntVarP(&lines, "lines", "n", 100, "Number of lines to display")
	LogViewCmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output")

	LogCmd.AddCommand(LogViewCmd)
}
