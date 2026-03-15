package log

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var LogCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Clean node logs",
	Long: `Remove all log files from the Quilibrium node log directory.

Examples:
  qclient node log clean`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := utils.CheckAndRequestSudo("Cleaning logs requires root privileges"); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}

		logDir := utils.LogPath
		entries, err := os.ReadDir(logDir)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("No logs directory found.")
			} else {
				fmt.Fprintf(os.Stderr, "Error reading log directory: %v\n", err)
			}
			return
		}

		removed := 0
		for _, entry := range entries {
			name := entry.Name()
			if strings.HasSuffix(name, ".log") || strings.HasSuffix(name, ".log.gz") {
				path := filepath.Join(logDir, name)
				if err := os.Remove(path); err != nil {
					fmt.Fprintf(os.Stderr, "Warning: could not remove %s: %v\n", name, err)
					continue
				}
				removed++
			}
		}

		fmt.Printf("Removed %d log file(s) from %s\n", removed, logDir)
	},
}

func init() {
	LogCmd.AddCommand(LogCleanCmd)
}
