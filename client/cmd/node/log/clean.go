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
	Long: `Remove all log files from the active node config's log directory.

The log directory is resolved from the active node config's
logger.path. If the active config has no logger block (i.e. the node
logs to the system log), there is nothing for this command to clean —
use the system log tooling (e.g. journalctl --vacuum-time=...) instead.

Examples:
  qclient node log clean`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := utils.CheckAndRequestSudo("Cleaning logs requires root privileges"); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}

		resolved, err := utils.ResolveActiveNodeLog()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving node log: %v\n", err)
			return
		}
		if !resolved.FileBased {
			fmt.Fprintf(os.Stderr,
				"Node config %q at %s has no logger block; the node "+
					"logs to the system log, which qclient does not "+
					"clean. Use journalctl --vacuum-time=... or set "+
					"logger.path first.\n",
				resolved.ConfigName, resolved.ConfigDir,
			)
			return
		}

		removed := cleanLogsIn(resolved.LogDir)
		fmt.Printf("Removed %d log file(s) from %s\n", removed, resolved.LogDir)
	},
}

func cleanLogsIn(logDir string) int {
	entries, err := os.ReadDir(logDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No logs directory found.")
		} else {
			fmt.Fprintf(os.Stderr, "Error reading log directory: %v\n", err)
		}
		return 0
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
	return removed
}

func init() {
	LogCmd.AddCommand(LogCleanCmd)
}
