package log

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
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

Logs are read from the active node config's logger.path. If the active
node config has no logger block, qclient falls back to the system log
(journalctl on Linux, launchd StandardOutPath on macOS).

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
	Long: `View the Quilibrium node log.

The log source is resolved from the active node config's logger.path.
If the config has no logger block, the system log is used instead
(journalctl -u <service> on Linux, the launchd StandardOutPath on macOS).

Examples:
  qclient node log view              # show last 100 lines
  qclient node log view --lines 200  # show last 200 lines
  qclient node log view --follow     # follow log output`,
	Run: func(cmd *cobra.Command, args []string) {
		resolved, err := utils.ResolveActiveNodeLog()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving node log: %v\n", err)
			return
		}

		if resolved.FileBased {
			logFile := resolved.MasterLogFile()
			if _, err := os.Stat(logFile); os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr,
					"Log file not found: %s\n"+
						"The node config at %s declares logger.path=%s "+
						"but no master.log has been written yet. "+
						"Has the node started?\n",
					logFile, resolved.ConfigDir, resolved.LogDir,
				)
				return
			}
			if follow {
				tailFollow(logFile)
			} else {
				tailLines(logFile)
			}
			return
		}

		viewSystemLog(resolved)
	},
}

// viewSystemLog falls back to journalctl (Linux) or the launchd stdout
// path (macOS) when the active node config has no logger block.
func viewSystemLog(resolved utils.ResolvedNodeLog) {
	fmt.Fprintf(os.Stderr,
		"Node config %q at %s has no logger block; reading from the "+
			"system log instead. Run `qclient node config set "+
			"logger.path <dir>` to enable file-based logging.\n",
		resolved.ConfigName, resolved.ConfigDir,
	)

	switch runtime.GOOS {
	case "linux":
		service := utils.GetNodeServiceName()
		args := []string{"-u", service, "-n", strconv.Itoa(lines), "--no-pager"}
		if follow {
			args = append(args, "-f")
		}
		runStreaming("journalctl", args...)
	case "darwin":
		// launchd writes stdout/stderr into <LogPath>/node.log per the
		// plist installed by qclient. Fall back to the pre-refactor
		// root log directory so existing installs keep working.
		stdoutPath := "/var/log/quilibrium/node.log"
		if _, err := os.Stat(stdoutPath); err != nil {
			fmt.Fprintf(os.Stderr,
				"No launchd stdout log found at %s. Check the service "+
					"plist under /Library/LaunchDaemons for the "+
					"StandardOutPath.\n",
				stdoutPath,
			)
			return
		}
		if follow {
			runStreaming("tail", "-n", strconv.Itoa(lines), "-f", stdoutPath)
		} else {
			runStreaming("tail", "-n", strconv.Itoa(lines), stdoutPath)
		}
	default:
		fmt.Fprintf(os.Stderr,
			"System log fallback is not supported on %s; set "+
				"logger.path in the node config to use file logging.\n",
			runtime.GOOS,
		)
	}
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
	runStreaming("tail", "-n", strconv.Itoa(lines), "-f", logFile)
}

// runStreaming runs an external command, wiring stdout/stderr through
// to this process and forwarding SIGINT/SIGTERM so Ctrl+C behaves
// correctly when following logs.
func runStreaming(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting %s: %v\n", name, err)
		return
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		_ = cmd.Process.Kill()
	}()

	_ = cmd.Wait()
}

func init() {
	LogViewCmd.Flags().IntVarP(&lines, "lines", "n", 100, "Number of lines to display")
	LogViewCmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output")

	LogCmd.AddCommand(LogViewCmd)
}
