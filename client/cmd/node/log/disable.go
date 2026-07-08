package log

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/config"
)

var LogDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable file-based logging for the active node config",
	Long: `Disable file-based logging by removing the logger block from the
active node config's config.yml. The node will fall back to stdout,
which the service manager captures (journalctl on Linux, launchd
StandardOutPath on macOS).

Existing log files on disk are not deleted; use ` + "`qclient node log clean`" + `
first if you want to wipe them.

Examples:
  qclient node log disable
  qclient node log disable --config mynode`,
	Run: func(cmd *cobra.Command, args []string) {
		resolved, err := utils.ResolveActiveNodeLog()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving active node config: %v\n", err)
			os.Exit(1)
		}
		if resolved.ConfigDir == "" {
			fmt.Fprintln(os.Stderr,
				"No active node config found. Run `qclient node config create` first.",
			)
			os.Exit(1)
		}

		cfgPath := filepath.Join(resolved.ConfigDir, "config.yml")
		cfg, err := config.NewConfig(cfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", cfgPath, err)
			os.Exit(1)
		}

		if cfg.Logger == nil {
			fmt.Printf("File-based logging is already disabled for %q (%s).\n",
				resolved.ConfigName, cfgPath)
			return
		}

		prevPath := cfg.Logger.Path
		cfg.Logger = nil

		if err := config.SaveConfig(resolved.ConfigDir, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving %s: %v\n", cfgPath, err)
			os.Exit(1)
		}

		fmt.Printf("Disabled file-based logging for %q (%s).\n",
			resolved.ConfigName, cfgPath)
		if prevPath != "" {
			fmt.Printf("Existing log files under %s were left in place; "+
				"run `qclient node log clean` to remove them.\n", prevPath)
		}
	},
}

func init() {
	LogCmd.AddCommand(LogDisableCmd)
}
