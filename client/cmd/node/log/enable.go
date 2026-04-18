package log

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/config"
)

var (
	enablePath       string
	enableMaxSize    int
	enableMaxBackups int
	enableMaxAge     int
	enableCompress   bool
	enableForce      bool

	// Track which flags the user actually set so we only override when
	// they asked us to (vs. falling back to the existing value or the
	// built-in default).
	enableCompressSet bool
)

var LogEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable file-based logging for the active node config",
	Long: fmt.Sprintf(`Enable file-based logging by writing a logger block into the
active node config's config.yml.

If the active node config already has a logger block with a non-empty
path, this command leaves existing values in place unless --force is
passed. Missing fields are filled in with the defaults below. Any flag
you pass overrides both the existing value and the default.

Defaults:
  path        <config-dir>/%s
  max-size    %d   # Rotate after %dMB
  max-backups %d   # Keep %d old log files
  max-age     %d   # Delete logs older than %d days
  compress    %t   # Gzip rotated files

Examples:
  qclient node log enable
  qclient node log enable --path /mnt/logs/quil --max-size 200
  qclient node log enable --max-backups 10 --max-age 60 --compress=false
  qclient node log enable --force --path /var/log/quilibrium/mynode`,
		utils.DefaultNodeLogRelDir,
		utils.DefaultLoggerMaxSize, utils.DefaultLoggerMaxSize,
		utils.DefaultLoggerMaxBackups, utils.DefaultLoggerMaxBackups,
		utils.DefaultLoggerMaxAge, utils.DefaultLoggerMaxAge,
		utils.DefaultLoggerCompress,
	),
	Run: func(cmd *cobra.Command, args []string) {
		enableCompressSet = cmd.Flags().Changed("compress")

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

		preexisting := cfg.Logger != nil && cfg.Logger.Path != ""
		if cfg.Logger == nil {
			cfg.Logger = &config.LogConfig{}
		}

		applyEnableFlags(cfg.Logger, resolved.ConfigDir, preexisting)

		if err := config.SaveConfig(resolved.ConfigDir, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving %s: %v\n", cfgPath, err)
			os.Exit(1)
		}

		if preexisting && !enableForce && !anyEnableFlagSet(cmd) {
			fmt.Printf("Logger already enabled for %q (%s); leaving existing settings in place.\n",
				resolved.ConfigName, cfgPath)
		} else {
			fmt.Printf("Enabled file-based logging for %q (%s).\n",
				resolved.ConfigName, cfgPath)
		}
		printLoggerSummary(cfg.Logger)
	},
}

// applyEnableFlags fills in the logger block using, in priority order:
//  1. values explicitly passed on the command line,
//  2. existing values in the config (unless --force is set),
//  3. built-in defaults from the utils package.
func applyEnableFlags(lg *config.LogConfig, configDir string, preexisting bool) {
	if enablePath != "" {
		lg.Path = enablePath
	} else if lg.Path == "" || enableForce {
		lg.Path = utils.DefaultNodeLogDirForConfig(configDir)
	}

	if enableMaxSize > 0 {
		lg.MaxSize = enableMaxSize
	} else if lg.MaxSize == 0 || enableForce {
		lg.MaxSize = utils.DefaultLoggerMaxSize
	}

	if enableMaxBackups > 0 {
		lg.MaxBackups = enableMaxBackups
	} else if lg.MaxBackups == 0 || enableForce {
		lg.MaxBackups = utils.DefaultLoggerMaxBackups
	}

	if enableMaxAge > 0 {
		lg.MaxAge = enableMaxAge
	} else if lg.MaxAge == 0 || enableForce {
		lg.MaxAge = utils.DefaultLoggerMaxAge
	}

	if enableCompressSet {
		lg.Compress = enableCompress
	} else if !preexisting || enableForce {
		lg.Compress = utils.DefaultLoggerCompress
	}
}

func anyEnableFlagSet(cmd *cobra.Command) bool {
	names := []string{"path", "max-size", "max-backups", "max-age", "compress"}
	for _, n := range names {
		if cmd.Flags().Changed(n) {
			return true
		}
	}
	return false
}

func printLoggerSummary(lg *config.LogConfig) {
	fmt.Println("  logger:")
	if lg == nil {
		fmt.Println("    (none)")
		return
	}
	fmt.Printf("    path: %s\n", lg.Path)
	fmt.Printf("    maxSize: %d\n", lg.MaxSize)
	fmt.Printf("    maxBackups: %d\n", lg.MaxBackups)
	fmt.Printf("    maxAge: %d\n", lg.MaxAge)
	fmt.Printf("    compress: %t\n", lg.Compress)
	if len(lg.LogFilters) > 0 {
		fmt.Println("    logFilters:")
		for k, v := range lg.LogFilters {
			fmt.Printf("      %s: %s\n", k, v)
		}
	}
}

func init() {
	LogEnableCmd.Flags().StringVar(&enablePath, "path", "",
		"Directory where the node writes logs (default: <config-dir>/"+utils.DefaultNodeLogRelDir+")")
	LogEnableCmd.Flags().IntVar(&enableMaxSize, "max-size", 0,
		"Megabytes per log file before rotation (default: 100)")
	LogEnableCmd.Flags().IntVar(&enableMaxBackups, "max-backups", 0,
		"Number of rotated log files to keep (default: 5)")
	LogEnableCmd.Flags().IntVar(&enableMaxAge, "max-age", 0,
		"Days to keep rotated log files (default: 30)")
	LogEnableCmd.Flags().BoolVar(&enableCompress, "compress", true,
		"Gzip rotated log files")
	LogEnableCmd.Flags().BoolVar(&enableForce, "force", false,
		"Overwrite existing logger fields with defaults/flags")

	LogCmd.AddCommand(LogEnableCmd)
}
