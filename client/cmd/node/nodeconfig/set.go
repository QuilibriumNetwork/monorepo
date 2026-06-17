package nodeconfig

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/config"
)

var NodeConfigSetCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Set a configuration value",
	Long: `Set a configuration value in the node config.yml file.

To specify a config other than the default, use the --config flag.

Supported keys:
  engine.statsMultiaddr
  p2p.listenMultiaddr
  listenGrpcMultiaddr
  listenRestMultiaddr
  logger.path          Directory where the node writes logs
  logger.maxSize       Megabytes per log file before rotation
  logger.maxBackups    Number of rotated files to keep
  logger.maxAge        Days to keep rotated files
  logger.compress      true/false — gzip rotated files
  logger.logFilters    Comma-separated list of component=level pairs,
                       e.g. "p2p=debug,engine=warn"

Examples:
  qclient node config set engine.statsMultiaddr /dns/stats.quilibrium.com/tcp/443
  qclient node config set --config mynode engine.statsMultiaddr /dns/stats.quilibrium.com/tcp/443
  qclient node config set logger.path /path/to/my/logs
  qclient node config set logger.compress true
  qclient node config set logger.logFilters p2p=debug,engine=warn
`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]
		value := args[1]

		if NodeConfig == nil || ActiveNodeConfigDir == "" {
			fmt.Println("No active node config loaded. Run `qclient node config create` first, or pass --config <name>.")
			os.Exit(1)
		}

		if err := setConfigKey(key, value); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if err := config.SaveConfig(ActiveNodeConfigDir, NodeConfig); err != nil {
			fmt.Printf("Failed to save config: %s\n", err)
			os.Exit(1)
		}

		fmt.Printf("Successfully updated %s to %s in %s/config.yml\n", key, value, ActiveNodeConfigDir)
	},
}

// setConfigKey mutates NodeConfig in place based on the key/value. It
// returns an error rather than exiting so the caller can decide how to
// report it.
func setConfigKey(key, value string) error {
	switch key {
	case "engine.statsMultiaddr":
		NodeConfig.Engine.StatsMultiaddr = value
	case "p2p.listenMultiaddr":
		NodeConfig.P2P.ListenMultiaddr = value
	case "listenGrpcMultiaddr":
		NodeConfig.ListenGRPCMultiaddr = value
	case "listenRestMultiaddr":
		NodeConfig.ListenRestMultiaddr = value
	case "logger.path":
		ensureLogger()
		NodeConfig.Logger.Path = value
	case "logger.maxSize":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("logger.maxSize must be an integer, got %q", value)
		}
		ensureLogger()
		NodeConfig.Logger.MaxSize = n
	case "logger.maxBackups":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("logger.maxBackups must be an integer, got %q", value)
		}
		ensureLogger()
		NodeConfig.Logger.MaxBackups = n
	case "logger.maxAge":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("logger.maxAge must be an integer, got %q", value)
		}
		ensureLogger()
		NodeConfig.Logger.MaxAge = n
	case "logger.compress":
		b, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("logger.compress must be true or false, got %q", value)
		}
		ensureLogger()
		NodeConfig.Logger.Compress = b
	case "logger.logFilters":
		filters, err := parseLogFilters(value)
		if err != nil {
			return err
		}
		ensureLogger()
		NodeConfig.Logger.LogFilters = filters
	default:
		return fmt.Errorf(
			"Unsupported configuration key: %s\n"+
				"Supported keys: engine.statsMultiaddr, p2p.listenMultiaddr, "+
				"listenGrpcMultiaddr, listenRestMultiaddr, logger.path, "+
				"logger.maxSize, logger.maxBackups, logger.maxAge, "+
				"logger.compress, logger.logFilters",
			key,
		)
	}
	return nil
}

func ensureLogger() {
	if NodeConfig.Logger == nil {
		NodeConfig.Logger = &config.LogConfig{}
	}
}

// parseLogFilters accepts "component=level,component=level" and returns
// the equivalent map. Whitespace around entries is ignored; an empty
// string clears the filter map.
func parseLogFilters(value string) (map[string]string, error) {
	out := map[string]string{}
	value = strings.TrimSpace(value)
	if value == "" {
		return out, nil
	}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf(
				"logger.logFilters entry %q must be component=level", part,
			)
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		if k == "" || v == "" {
			return nil, fmt.Errorf(
				"logger.logFilters entry %q has an empty component or level", part,
			)
		}
		out[k] = v
	}
	return out, nil
}
