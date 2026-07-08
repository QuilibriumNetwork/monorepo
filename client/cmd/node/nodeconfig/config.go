package nodeconfig

import (
	"fmt"
	"os/user"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/config"
)

var (
	NodeUser   *user.User
	ConfigDirs string
	// NodeConfigToRun is the default-config symlink path
	// (~/.quilibrium/configs/default). `config create`, `config
	// import`, and `config switch` use it as the *link destination* so
	// the node always loads whichever real config is currently aliased
	// as "default".
	NodeConfigToRun string
	// ActiveNodeConfigDir is the absolute path to the directory of the
	// currently-active config.yml — either the resolved --config value
	// or the default symlink's target. Commands that write to
	// config.yml (e.g. `config set`) use this so writes land in the
	// real config dir rather than in the CWD.
	ActiveNodeConfigDir string
	SetDefault          bool
	NodeConfig          *config.Config
)

// ConfigCmd represents the node config command
var NodeConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage node configuration",
	Long: `Manage Quilibrium node configuration.
	
This command provides utilities for configuring your Quilibrium node, such as:
- Setting configuration values
- Setting default configuration
- Creating default configuration
- Importing configuration
`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Store reference to parent's PersistentPreRun to call it first
		parent := cmd.Parent()
		if parent != nil && parent.PersistentPreRun != nil {
			parent.PersistentPreRun(parent, args)
		}

		ConfigDirs = utils.GetNodeConfigsDir()
		NodeConfigToRun = utils.GetDefaultNodeConfigSymlink()
		// NodeConfig and ActiveNodeConfigDir are populated by the
		// parent node command's PersistentPreRun (which has already
		// run above via parent.PersistentPreRun) so that --config is
		// honored.

		NodeConfigSwitchCmd.Long = fmt.Sprintf(`Switch the configuration to be run by the node by creating a symlink.
	
Example:
  qclient node config switch mynode
	
This will symlink %s/mynode to %s`, ConfigDirs, NodeConfigToRun)
	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func init() {
	NodeConfigCmd.AddCommand(NodeConfigAssignRewardsCmd)
	NodeConfigCmd.AddCommand(NodeConfigCreateCmd)
	NodeConfigCmd.AddCommand(NodeConfigImportCmd)
	NodeConfigCmd.AddCommand(NodeConfigSetCmd)
	NodeConfigCmd.AddCommand(NodeConfigSwitchCmd)
}
