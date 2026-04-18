package config

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/cmd/node"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var ClientConfigServiceNameCmd = &cobra.Command{
	Use:   "service-name [name]",
	Short: "Set the Linux systemd service name used by the node",
	Long: `Set the name of the systemd service unit for the Quilibrium node.

On Linux, this controls the name used for commands like:
  sudo systemctl start  <name>
  sudo systemctl status <name>
and the unit file written at /etc/systemd/system/<name>.service.

The default is "quilibrium-node". The binary symlink at /usr/local/bin is
always created as quilibrium-node regardless of this value.

If a systemd unit is already installed under the previous name, this command
will migrate it: the old service is stopped/disabled/removed and a new unit
file is created under the new name (preserving enabled/active state).

Examples:
  qclient config service-name my-node
  qclient config service-name           # prints current value`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := utils.LoadClientConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}

		current := cfg.NodeServiceName
		if current == "" {
			current = utils.DefaultNodeServiceName
		}

		if len(args) == 0 {
			fmt.Printf("Node service name: %s\n", current)
			return
		}

		newName := strings.TrimSpace(args[0])
		if err := utils.ValidateNodeServiceName(newName); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if newName == current {
			fmt.Printf("Node service name is already %q, nothing to do.\n", current)
			return
		}

		// On Linux, if the old unit file exists we need sudo up front to be
		// able to migrate cleanly.
		oldUnitPath := "/etc/systemd/system/" + current + ".service"
		needsMigration := utils.OsType == "linux" && utils.FileExists(oldUnitPath)

		if needsMigration {
			if err := utils.CheckAndRequestSudo(
				"Renaming the installed systemd service requires root privileges",
			); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}

		// Capture prior state before we touch anything.
		wasActive := needsMigration && systemctlCheck("is-active", current)
		wasEnabled := needsMigration && systemctlCheck("is-enabled", current)

		if needsMigration {
			fmt.Printf("Migrating installed service %q -> %q...\n", current, newName)

			if wasActive {
				if err := runSystemctl("stop", current); err != nil {
					fmt.Fprintf(os.Stderr,
						"Warning: failed to stop %q: %v\n", current, err,
					)
				}
			}
			if wasEnabled {
				if err := runSystemctl("disable", current); err != nil {
					fmt.Fprintf(os.Stderr,
						"Warning: failed to disable %q: %v\n", current, err,
					)
				}
			}

			// Remove old unit file directly (RemoveSystemdServiceFile reads
			// the configured name, which we haven't rotated yet — but we
			// know the exact path here).
			if err := os.Remove(oldUnitPath); err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr,
					"Warning: failed to remove old unit file %s: %v\n",
					oldUnitPath, err,
				)
			}

			if err := runSystemctl("daemon-reload"); err != nil {
				fmt.Fprintf(os.Stderr,
					"Warning: systemctl daemon-reload failed: %v\n", err,
				)
			}
		}

		// Persist the new name before writing the new unit file so that
		// CreateSystemdServiceFile picks it up via GetNodeServiceName().
		cfg.NodeServiceName = newName
		if err := utils.SaveClientConfig(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving config: %v\n", err)
			os.Exit(1)
		}

		if needsMigration {
			if err := node.CreateSystemdServiceFile(false); err != nil {
				fmt.Fprintf(os.Stderr,
					"Error creating new systemd service file: %v\n", err,
				)
				os.Exit(1)
			}

			if wasEnabled {
				if err := runSystemctl("enable", newName); err != nil {
					fmt.Fprintf(os.Stderr,
						"Warning: failed to enable %q: %v\n", newName, err,
					)
				}
			}
			if wasActive {
				if err := runSystemctl("start", newName); err != nil {
					fmt.Fprintf(os.Stderr,
						"Warning: failed to start %q: %v\n", newName, err,
					)
				}
			}

			fmt.Printf("Service migrated. Active=%v Enabled=%v\n", wasActive, wasEnabled)
		}

		fmt.Printf("Node service name set to %q.\n", newName)
		if !needsMigration && utils.OsType == "linux" {
			fmt.Println(
				"No existing systemd unit was found under the previous name; " +
					"the new name will take effect the next time you install or " +
					"update the service (e.g. `sudo qclient node service install`).",
			)
		}
	},
}

// systemctlCheck returns true when `systemctl <subcmd> <unit>` exits 0.
func systemctlCheck(subcmd, unit string) bool {
	cmd := exec.Command("systemctl", subcmd, unit)
	return cmd.Run() == nil
}

// runSystemctl runs `sudo systemctl <args...>` and returns its error.
func runSystemctl(args ...string) error {
	full := append([]string{"systemctl"}, args...)
	cmd := exec.Command("sudo", full...)
	return cmd.Run()
}
