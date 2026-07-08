package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var uninstallForce bool

// qclientSymlinkPath is the symlink created by `qclient link`.
const qclientSymlinkPath = "/usr/local/bin/qclient"

var UninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall qclient (binaries, symlink, client config)",
	Long: `Uninstalls the qclient binary tree, the /usr/local/bin/qclient symlink,
and the qclient client config file. Node configs under ~/.quilibrium/configs/
are preserved.

This command will prompt for confirmation unless the --force flag is used.

The following will be removed:
  - qclient install dir (versioned binaries + signatures)
  - Legacy qclient binary dir (/var/quilibrium/bin/qclient), if present
  - /usr/local/bin/qclient symlink
  - qclient client config file (~/.quilibrium/qclient.yml)
  - The currently running qclient executable (scheduled after exit)

The following will NOT be removed:
  - Node configs (~/.quilibrium/configs/)
  - Anything installed by 'qclient node install' (use 'qclient node uninstall')

Examples:
  sudo qclient uninstall
  sudo qclient uninstall --force`,
	// Skip the signature check PersistentPreRun for this command so
	// users can uninstall even when signatures are missing/stale.
	PersistentPreRun: func(cmd *cobra.Command, args []string) {},
	Run: func(cmd *cobra.Command, args []string) {
		if !utils.IsSudo() {
			fmt.Println("This command must be run with sudo: sudo qclient uninstall")
			os.Exit(1)
		}

		if !uninstallForce {
			fmt.Println("This will remove qclient binaries, the /usr/local/bin/qclient symlink,")
			fmt.Println("and the qclient client config file.")
			fmt.Println("Node configs in ~/.quilibrium/configs/ will NOT be removed.")
			fmt.Print("\nAre you sure you want to continue? [y/N]: ")

			reader := bufio.NewReader(os.Stdin)
			response, _ := reader.ReadString('\n')
			response = strings.TrimSpace(strings.ToLower(response))
			if response != "y" && response != "yes" {
				fmt.Println("Uninstall cancelled.")
				return
			}
		}

		uninstallQClient()
	},
}

func uninstallQClient() {
	binDir := utils.GetQClientBinaryDir()

	fmt.Println("Removing qclient binaries...")
	if err := os.RemoveAll(binDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not remove qclient binaries at %s: %v\n", binDir, err)
	}

	// Best-effort: remove legacy pre-FHS-split location too.
	if _, err := os.Stat(utils.LegacyQClientBinaryDir); err == nil {
		fmt.Printf("Removing legacy qclient binaries at %s...\n", utils.LegacyQClientBinaryDir)
		if err := os.RemoveAll(utils.LegacyQClientBinaryDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not remove legacy qclient binaries: %v\n", err)
		}
	}

	fmt.Println("Removing qclient symlink...")
	if err := os.Remove(qclientSymlinkPath); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Warning: could not remove symlink at %s: %v\n", qclientSymlinkPath, err)
	}

	configPath := utils.GetConfigPath()
	fmt.Println("Removing qclient client config...")
	if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Warning: could not remove client config at %s: %v\n", configPath, err)
	}

	// Schedule self-deletion of the running executable after we exit.
	// The install dir RemoveAll above may have already removed it on
	// Linux (unlink-while-running is allowed), but on macOS and when
	// the binary was copied/linked elsewhere we still need to clean it
	// up. Best-effort — ignore errors.
	scheduleSelfDelete()

	fmt.Println()
	fmt.Println("qclient uninstalled successfully.")
	fmt.Println()
	fmt.Println("Your node configs have been preserved at:")
	if cu, err := utils.GetCurrentSudoUser(); err == nil {
		fmt.Printf("  %s\n", filepath.Join(cu.HomeDir, utils.DefaultNodeConfigsSubdir))
	} else {
		fmt.Println("  ~/.quilibrium/configs/")
	}
}

// scheduleSelfDelete forks a detached shell that waits briefly for this
// process to exit, then removes the currently running executable. This
// is the cross-platform way to let a binary "delete itself": on Linux
// unlink-while-running works, but on macOS the file is still on disk
// after RemoveAll until the last reference is dropped.
func scheduleSelfDelete() {
	ex, err := os.Executable()
	if err != nil {
		return
	}
	resolved, err := filepath.EvalSymlinks(ex)
	if err == nil {
		ex = resolved
	}
	// Detached shell: sleep briefly so our parent process can exit,
	// then rm. We intentionally don't wait on this command.
	sh := fmt.Sprintf("sleep 1; rm -f %q", ex)
	cmd := exec.Command("/bin/sh", "-c", sh)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	_ = cmd.Start()
	if cmd.Process != nil {
		_ = cmd.Process.Release()
	}
}

func init() {
	UninstallCmd.Flags().BoolVar(&uninstallForce, "force", false, "Skip confirmation prompt")
}
