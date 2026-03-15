package node

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

var (
	Force bool
)

// uninstallNodeCmd represents the command to uninstall the Quilibrium node
var NodeUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall Quilibrium node",
	Long: `Uninstalls the Quilibrium node and associated files, excluding user data.
This command will prompt for confirmation unless the --force flag is used.

The following will be removed:
  - Node service (systemd/launchd)
  - All node binaries and signatures
  - Node symlink
  - Log files
  - Logrotate configuration

The following will NOT be removed:
  - Configuration files (~/.quilibrium/configs/)

Examples:
  # Uninstall with confirmation prompt
  qclient node uninstall

  # Uninstall without confirmation
  qclient node uninstall --force`,
	Run: func(cmd *cobra.Command, args []string) {
		if !utils.IsSudo() {
			fmt.Println("This command must be run with sudo: sudo qclient node uninstall")
			os.Exit(1)
		}

		if !Force {
			fmt.Println("This will uninstall the Quilibrium node and remove all binaries and logs.")
			fmt.Println("Configuration files in ~/.quilibrium/configs/ will NOT be removed.")
			fmt.Print("\nAre you sure you want to continue? [y/N]: ")

			reader := bufio.NewReader(os.Stdin)
			response, _ := reader.ReadString('\n')
			response = strings.TrimSpace(strings.ToLower(response))

			if response != "y" && response != "yes" {
				fmt.Println("Uninstall cancelled.")
				return
			}
		}

		uninstallNode()
	},
}

func uninstallNode() {
	// 1. Stop the service
	fmt.Println("Stopping node service...")
	stopNodeService()

	// 2. Remove the service
	fmt.Println("Removing node service...")
	removeNodeService()

	// 3. Remove all binaries
	fmt.Println("Removing node binaries...")
	if err := os.RemoveAll(utils.NodeDataPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not remove binaries at %s: %v\n", utils.NodeDataPath, err)
	}

	// 4. Remove symlink
	fmt.Println("Removing node symlink...")
	if err := os.Remove(utils.DefaultNodeSymlinkPath); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Warning: could not remove symlink at %s: %v\n", utils.DefaultNodeSymlinkPath, err)
	}

	// 5. Remove logs
	fmt.Println("Removing log files...")
	if err := os.RemoveAll(utils.LogPath); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Warning: could not remove logs at %s: %v\n", utils.LogPath, err)
	}

	// 6. Remove logrotate config
	logrotateConfig := "/etc/logrotate.d/" + utils.NodeServiceName
	if err := os.Remove(logrotateConfig); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Warning: could not remove logrotate config at %s: %v\n", logrotateConfig, err)
	}

	fmt.Println()
	fmt.Println("Quilibrium node uninstalled successfully.")
	fmt.Println()
	fmt.Println("Your configuration files have been preserved at:")
	fmt.Printf("  %s\n", ConfigDirs)
	fmt.Println()
	fmt.Println("To reinstall, run: sudo qclient node install")
}

func stopNodeService() {
	if OsType == "darwin" {
		cmd := exec.Command("sudo", "launchctl", "stop", fmt.Sprintf("com.quilibrium.%s", utils.NodeServiceName))
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "  Note: could not stop service (may not be running): %v\n", err)
		}
	} else {
		cmd := exec.Command("sudo", "systemctl", "stop", utils.NodeServiceName)
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "  Note: could not stop service (may not be running): %v\n", err)
		}
	}
}

func removeNodeService() {
	if OsType == "linux" {
		// Disable service first
		disableCmd := exec.Command("sudo", "systemctl", "disable", utils.NodeServiceName)
		disableCmd.Run() // ignore error

		// Remove service file
		servicePath := "/etc/systemd/system/" + utils.NodeServiceName + ".service"
		if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "  Warning: could not remove service file: %v\n", err)
		}

		// Reload daemon
		reloadCmd := exec.Command("sudo", "systemctl", "daemon-reload")
		reloadCmd.Run() // ignore error
	} else if OsType == "darwin" {
		plistPath := fmt.Sprintf("/Library/LaunchDaemons/com.quilibrium.%s.plist", utils.NodeServiceName)

		// Unload service
		unloadCmd := exec.Command("sudo", "launchctl", "unload", "-w", plistPath)
		unloadCmd.Run() // ignore error

		// Remove plist
		if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "  Warning: could not remove service plist: %v\n", err)
		}
	}
}

func init() {
	NodeUninstallCmd.Flags().BoolVar(&Force, "force", false, "Skip confirmation prompt for uninstallation")
}
