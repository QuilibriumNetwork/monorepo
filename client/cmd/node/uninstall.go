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
  - Any leftover legacy logrotate configuration from older installs

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

	binDir := utils.GetNodeBinaryDir()
	symlinkPath := utils.GetNodeSymlinkPath()
	logDirs := utils.ResolveAllNodeLogDirs()
	if resolved, err := utils.ResolveActiveNodeLog(); err == nil && resolved.FileBased {
		present := false
		for _, d := range logDirs {
			if d == resolved.LogDir {
				present = true
				break
			}
		}
		if !present {
			logDirs = append(logDirs, resolved.LogDir)
		}
	}
	envPath := utils.GetNodeEnvFilePath()

	// 3. Remove all binaries
	fmt.Println("Removing node binaries...")
	if err := os.RemoveAll(binDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not remove binaries at %s: %v\n", binDir, err)
	}

	// 4. Remove symlink
	fmt.Println("Removing node symlink...")
	if err := os.Remove(symlinkPath); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Warning: could not remove symlink at %s: %v\n", symlinkPath, err)
	}

	// 5. Remove logs
	fmt.Println("Removing log files...")
	for _, logDir := range logDirs {
		if err := os.RemoveAll(logDir); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Warning: could not remove logs at %s: %v\n", logDir, err)
		}
	}

	// 6. Best-effort removal of any legacy logrotate config left over
	// from previous qclient versions. Current installs don't create
	// one; the node rotates its own logs.
	legacyLogrotate := "/etc/logrotate.d/" + utils.NodeServiceName
	if err := os.Remove(legacyLogrotate); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Warning: could not remove legacy logrotate config at %s: %v\n", legacyLogrotate, err)
	}

	// 7. Remove environment file
	fmt.Println("Removing environment file...")
	if err := os.Remove(envPath); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Warning: could not remove environment file at %s: %v\n", envPath, err)
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
		cmd := exec.Command("sudo", "systemctl", "stop", utils.GetNodeServiceName())
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "  Note: could not stop service (may not be running): %v\n", err)
		}
	}
}

func removeNodeService() {
	if OsType == "linux" {
		serviceName := utils.GetNodeServiceName()
		// Disable service first
		disableCmd := exec.Command("sudo", "systemctl", "disable", serviceName)
		disableCmd.Run() // ignore error

		// Remove service file
		servicePath := "/etc/systemd/system/" + serviceName + ".service"
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
