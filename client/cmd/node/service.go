package node

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

// nodeServiceCmd represents the command to manage the Quilibrium node service
var nodeServiceCmd = &cobra.Command{
	Use:   "service [command]",
	Short: "Manage the Quilibrium node service",
	Long: `Manage the Quilibrium node service.
Available commands:
  start     Start the node service
  stop      Stop the node service
  restart   Restart the node service
  status    Check the status of the node service
  enable    Enable the node service to start on boot
  disable   Disable the node service from starting on boot
  install   Install the service for the current OS

Examples:
  # Start the node service
  qclient node service start

  # Check service status
  qclient node service status

  # Enable service to start on boot
  qclient node service enable`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		command := args[0]
		switch command {
		case "start":
			startService()
		case "stop":
			stopService()
		case "restart":
			restartService()
		case "status":
			checkServiceStatus()
		case "enable":
			enableService()
		case "disable":
			disableService()
		case "reload":
			reloadService()
		case "install":
			installService()
		default:
			fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
			fmt.Fprintf(os.Stderr, "Available commands: start, stop, restart, status, enable, disable, reload, install\n")
			os.Exit(1)
		}
	},
}

// installService installs the appropriate service configuration for the current OS
func installService() {
	if err := utils.CheckAndRequestSudo("Installing service requires root privileges"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	fmt.Fprintf(os.Stdout, "Installing Quilibrium node service for %s...\n", osType)

	if osType == "darwin" {
		installMacOSService()
	} else if osType == "linux" {
		if err := createSystemdServiceFile(); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating systemd service file: %v\n", err)
			return
		}
	} else {
		fmt.Fprintf(os.Stderr, "Error: Unsupported operating system: %s\n", osType)
		return
	}

	fmt.Fprintf(os.Stdout, "Quilibrium node service installed successfully\n")
}

// startService starts the Quilibrium node service
func startService() {
	if err := utils.CheckAndRequestSudo("Starting service requires root privileges"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if osType == "darwin" {
		// MacOS launchd command
		cmd := exec.Command("sudo", "launchctl", "start", fmt.Sprintf("com.quilibrium.%s", serviceName))
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting service: %v\n", err)
			return
		}
	} else {
		// Linux systemd command
		cmd := exec.Command("sudo", "systemctl", "start", serviceName)
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting service: %v\n", err)
			return
		}
	}

	fmt.Fprintf(os.Stdout, "Started Quilibrium node service\n")
}

// stopService stops the Quilibrium node service
func stopService() {
	if err := utils.CheckAndRequestSudo("Stopping service requires root privileges"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if osType == "darwin" {
		// MacOS launchd command
		cmd := exec.Command("sudo", "launchctl", "stop", fmt.Sprintf("com.quilibrium.%s", serviceName))
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error stopping service: %v\n", err)
			return
		}
	} else {
		// Linux systemd command
		cmd := exec.Command("sudo", "systemctl", "stop", serviceName)
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error stopping service: %v\n", err)
			return
		}
	}

	fmt.Fprintf(os.Stdout, "Stopped Quilibrium node service\n")
}

// restartService restarts the Quilibrium node service
func restartService() {
	if err := utils.CheckAndRequestSudo("Restarting service requires root privileges"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if osType == "darwin" {
		// MacOS launchd command - stop then start
		stopCmd := exec.Command("sudo", "launchctl", "stop", fmt.Sprintf("com.quilibrium.%s", serviceName))
		if err := stopCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error stopping service: %v\n", err)
			return
		}

		startCmd := exec.Command("sudo", "launchctl", "start", fmt.Sprintf("com.quilibrium.%s", serviceName))
		if err := startCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting service: %v\n", err)
			return
		}
	} else {
		// Linux systemd command
		cmd := exec.Command("sudo", "systemctl", "restart", serviceName)
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error restarting service: %v\n", err)
			return
		}
	}

	fmt.Fprintf(os.Stdout, "Restarted Quilibrium node service\n")
}

// reloadService reloads the Quilibrium node service
func reloadService() {
	if err := utils.CheckAndRequestSudo("Reloading service requires root privileges"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if osType == "darwin" {
		// MacOS launchd command - unload then load
		plistPath := fmt.Sprintf("/Library/LaunchDaemons/com.quilibrium.%s.plist", serviceName)
		unloadCmd := exec.Command("sudo", "launchctl", "unload", plistPath)
		if err := unloadCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error unloading service: %v\n", err)
			return
		}

		loadCmd := exec.Command("sudo", "launchctl", "load", plistPath)
		if err := loadCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading service: %v\n", err)
			return
		}

		fmt.Fprintf(os.Stdout, "Reloaded launchd service\n")
	} else {
		// Linux systemd command
		cmd := exec.Command("sudo", "systemctl", "daemon-reload")
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reloading service: %v\n", err)
			return
		}

		fmt.Fprintf(os.Stdout, "Reloaded systemd service\n")
	}
}

// checkServiceStatus checks the status of the Quilibrium node service
func checkServiceStatus() {
	if err := utils.CheckAndRequestSudo("Checking service status requires root privileges"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if osType == "darwin" {
		// MacOS launchd command
		cmd := exec.Command("sudo", "launchctl", "list", fmt.Sprintf("com.quilibrium.%s", serviceName))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error checking service status: %v\n", err)
		}
	} else {
		// Linux systemd command
		cmd := exec.Command("sudo", "systemctl", "status", serviceName)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error checking service status: %v\n", err)
		}
	}
}

// enableService enables the Quilibrium node service to start on boot
func enableService() {
	if err := utils.CheckAndRequestSudo("Enabling service requires root privileges"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if osType == "darwin" {
		// MacOS launchd command - load with -w flag to enable at boot
		plistPath := fmt.Sprintf("/Library/LaunchDaemons/com.quilibrium.%s.plist", serviceName)
		cmd := exec.Command("sudo", "launchctl", "load", "-w", plistPath)
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error enabling service: %v\n", err)
			return
		}
	} else {
		// Linux systemd command
		cmd := exec.Command("sudo", "systemctl", "enable", serviceName)
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error enabling service: %v\n", err)
			return
		}
	}

	fmt.Fprintf(os.Stdout, "Enabled Quilibrium node service to start on boot\n")
}

// disableService disables the Quilibrium node service from starting on boot
func disableService() {
	if err := utils.CheckAndRequestSudo("Disabling service requires root privileges"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if osType == "darwin" {
		// MacOS launchd command - unload with -w flag to disable at boot
		plistPath := fmt.Sprintf("/Library/LaunchDaemons/com.quilibrium.%s.plist", serviceName)
		cmd := exec.Command("sudo", "launchctl", "unload", "-w", plistPath)
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error disabling service: %v\n", err)
			return
		}
	} else {
		// Linux systemd command
		cmd := exec.Command("sudo", "systemctl", "disable", serviceName)
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error disabling service: %v\n", err)
			return
		}
	}

	fmt.Fprintf(os.Stdout, "Disabled Quilibrium node service from starting on boot\n")
}
