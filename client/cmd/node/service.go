package node

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"

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

	fmt.Fprintf(os.Stdout, "Installing Quilibrium node service for %s...\n", OsType)

	if OsType == "darwin" {
		// launchctl is already installed on macOS by default, so no need to check for it
		installMacOSService()
	} else if OsType == "linux" {
		// systemd is not installed on linux by default, so we need to check for it
		if !utils.CheckForSystemd() {
			// install systemd if not found
			installSystemd()
		}
		if err := createSystemdServiceFile(); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating systemd service file: %v\n", err)
			return
		}
	} else {
		fmt.Fprintf(os.Stderr, "Error: Unsupported operating system: %s\n", OsType)
		return
	}

	fmt.Fprintf(os.Stdout, "Quilibrium node service installed successfully\n")
}

func installSystemd() {
	fmt.Fprintf(os.Stdout, "Installing systemd...\n")
	updateCmd := exec.Command("sudo", "apt-get", "update")
	updateCmd.Stdout = nil
	updateCmd.Stderr = nil
	if err := updateCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error updating package lists: %v\n", err)
		return
	}

	installCmd := exec.Command("sudo", "apt-get", "install", "-y", "systemd")
	installCmd.Stdout = nil
	installCmd.Stderr = nil
	if err := installCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error installing systemd: %v\n", err)
		return
	}
}

// startService starts the Quilibrium node service
func startService() {
	if err := utils.CheckAndRequestSudo("Starting service requires root privileges"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	if OsType == "darwin" {
		// MacOS launchd command
		cmd := exec.Command("sudo", "launchctl", "start", fmt.Sprintf("com.quilibrium.%s", ServiceName))
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting service: %v\n", err)
			return
		}
	} else {
		// Linux systemd command
		cmd := exec.Command("sudo", "systemctl", "start", ServiceName)
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

	if OsType == "darwin" {
		// MacOS launchd command
		cmd := exec.Command("sudo", "launchctl", "stop", fmt.Sprintf("com.quilibrium.%s", ServiceName))
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error stopping service: %v\n", err)
			return
		}
	} else {
		// Linux systemd command
		cmd := exec.Command("sudo", "systemctl", "stop", ServiceName)
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

	if OsType == "darwin" {
		// MacOS launchd command - stop then start
		stopCmd := exec.Command("sudo", "launchctl", "stop", fmt.Sprintf("com.quilibrium.%s", ServiceName))
		if err := stopCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error stopping service: %v\n", err)
			return
		}

		startCmd := exec.Command("sudo", "launchctl", "start", fmt.Sprintf("com.quilibrium.%s", ServiceName))
		if err := startCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting service: %v\n", err)
			return
		}
	} else {
		// Linux systemd command
		cmd := exec.Command("sudo", "systemctl", "restart", ServiceName)
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

	if OsType == "darwin" {
		// MacOS launchd command - unload then load
		plistPath := fmt.Sprintf("/Library/LaunchDaemons/com.quilibrium.%s.plist", ServiceName)
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

	if OsType == "darwin" {
		// MacOS launchd command
		cmd := exec.Command("sudo", "launchctl", "list", fmt.Sprintf("com.quilibrium.%s", ServiceName))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error checking service status: %v\n", err)
		}
	} else {
		// Linux systemd command
		cmd := exec.Command("sudo", "systemctl", "status", ServiceName)
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

	if OsType == "darwin" {
		// MacOS launchd command - load with -w flag to enable at boot
		plistPath := fmt.Sprintf("/Library/LaunchDaemons/com.quilibrium.%s.plist", ServiceName)
		cmd := exec.Command("sudo", "launchctl", "load", "-w", plistPath)
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error enabling service: %v\n", err)
			return
		}
	} else {
		// Linux systemd command
		cmd := exec.Command("sudo", "systemctl", "enable", ServiceName)
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

	if OsType == "darwin" {
		// MacOS launchd command - unload with -w flag to disable at boot
		plistPath := fmt.Sprintf("/Library/LaunchDaemons/com.quilibrium.%s.plist", ServiceName)
		cmd := exec.Command("sudo", "launchctl", "unload", "-w", plistPath)
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error disabling service: %v\n", err)
			return
		}
	} else {
		// Linux systemd command
		cmd := exec.Command("sudo", "systemctl", "disable", ServiceName)
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error disabling service: %v\n", err)
			return
		}
	}

	fmt.Fprintf(os.Stdout, "Disabled Quilibrium node service from starting on boot\n")
}

func createService() {
	// Create systemd service file
	if OsType == "linux" {
		if err := createSystemdServiceFile(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to create systemd service file: %v\n", err)
		}
	} else if OsType == "darwin" {
		installMacOSService()
	} else {
		fmt.Fprintf(os.Stderr, "Warning: Background service file creation not supported on %s\n", OsType)
		return
	}
}

// createSystemdServiceFile creates the systemd service file with environment file support
func createSystemdServiceFile() error {
	if !utils.CheckForSystemd() {
		installSystemd()
	}

	// Check if we need sudo privileges
	if err := utils.CheckAndRequestSudo("Creating systemd service file requires root privileges"); err != nil {
		return fmt.Errorf("failed to get sudo privileges: %w", err)
	}

	// Create environment file content
	envContent := `# Quilibrium Node Environment`

	// Write environment file
	envPath := filepath.Join(utils.RootQuilibriumPath, "quilibrium.env")
	if err := os.WriteFile(envPath, []byte(envContent), 0640); err != nil {
		return fmt.Errorf("failed to create environment file: %w", err)
	}

	// Set ownership of environment file
	chownCmd := utils.ChownPath(envPath, NodeUser, false)
	if chownCmd != nil {
		return fmt.Errorf("failed to set environment file ownership: %w", chownCmd)
	}

	// Create systemd service file content
	serviceContent := fmt.Sprintf(`[Unit]
Description=Quilibrium Node Service
After=network.target

[Service]
Type=simple
User=quilibrium
EnvironmentFile=/opt/quilibrium/config/quilibrium.env
ExecStart=/usr/local/bin/quilibrium-node --config %s
Restart=on-failure
RestartSec=10
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`, ConfigDirs+"/default")

	// Write service file
	servicePath := "/etc/systemd/system/quilibrium-node.service"
	if err := utils.WriteFileAuto(servicePath, serviceContent); err != nil {
		return fmt.Errorf("failed to create service file: %w", err)
	}

	// Reload systemd daemon
	reloadCmd := exec.Command("sudo", "systemctl", "daemon-reload")
	if err := reloadCmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Created systemd service file at %s\n", servicePath)
	fmt.Fprintf(os.Stdout, "Created environment file at %s\n", envPath)
	return nil
}

// installMacOSService installs a launchd service on macOS
func installMacOSService() {
	fmt.Println("Installing launchd service for Quilibrium node...")

	// Create plist file content
	plistTemplate := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{.Label}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/local/bin/quilibrium-node</string>
		<string>--config</string>
		<string>/opt/quilibrium/config/</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>QUILIBRIUM_DATA_DIR</key>
		<string>{{.DataPath}}</string>
		<key>QUILIBRIUM_LOG_LEVEL</key>
		<string>info</string>
		<key>QUILIBRIUM_LISTEN_GRPC_MULTIADDR</key>
		<string>/ip4/127.0.0.1/tcp/8337</string>
		<key>QUILIBRIUM_LISTEN_REST_MULTIADDR</key>
		<string>/ip4/127.0.0.1/tcp/8338</string>
		<key>QUILIBRIUM_STATS_MULTIADDR</key>
		<string>/dns/stats.quilibrium.com/tcp/443</string>
		<key>QUILIBRIUM_NETWORK_ID</key>
		<string>0</string>
		<key>QUILIBRIUM_DEBUG</key>
		<string>false</string>
		<key>QUILIBRIUM_SIGNATURE_CHECK</key>
		<string>true</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardErrorPath</key>
	<string>{{.LogPath}}/node.err</string>
	<key>StandardOutPath</key>
	<string>{{.LogPath}}/node.log</string>
</dict>
</plist>`

	// Prepare template data
	data := struct {
		Label       string
		DataPath    string
		ServiceName string
		LogPath     string
	}{
		Label:       fmt.Sprintf("com.quilibrium.node"),
		DataPath:    utils.NodeDataPath,
		ServiceName: "node",
		LogPath:     logPath,
	}

	// Parse and execute template
	tmpl, err := template.New("plist").Parse(plistTemplate)
	if err != nil {
		fmt.Printf("Error creating plist template: %v\n", err)
		return
	}

	// Determine plist file path
	var plistPath = fmt.Sprintf("/Library/LaunchDaemons/%s.plist", data.Label)

	// Write plist file
	file, err := os.Create(plistPath)
	if err != nil {
		fmt.Printf("Error creating plist file: %v\n", err)
		return
	}
	defer file.Close()

	if err := tmpl.Execute(file, data); err != nil {
		fmt.Printf("Error writing plist file: %v\n", err)
		return
	}

	// Set correct permissions
	chownCmd := exec.Command("chown", "root:wheel", plistPath)
	if err := chownCmd.Run(); err != nil {
		fmt.Printf("Warning: Failed to change ownership of plist file: %v\n", err)
	}

	// Load the service
	var loadCmd = exec.Command("launchctl", "load", "-w", plistPath)

	if err := loadCmd.Run(); err != nil {
		fmt.Printf("Error loading service: %v\n", err)
		fmt.Println("You may need to load the service manually.")
	}

	fmt.Printf("Launchd service installed successfully as %s\n", plistPath)
	fmt.Println("\nTo start the service:")
	fmt.Printf("  sudo launchctl start %s\n", data.Label)
	fmt.Println("\nTo stop the service:")
	fmt.Printf("  sudo launchctl stop %s\n", data.Label)
	fmt.Println("\nTo view service logs:")
	fmt.Printf("  cat %s/%s.log\n", data.LogPath, data.ServiceName)
}
