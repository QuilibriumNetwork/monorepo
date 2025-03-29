package node

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

// determineVersion gets the version to install from args or defaults to "latest"
func determineVersion(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return "latest"
}

// confirmPaths asks the user to confirm the installation and data paths
func confirmPaths(installPath, dataPath string) bool {
	fmt.Print("Do you want to continue with these paths? [Y/n]: ")
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))

	return response == "" || response == "y" || response == "yes"
}

// createNodeUser creates a dedicated user for running the node
func createNodeUser() error {
	fmt.Fprintf(os.Stdout, "Creating dedicated user '%s' for running the node...\n", nodeUser)

	// Check for sudo privileges
	if err := utils.CheckAndRequestSudo("Creating system user requires root privileges"); err != nil {
		return fmt.Errorf("failed to get sudo privileges: %w", err)
	}

	var cmd *exec.Cmd

	if osType == "linux" {
		// Check if user already exists
		checkCmd := exec.Command("id", nodeUser)
		if checkCmd.Run() == nil {
			fmt.Fprintf(os.Stdout, "User '%s' already exists\n", nodeUser)
			return nil
		}

		// Create user on Linux
		cmd = exec.Command("useradd", "-r", "-s", "/bin/false", "-m", "-c", "Quilibrium Node User", nodeUser)
	} else if osType == "darwin" {
		// Check if user already exists on macOS
		checkCmd := exec.Command("dscl", ".", "-read", "/Users/"+nodeUser)
		if checkCmd.Run() == nil {
			fmt.Fprintf(os.Stdout, "User '%s' already exists\n", nodeUser)
			return nil
		}

		// Create user on macOS
		// Get next available user ID
		uidCmd := exec.Command("dscl", ".", "-list", "/Users", "UniqueID")
		uidOutput, err := uidCmd.Output()
		if err != nil {
			return fmt.Errorf("failed to get user IDs: %v", err)
		}

		// Find the highest UID and add 1
		var maxUID int = 500 // Start with a reasonable system UID
		for _, line := range strings.Split(string(uidOutput), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				var uid int
				fmt.Sscanf(fields[len(fields)-1], "%d", &uid)
				if uid > maxUID && uid < 65000 { // Avoid system UIDs
					maxUID = uid
				}
			}
		}
		nextUID := maxUID + 1

		// Create the user
		cmd = exec.Command("dscl", ".", "-create", "/Users/"+nodeUser)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("Failed to create user: %v", err)
		}

		// Set the user's properties
		commands := [][]string{
			{"-create", "/Users/" + nodeUser, "UniqueID", fmt.Sprintf("%d", nextUID)},
			{"-create", "/Users/" + nodeUser, "PrimaryGroupID", "20"}, // staff group
			{"-create", "/Users/" + nodeUser, "UserShell", "/bin/false"},
			{"-create", "/Users/" + nodeUser, "NFSHomeDirectory", "/var/empty"},
			{"-create", "/Users/" + nodeUser, "RealName", "Quilibrium Node User"},
		}

		for _, args := range commands {
			cmd = exec.Command("dscl", append([]string{"."}, args...)...)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to set user property %s: %v", args[1], err)
			}
		}

		// Disable the user account
		cmd = exec.Command("dscl", ".", "-create", "/Users/"+nodeUser, "Password", "*")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to disable user account: %v", err)
		}

		return nil
	} else {
		return fmt.Errorf("user creation not supported on %s", osType)
	}

	// Run the command
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	fmt.Fprintf(os.Stdout, "User '%s' created successfully\n", nodeUser)
	return nil
}

// setOwnership sets the ownership of directories to the node user
func setOwnership() {
	fmt.Fprintf(os.Stdout, "Setting ownership of %s and %s to %s...\n", installPath, dataPath, nodeUser)

	// Change ownership of installation directory
	chownCmd := exec.Command("chown", "-R", nodeUser+":"+nodeUser, installPath)
	if err := chownCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to change ownership of %s: %v\n", installPath, err)
	}

	// Change ownership of data directory
	chownCmd = exec.Command("chown", "-R", nodeUser+":"+nodeUser, dataPath)
	if err := chownCmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to change ownership of %s: %v\n", dataPath, err)
	}
}

// setupLogRotation creates a logrotate configuration file for the Quilibrium node
func setupLogRotation() error {
	// Check if we need sudo privileges for creating logrotate config
	if err := utils.CheckAndRequestSudo("Creating logrotate configuration requires root privileges"); err != nil {
		return fmt.Errorf("failed to get sudo privileges: %w", err)
	}

	// Create logrotate configuration
	configContent := fmt.Sprintf(`%s/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 %s %s
    postrotate
        systemctl reload quilibrium-node >/dev/null 2>&1 || true
    endscript
}`, logPath, nodeUser, nodeUser)

	// Write the configuration file
	configPath := "/etc/logrotate.d/quilibrium-node"
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("failed to create logrotate configuration: %w", err)
	}

	// Create log directory with proper permissions
	if err := os.MkdirAll(logPath, 0750); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Set ownership of log directory
	chownCmd := exec.Command("chown", nodeUser+":"+nodeUser, logPath)
	if err := chownCmd.Run(); err != nil {
		return fmt.Errorf("failed to set log directory ownership: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Created log rotation configuration at %s\n", configPath)
	return nil
}

// finishInstallation completes the installation process by making the binary executable and creating a symlink
func finishInstallation(nodeBinaryPath string, version string) {

	setOwnership()

	// Make the binary executable
	if err := os.Chmod(nodeBinaryPath, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error making binary executable: %v\n", err)
		return
	}

	// Check if we need sudo privileges for creating symlink in system directory
	if strings.HasPrefix(defaultSymlinkPath, "/usr/") || strings.HasPrefix(defaultSymlinkPath, "/bin/") || strings.HasPrefix(defaultSymlinkPath, "/sbin/") {
		if err := utils.CheckAndRequestSudo(fmt.Sprintf("Creating symlink at %s requires root privileges", defaultSymlinkPath)); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to get sudo privileges: %v\n", err)
			return
		}
	}

	// Create symlink using the utils package
	if err := utils.CreateSymlink(nodeBinaryPath, defaultSymlinkPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating symlink: %v\n", err)
	}

	// Set up log rotation
	if err := setupLogRotation(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to set up log rotation: %v\n", err)
	}

	// Create systemd service file
	if osType == "linux" {
		if err := createSystemdServiceFile(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to create systemd service file: %v\n", err)
		}
	} else if osType == "darwin" {
		installMacOSService()
	} else {
		fmt.Fprintf(os.Stderr, "Warning: Background service file creation not supported on %s\n", osType)
		return
	}

	// Print success message
	printSuccessMessage(version)
}

// printSuccessMessage prints a success message after installation
func printSuccessMessage(version string) {
	fmt.Fprintf(os.Stdout, "\nSuccessfully installed Quilibrium node %s\n", version)
	fmt.Fprintf(os.Stdout, "Installation directory: %s\n", installPath)
	fmt.Fprintf(os.Stdout, "Data directory: %s\n", dataPath)
	fmt.Fprintf(os.Stdout, "Binary symlinked to %s\n", defaultSymlinkPath)
	fmt.Fprintf(os.Stdout, "Log directory: %s\n", logPath)
	fmt.Fprintf(os.Stdout, "Environment file: /etc/default/quilibrium-node\n")
	fmt.Fprintf(os.Stdout, "Service file: /etc/systemd/system/quilibrium-node.service\n")

	fmt.Fprintf(os.Stdout, "\nTo start the node, you can run:\n")
	fmt.Fprintf(os.Stdout, "  %s --config %s/config/config.yaml\n",
		defaultSymlinkPath, dataPath)
	fmt.Fprintf(os.Stdout, "  # Or use systemd service:\n")
	fmt.Fprintf(os.Stdout, "  sudo systemctl start quilibrium-node\n")

	fmt.Fprintf(os.Stdout, "\nFor more options, run:\n")
	fmt.Fprintf(os.Stdout, "  quilibrium-node --help\n")
}

// createSystemdServiceFile creates the systemd service file with environment file support
func createSystemdServiceFile() error {
	// Check if we need sudo privileges
	if err := utils.CheckAndRequestSudo("Creating systemd service file requires root privileges"); err != nil {
		return fmt.Errorf("failed to get sudo privileges: %w", err)
	}

	// Create environment file content
	envContent := fmt.Sprintf(`# Quilibrium Node Environment`, dataPath)

	// Write environment file
	envPath := filepath.Join(dataPath, "config", "quilibrium.env")
	if err := os.WriteFile(envPath, []byte(envContent), 0640); err != nil {
		return fmt.Errorf("failed to create environment file: %w", err)
	}

	// Set ownership of environment file
	chownCmd := exec.Command("chown", nodeUser+":"+nodeUser, envPath)
	if err := chownCmd.Run(); err != nil {
		return fmt.Errorf("failed to set environment file ownership: %w", err)
	}

	// Create systemd service file content
	serviceContent := fmt.Sprintf(`[Unit]
Description=Quilibrium Node Service
After=network.target

[Service]
Type=simple
User=quilibrium
EnvironmentFile=/opt/quilibrium/config/quilibrium.env
ExecStart=/usr/local/bin/quilibrium-node --config /opt/quilibrium/config
Restart=on-failure
RestartSec=10
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`, nodeUser, defaultSymlinkPath, dataPath)

	// Write service file
	servicePath := "/etc/systemd/system/quilibrium-node.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to create service file: %w", err)
	}

	// Reload systemd daemon
	reloadCmd := exec.Command("systemctl", "daemon-reload")
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
		DataPath:    dataPath,
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
