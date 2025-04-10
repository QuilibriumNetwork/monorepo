package node

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
// func confirmPaths(installPath, dataPath string) bool {
// 	fmt.Print("Do you want to continue with these paths? [Y/n]: ")
// 	reader := bufio.NewReader(os.Stdin)
// 	response, _ := reader.ReadString('\n')
// 	response = strings.TrimSpace(strings.ToLower(response))

// 	return response == "" || response == "y" || response == "yes"
// }

// setOwnership sets the ownership of directories to the node user
func setOwnership() {

	// Change ownership of installation directory
	err := utils.ChownPath(utils.NodeDataPath, NodeUser, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to change ownership of %s: %v\n", utils.NodeDataPath, err)
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
}`, logPath, NodeUser.Username, NodeUser.Username)

	// Write the configuration file
	configPath := "/etc/logrotate.d/quilibrium-node"
	if err := utils.WriteFile(configPath, configContent); err != nil {
		return fmt.Errorf("failed to create logrotate configuration: %w", err)
	}

	// Create log directory with proper permissions
	if err := utils.ValidateAndCreateDir(logPath, NodeUser); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Set ownership of log directory
	err := utils.ChownPath(logPath, NodeUser, true)
	if err != nil {
		return fmt.Errorf("failed to set log directory ownership: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Created log rotation configuration at %s\n", configPath)
	return nil
}

// finishInstallation completes the installation process by making the binary executable and creating a symlink
func finishInstallation(version string) {
	setOwnership()

	normalizedBinaryName := "node-" + version + "-" + OsType + "-" + Arch

	// Finish installation
	nodeBinaryPath := filepath.Join(utils.NodeDataPath, version, normalizedBinaryName)
	fmt.Printf("Making binary executable: %s\n", nodeBinaryPath)
	// Make the binary executable
	if err := utils.ChmodPath(nodeBinaryPath, 0755, "executable"); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to make binary executable: %v\n", err)
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

	// Print success message
	printSuccessMessage(version)
}

// printSuccessMessage prints a success message after installation
func printSuccessMessage(version string) {
	fmt.Fprintf(os.Stdout, "\nSuccessfully installed Quilibrium node %s\n", version)
	fmt.Fprintf(os.Stdout, "Binary download directory: %s\n", filepath.Join(utils.NodeDataPath, version))
	fmt.Fprintf(os.Stdout, "Binary symlinked to %s\n", defaultSymlinkPath)
	fmt.Fprintf(os.Stdout, "Log directory: %s\n", logPath)
	fmt.Fprintf(os.Stdout, "Environment file: /etc/default/quilibrium-node\n")
	fmt.Fprintf(os.Stdout, "Service file: /etc/systemd/system/quilibrium-node.service\n")

	fmt.Fprintf(os.Stdout, "\nConfiguration:\n")
	fmt.Fprintf(os.Stdout, "  To create a new configuration:\n")
	fmt.Fprintf(os.Stdout, "    qclient node config create [name] --default\n")
	fmt.Fprintf(os.Stdout, "    quilibrium-node --peer-id %s/default-config\n", ConfigDirs)

	fmt.Fprintf(os.Stdout, "\n  To use an existing configuration:\n")
	fmt.Fprintf(os.Stdout, "    cp -r /path/to/your/existing/config %s/default-config\n", ConfigDirs)
	fmt.Fprintf(os.Stdout, "    # Or modify the service file to point to your existing config:\n")
	fmt.Fprintf(os.Stdout, "    sudo nano /etc/systemd/system/quilibrium-node.service\n")
	fmt.Fprintf(os.Stdout, "    # Then reload systemd:\n")
	fmt.Fprintf(os.Stdout, "    sudo systemctl daemon-reload\n")

	fmt.Fprintf(os.Stdout, "\nTo select a configuration:\n")
	fmt.Fprintf(os.Stdout, "  qclient node config switch <config-name>\n")
	fmt.Fprintf(os.Stdout, "  # Or use the --default flag when creating a config to automatically select it:\n")
	fmt.Fprintf(os.Stdout, "  qclient node config create --default\n")

	fmt.Fprintf(os.Stdout, "\nTo manually start the node (must create a config first), you can run:\n")
	fmt.Fprintf(os.Stdout, "  %s --config %s/myconfig/\n",
		ServiceName, ConfigDirs)
	fmt.Fprintf(os.Stdout, "  # Or use systemd service using the default config:\n")
	fmt.Fprintf(os.Stdout, "  sudo systemctl start quilibrium-node\n")

	fmt.Fprintf(os.Stdout, "\nFor more options, run:\n")
	fmt.Fprintf(os.Stdout, "  quilibrium-node --help\n")
}
