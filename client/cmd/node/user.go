package node

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

// createNodeUser creates a dedicated user for running the node
func createNodeUser(nodeUser string) error {
	fmt.Fprintf(os.Stdout, "Creating dedicated user '%s' for running the node...\n", nodeUser)

	// Check for sudo privileges
	if err := utils.CheckAndRequestSudo("Creating system user requires root privileges"); err != nil {
		return fmt.Errorf("failed to get sudo privileges: %w", err)
	}

	if osType == "linux" {
		return createLinuxNodeUser(nodeUser)
	} else if osType == "darwin" {
		return createMacNodeUser(nodeUser)
	} else {
		return fmt.Errorf("User creation not supported on %s", osType)
	}
}

func createLinuxNodeUser(username string) error {
	var cmd *exec.Cmd

	// Check if user already exists
	_, err := user.Lookup(username)
	if err == nil {
		fmt.Fprintf(os.Stdout, "User '%s' already exists\n", username)
		return nil
	}

	// Create user on Linux
	cmd = exec.Command("useradd", "-r", "-s", "/bin/false", "-m", "-c", "Quilibrium Node User", username)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	fmt.Fprintf(os.Stdout, "User '%s' created successfully\n", username)
	return nil
}

func createMacNodeUser(username string) error {
	var cmd *exec.Cmd

	// Check if user already exists
	_, err := user.Lookup(username)
	if err == nil {
		fmt.Fprintf(os.Stdout, "User '%s' already exists\n", username)
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
}
