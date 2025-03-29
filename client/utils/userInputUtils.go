package utils

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ConfirmSymlinkOverwrite asks the user to confirm overwriting an existing symlink
func ConfirmSymlinkOverwrite(path string) bool {
	fmt.Printf("Symlink already exists at %s. Overwrite? [y/N]: ", path)
	var response string
	fmt.Scanln(&response)
	return strings.ToLower(response) == "y"
}

// CheckAndRequestSudo checks if we have sudo privileges and requests them if needed
func CheckAndRequestSudo(reason string) error {
	// Check if we're already root
	if os.Geteuid() == 0 {
		return nil
	}

	// Check if sudo is available
	if _, err := exec.LookPath("sudo"); err != nil {
		return fmt.Errorf("sudo is not available: %w", err)
	}

	// Request sudo privileges
	cmd := exec.Command("sudo", "-v")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to get sudo privileges: %w", err)
	}

	return nil
}
