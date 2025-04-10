package utils

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// GetSystemInfo determines and validates the OS and architecture
func GetSystemInfo() (string, string, error) {
	osType := runtime.GOOS
	arch := runtime.GOARCH

	// Check if OS type is supported
	if osType != "darwin" && osType != "linux" {
		return "", "", fmt.Errorf("unsupported operating system: %s", osType)
	}

	// Map Go architecture names to Quilibrium architecture names
	if arch == "amd64" {
		arch = "amd64"
	} else if arch == "arm64" {
		arch = "arm64"
	} else {
		return "", "", fmt.Errorf("unsupported architecture: %s", arch)
	}

	return osType, arch, nil
}

func GetCurrentSudoUser() (*user.User, error) {
	if os.Geteuid() != 0 {
		return user.Current()
	}

	cmd := exec.Command("sh", "-c", "env | grep SUDO_USER | cut -d= -f2 | cut -d\\n -f1")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to get current sudo user: %v", err)
	}

	userLookup, err := user.Lookup(strings.TrimSpace(out.String()))
	if err != nil {
		return nil, fmt.Errorf("failed to get current sudo user: %v", err)
	}
	return userLookup, nil
}

func GetUserQuilibriumDir() string {
	sudoUser, err := GetCurrentSudoUser()
	if err != nil {
		fmt.Println("Error getting current sudo user")
		os.Exit(1)
	}

	return filepath.Join(sudoUser.HomeDir, ".quilibrium")
}
