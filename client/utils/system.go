package utils

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
)

var (
	OsType = runtime.GOOS
	Arch   = runtime.GOARCH
)

// GetSystemInfo determines and validates the OS and architecture
func GetSystemInfo() (string, string, error) {
	// Check if OS type is supported
	if OsType != "darwin" && OsType != "linux" {
		return "", "", fmt.Errorf("unsupported operating system: %s", OsType)
	}

	// Map Go architecture names to Quilibrium architecture names
	if Arch == "amd64" {
		Arch = "amd64"
	} else if Arch == "arm64" {
		Arch = "arm64"
	} else {
		return "", "", fmt.Errorf("unsupported architecture: %s", Arch)
	}

	return OsType, Arch, nil
}

func GetCurrentSudoUser() (*user.User, error) {
	if os.Geteuid() != 0 {
		return user.Current()
	}

	username := os.Getenv("SUDO_USER")
	if username == "" {
		username = "root"
	}

	userLookup, err := user.Lookup(username)
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
