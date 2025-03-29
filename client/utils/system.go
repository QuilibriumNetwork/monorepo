package utils

import (
	"fmt"
	"runtime"
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
