package utils

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// DefaultNodeUser is the default user name for node operations
var DefaultNodeUser = "quilibrium"
var ClientConfigDir = filepath.Join("/etc/quilibrium/", "config")
var ClientConfigPath = filepath.Join(ClientConfigDir, string(ReleaseTypeQClient)+".yaml")
var ClientInstallPath = filepath.Join("/opt/quilibrium/", string(ReleaseTypeQClient))
var DataPath = filepath.Join("/var/quilibrium/", "data")
var ClientDataPath = filepath.Join(DataPath, string(ReleaseTypeQClient))
var NodeDataPath = filepath.Join(DataPath, string(ReleaseTypeNode))
var DefaultSymlinkDir = "/usr/local/bin"
var DefaultNodeSymlinkPath = filepath.Join(DefaultSymlinkDir, string(ReleaseTypeNode))
var DefaultQClientSymlinkPath = filepath.Join(DefaultSymlinkDir, string(ReleaseTypeQClient))
var osType = runtime.GOOS
var arch = runtime.GOARCH

// CalculateFileHashes calculates SHA256 and MD5 hashes for a file
func CalculateFileHashes(filePath string) (string, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	// Calculate SHA256
	sha256Hash := sha256.New()
	if _, err := io.Copy(sha256Hash, file); err != nil {
		return "", "", fmt.Errorf("error calculating SHA256: %w", err)
	}

	// Reset file position to beginning for MD5 calculation
	if _, err := file.Seek(0, 0); err != nil {
		return "", "", fmt.Errorf("error seeking file: %w", err)
	}

	// Calculate MD5
	md5Hash := md5.New()
	if _, err := io.Copy(md5Hash, file); err != nil {
		return "", "", fmt.Errorf("error calculating MD5: %w", err)
	}

	return hex.EncodeToString(sha256Hash.Sum(nil)), hex.EncodeToString(md5Hash.Sum(nil)), nil
}

// CreateSymlink creates a symlink, handling the case where it already exists
func CreateSymlink(execPath, targetPath string) error {
	// Check if the symlink already exists
	if _, err := os.Lstat(targetPath); err == nil {
		// Symlink exists, ask if user wants to overwrite
		if !ConfirmSymlinkOverwrite(targetPath) {
			fmt.Println("Operation cancelled.")
			return nil
		}

		// Remove existing symlink
		if err := os.Remove(targetPath); err != nil {
			return fmt.Errorf("failed to remove existing symlink: %w", err)
		}
	}

	// Create the symlink
	if err := os.Symlink(execPath, targetPath); err != nil {
		return fmt.Errorf("failed to create symlink: %w", err)
	}

	return nil
}

// ReadClientConfig reads the client configuration from the specified config directory
// If the config file doesn't exist, it returns an empty config
func ReadClientConfig() (*ClientConfig, error) {
	// Check if config file exists
	if !FileExists(ClientConfigPath) {
		// Return empty config if file doesn't exist
		return &ClientConfig{}, nil
	}

	// Read the config file
	data, err := os.ReadFile(ClientConfigPath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	// Parse YAML
	var config ClientConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("error parsing config file: %w", err)
	}

	return &config, nil
}

// UpdateClientConfig updates the client configuration in the specified config directory
// If the config file doesn't exist, it creates a new one
func UpdateClientConfig(config *ClientConfig) error {
	configDir := ClientConfigDir
	// Check if we need sudo privileges (if config directory is in a system directory)
	if err := CheckAndRequestSudo(fmt.Sprintf("Updating config directory at %s requires root privileges", configDir)); err != nil {
		return fmt.Errorf("failed to get sudo privileges: %w", err)
	}

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configPath := GetConfigPath(configDir)

	// Marshal config to YAML
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("error serializing config: %w", err)
	}

	// Write config to file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("error writing config file: %w", err)
	}

	// Set ownership if a dedicated user was created
	if DefaultNodeUser != "" {
		// Check for sudo privileges for changing ownership
		if err := CheckAndRequestSudo(fmt.Sprintf("Changing ownership of %s requires root privileges", configPath)); err != nil {
			return fmt.Errorf("failed to get sudo privileges: %w", err)
		}

		chownCmd := exec.Command("chown", DefaultNodeUser+":"+DefaultNodeUser, configPath)
		if err := chownCmd.Run(); err != nil {
			return fmt.Errorf("failed to change ownership of config file: %w", err)
		}
	}

	return nil
}

// CreateConfigFile creates a basic configuration file for the node
func CreateConfigFile(configDir, dataDir, version string) {
	// Create a ClientConfig struct
	config := ClientConfig{
		Version:     version,
		DataDir:     ClientDataPath,
		SymlinkPath: DefaultQClientSymlinkPath,
	}

	// Use UpdateClientConfig to save the configuration
	if err := UpdateClientConfig(&config); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to create config file: %v\n", err)
		return
	}

	fmt.Fprintf(os.Stdout, "Created configuration file at %s/config.yaml\n", configDir)
}

// ValidateAndCreateDir validates a directory path and creates it if it doesn't exist
func ValidateAndCreateDir(path string) error {
	// Check if the directory exists
	info, err := os.Stat(path)
	if err == nil {
		// Path exists, check if it's a directory
		if !info.IsDir() {
			return fmt.Errorf("%s exists but is not a directory", path)
		}
		return nil
	}

	// Directory doesn't exist, try to create it
	if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", path, err)
		}
		return nil
	}

	// Some other error occurred
	return fmt.Errorf("error checking directory %s: %v", path, err)
}

// IsWritable checks if a directory is writable
func IsWritable(dir string) bool {
	// Check if directory exists
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}

	// Check if directory is writable by creating a temporary file
	tempFile := filepath.Join(dir, ".quilibrium_write_test")
	file, err := os.Create(tempFile)
	if err != nil {
		return false
	}
	file.Close()
	os.Remove(tempFile)
	return true
}

// CanCreateAndWrite checks if we can create and write to a directory
func CanCreateAndWrite(dir string) bool {
	// Try to create the directory
	if err := os.MkdirAll(dir, 0755); err != nil {
		return false
	}

	// Check if we can write to it
	return IsWritable(dir)
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// GetConfigPath returns the path to the client configuration file
func GetConfigPath(configDir string) string {
	return filepath.Join(configDir, "config.yaml")
}

// IsClientConfigured checks if the client is configured
func IsClientConfigured(configDir string) bool {
	configPath := GetConfigPath(configDir)
	return FileExists(configPath)
}
