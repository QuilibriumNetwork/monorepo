package utils

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

func CreateDefaultConfig() {
	configPath := GetConfigPath()

	fmt.Printf("Creating default config: %s\n", configPath)
	// Leave NodeInstallDir / NodeStateDir / NodeSymlinkDir empty here so
	// the OS-aware helpers in paths.go supply the current defaults
	// lazily. Persisting them would pin the user to whatever default
	// was in effect at config-creation time.
	SaveClientConfig(&ClientConfig{
		DataDir:         ClientDataPath,
		SymlinkPath:     DefaultQClientSymlinkPath,
		SignatureCheck:  true,
		PublicRpc:       false,
		CustomRpc:       "",
		NodeServiceName: DefaultNodeServiceName,
	})

	sudoUser, err := GetCurrentSudoUser()
	if err != nil {
		fmt.Println("Error getting current sudo user")
		os.Exit(1)
	}
	ChownPath(GetUserQuilibriumDir(), sudoUser, true)
}

// LoadClientConfig loads the client configuration from the config file
func LoadClientConfig() (*ClientConfig, error) {
	configPath := GetConfigPath()

	// Create default config if it doesn't exist. Leave the node path
	// fields empty so OS-aware defaults from paths.go apply lazily.
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		config := &ClientConfig{
			DataDir:         ClientDataPath,
			SymlinkPath:     filepath.Join(ClientDataPath, "current"),
			SignatureCheck:  true,
			PublicRpc:       false,
			CustomRpc:       "",
			NodeServiceName: DefaultNodeServiceName,
		}
		if err := SaveClientConfig(config); err != nil {
			return nil, err
		}
		return config, nil
	}

	// Read existing config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	config := &ClientConfig{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, err
	}

	// Backfill fields that may be missing from older configs. Only
	// backfill the service name here; leave NodeInstallDir /
	// NodeStateDir / NodeSymlinkDir empty so the OS-aware path
	// accessors apply current defaults. Older configs that already
	// have an explicit NodeInstallDir (e.g. the legacy
	// /var/quilibrium) keep their persisted value untouched.
	if config.NodeServiceName == "" {
		config.NodeServiceName = DefaultNodeServiceName
	}

	return config, nil
}

// SaveClientConfig saves the client configuration to the config file
func SaveClientConfig(config *ClientConfig) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	// Ensure the config directory exists
	if err := os.MkdirAll(GetConfigDir(), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	return os.WriteFile(GetConfigPath(), data, 0644)
}

// GetConfigPath returns the path to the client configuration file
func GetConfigPath() string {
	return filepath.Join(GetConfigDir(), ClientConfigFile)
}

func GetConfigDir() string {
	return filepath.Join(GetUserQuilibriumDir())
}

// IsClientConfigured checks if the client is configured
func IsClientConfigured() bool {
	return FileExists(ClientConfigPath)
}
