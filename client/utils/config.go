package utils

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

var ClientConfigDir = filepath.Join("/etc/quilibrium/", "config")
var ClientConfigFile = string(ReleaseTypeQClient) + ".yaml"
var ClientConfigPath = filepath.Join(ClientConfigDir, ClientConfigFile)

// var clientConfig = &ClientConfig{}

func CreateDefaultConfig() {
	fmt.Printf("Creating default config: %s\n", ClientConfigPath)
	SaveClientConfig(&ClientConfig{
		DataDir:        ClientDataPath,
		SymlinkPath:    DefaultQClientSymlinkPath,
		SignatureCheck: true,
	})
}

// LoadClientConfig loads the client configuration from the config file
func LoadClientConfig() (*ClientConfig, error) {
	// Create default config if it doesn't exist
	if _, err := os.Stat(ClientConfigPath); os.IsNotExist(err) {
		config := &ClientConfig{
			DataDir:        ClientDataPath,
			SymlinkPath:    filepath.Join(ClientDataPath, "current"),
			SignatureCheck: true,
		}
		if err := SaveClientConfig(config); err != nil {
			return nil, err
		}
		return config, nil
	}

	// Read existing config
	data, err := os.ReadFile(ClientConfigPath)
	if err != nil {
		return nil, err
	}

	config := &ClientConfig{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, err
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
	if err := os.MkdirAll(ClientConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	return os.WriteFile(ClientConfigPath, data, 0644)
}

// GetConfigPath returns the path to the client configuration file
func GetConfigPath() string {
	return ClientConfigPath
}

// IsClientConfigured checks if the client is configured
func IsClientConfigured() bool {
	return FileExists(ClientConfigPath)
}
