package utils

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

var ClientConfigDir = filepath.Join(os.Getenv("HOME"), ".quilibrium")
var ClientConfigFile = string(ReleaseTypeQClient) + "-config.yaml"
var ClientConfigPath = filepath.Join(ClientConfigDir, ClientConfigFile)

func CreateDefaultConfig() {
	configPath := GetConfigPath()

	fmt.Printf("Creating default config: %s\n", configPath)
	SaveClientConfig(&ClientConfig{
		DataDir:        ClientDataPath,
		SymlinkPath:    DefaultQClientSymlinkPath,
		SignatureCheck: true,
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

	// Create default config if it doesn't exist
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
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
	data, err := os.ReadFile(configPath)
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
