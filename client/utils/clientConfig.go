package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

func CreateDefaultConfig() {
	configPath := GetConfigPath()

	fmt.Printf("Creating default config: %s\n", configPath)
	SaveClientConfig(&ClientConfig{
		DataDir:        ClientDataPath,
		SymlinkPath:    DefaultQClientSymlinkPath,
		SignatureCheck: true,
		PublicRpc:      false,
		CustomRpc:      "",
		AddressList:    make(map[string]string),
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
			PublicRpc:      false,
			CustomRpc:      "",
			AddressList:    make(map[string]string),
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

func GetAddressList() (map[string]string, error) {
	config, err := LoadClientConfig()
	if err != nil {
		return nil, err
	}

	// Check if AddressList is nil, and initialize it if necessary
	if config.AddressList == nil {
		config.AddressList = make(map[string]string)
	}

	// Get list of configs in ConfigDir (excluding default)
	configDir := GetConfigDir()
	if configDir == "" {
		configDir = filepath.Join(GetUserQuilibriumDir(), "configs")
	}

	files, err := os.ReadDir(configDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read config directory: %w", err)
	}

	for _, file := range files {
		if !file.IsDir() || file.Name() == ReservedDefaultConfigName {
			continue
		}

		tempConfig, err := LoadNodeConfig(file.Name())
		if err != nil {
			continue // Skip files that can't be parsed
		}

		address, err := GetAccountFromNodeConfig(tempConfig)
		if err != nil {
			continue // Skip files that can't be parsed
		}

		// Extract address from filename or content if available
		name := strings.TrimSuffix(file.Name(), filepath.Ext(file.Name()))
		if _, ok := config.AddressList[name]; ok {
			config.AddressList[name] = string(address)
		}
	}
	return config.AddressList, nil
}
