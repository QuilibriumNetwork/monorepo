package config

import (
	"os"
	"path/filepath"
)

// HasConfigFiles checks if a directory contains both config.yml and keys.yml files
func HasConfigFiles(dirPath string) bool {
	configPath := filepath.Join(dirPath, "config.yml")
	keysPath := filepath.Join(dirPath, "keys.yml")

	// Check if both files exist
	configExists := false
	keysExists := false

	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		configExists = true
	}

	if _, err := os.Stat(keysPath); !os.IsNotExist(err) {
		keysExists = true
	}

	return configExists && keysExists
}
