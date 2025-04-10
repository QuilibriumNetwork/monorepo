package nodeconfig

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

func ListConfigurations() ([]string, error) {
	files, err := os.ReadDir(ConfigDirs)
	if err != nil {
		return nil, err
	}

	configs := make([]string, 0)
	for _, file := range files {
		if file.IsDir() {
			configs = append(configs, file.Name())
		}
	}

	return configs, nil
}
