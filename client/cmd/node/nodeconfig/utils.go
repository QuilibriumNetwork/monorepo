package nodeconfig

import (
	"os"
)

func ListConfigurations() ([]string, error) {
	files, err := os.ReadDir(ConfigDirs)
	if err != nil {
		return nil, err
	}

	configs := make([]string, 0)
	for _, file := range files {
		if file.IsDir() && file.Name() != "default" {
			configs = append(configs, file.Name())
		}
	}

	return configs, nil
}
