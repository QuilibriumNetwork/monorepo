package nodeconfig

import (
	"os"

	"source.quilibrium.com/quilibrium/monorepo/client/utils"
)

func ListConfigurations() ([]string, error) {
	files, err := os.ReadDir(ConfigDirs)
	if err != nil {
		return nil, err
	}

	configs := make([]string, 0)
	for _, file := range files {
		if file.IsDir() && file.Name() != utils.ReservedDefaultConfigName {
			configs = append(configs, file.Name())
		}
	}

	return configs, nil
}
