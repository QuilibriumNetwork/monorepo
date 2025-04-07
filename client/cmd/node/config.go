package node

import (
	"fmt"
	"os"

	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

func LoadConfig(configDirectory string) (*config.Config, error) {
	NodeConfig, err := config.LoadConfig(configDirectory, "", false)
	if err != nil {
		fmt.Printf("invalid config directory: %s\n", configDirectory)
		os.Exit(1)
	}
	return NodeConfig, nil
}
