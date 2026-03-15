package utils

import (
	"os"
	"path/filepath"
)

var (
	ClientDataPath            = filepath.Join(BinaryPath, string(ReleaseTypeQClient))
	ClientConfigDir           = filepath.Join(os.Getenv("HOME"), ".quilibrium")
	ClientConfigFile          = string(ReleaseTypeQClient) + "-config.yaml"
	ClientConfigPath          = filepath.Join(ClientConfigDir, ClientConfigFile)
	DefaultQClientSymlinkPath = filepath.Join(DefaultSymlinkDir, string(ReleaseTypeQClient))
)
