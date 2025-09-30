package config

import "path/filepath"

// Simple configuration for store of alias mappings
type AliasConfig struct {
	AliasFile *AliasFileConfig `yaml:"aliasFile"`
}

type AliasFileConfig struct {
	Path            string `yaml:"path"`
	CreateIfMissing bool   `yaml:"createIfMissing"`
}

// WithDefaults returns a copy of the AliasConfig with any missing fields set to
// their default values.
func (c AliasConfig) WithDefaults(configPath string) AliasConfig {
	cpy := c
	if cpy.AliasFile == nil {
		cpy.AliasFile = &AliasFileConfig{}
	}
	if cpy.AliasFile.Path == "" {
		cpy.AliasFile.Path = filepath.Join(configPath, "alias.yml")
		cpy.AliasFile.CreateIfMissing = true
	}

	return cpy
}
