package config

import (
	"io"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/utils/logging"
)

type LogConfig struct {
	Path       string `yaml:"path"`
	MaxSize    int    `yaml:"maxSize"`
	MaxBackups int    `yaml:"maxBackups"`
	MaxAge     int    `yaml:"maxAge"`
	Compress   bool   `yaml:"compress"`
}

func (c *Config) CreateLogger(coreId uint, debug bool) (
	*zap.Logger,
	io.Closer,
	error,
) {
	filename := c.LogFile
	if filename != "" || c.Logger != nil {
		dir := ""
		if c.Logger != nil {
			dir = c.Logger.Path
		}

		logger, closer, err := logging.NewRotatingFileLogger(
			debug,
			coreId,
			dir,
			filename,
		)
		return logger, closer, errors.Wrap(err, "create logger")
	}

	var logger *zap.Logger
	var err error
	if debug {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}

	return logger, io.NopCloser(nil), errors.Wrap(err, "create logger")
}
