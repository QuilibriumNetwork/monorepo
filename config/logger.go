package config

import (
	"io"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"source.quilibrium.com/quilibrium/monorepo/utils/logging"
)

type LogConfig struct {
	Path       string            `yaml:"path"`
	MaxSize    int               `yaml:"maxSize"`
	MaxBackups int               `yaml:"maxBackups"`
	MaxAge     int               `yaml:"maxAge"`
	Compress   bool              `yaml:"compress"`
	LogFilters map[string]string `yaml:"logFilters"`
}

func (c *Config) CreateLogger(
	coreId uint,
	debug bool,
	cliLogFilters map[string]string,
) (
	*zap.Logger,
	io.Closer,
	error,
) {
	// Merge config file filters with CLI overrides (CLI wins).
	merged := make(map[string]string)
	if c.Logger != nil {
		for k, v := range c.Logger.LogFilters {
			merged[k] = v
		}
	}
	for k, v := range cliLogFilters {
		merged[k] = v
	}

	if c.Logger != nil {
		logger, closer, err := logging.NewRotatingFileLogger(
			debug,
			coreId,
			c.Logger.Path,
			c.Logger.MaxSize,
			c.Logger.MaxBackups,
			c.Logger.MaxAge,
			c.Logger.Compress,
			merged,
		)
		return logger, closer, errors.Wrap(err, "create logger")
	}

	var logger *zap.Logger
	var err error

	filters := logging.ParseLogFilters(merged)
	if len(filters) > 0 {
		baseLevel := zap.InfoLevel
		if debug {
			baseLevel = zap.DebugLevel
		}
		coreLevel := baseLevel
		for _, lvl := range filters {
			if lvl < coreLevel {
				coreLevel = lvl
			}
		}

		var zapCfg zap.Config
		if debug {
			zapCfg = zap.NewDevelopmentConfig()
		} else {
			zapCfg = zap.NewProductionConfig()
		}
		zapCfg.Level = zap.NewAtomicLevelAt(coreLevel)
		zapCore, err := zapCfg.Build()
		if err != nil {
			return nil, io.NopCloser(nil), errors.Wrap(err, "create logger")
		}
		logger = zapCore.WithOptions(zap.WrapCore(func(c zapcore.Core) zapcore.Core {
			return logging.NewComponentFilterCore(c, baseLevel, filters)
		}))
	} else if debug {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}

	return logger, io.NopCloser(nil), errors.Wrap(err, "create logger")
}
