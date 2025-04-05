package utils

import "go.uber.org/zap"

var logger *zap.Logger
var debugLogger *zap.Logger

func GetLogger() *zap.Logger {
	return logger
}

func GetDebugLogger() *zap.Logger {
	return debugLogger
}

func init() {
	config := zap.NewProductionConfig()
	config.DisableCaller = false
	config.DisableStacktrace = false
	logger = zap.Must(config.Build())

	debugConfig := zap.NewDevelopmentConfig()
	debugLogger = zap.Must(debugConfig.Build())
}
