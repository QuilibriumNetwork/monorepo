package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

func filenameForCore(coreId uint) string {
	if coreId == 0 {
		return "master.log"
	}
	return fmt.Sprintf("worker-%d.log", coreId)
}

func NewRotatingFileLogger(
	debug bool,
	coreId uint,
	dir string,
	maxSize int,
	maxBackups int,
	maxAge int,
	compress bool,
	logFilters map[string]string,
) (
	*zap.Logger,
	io.Closer,
	error,
) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, err
	}

	filename := filenameForCore(coreId)

	logFilePath := filepath.Join(dir, filename)

	rot := &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    maxSize,
		MaxBackups: maxBackups,
		MaxAge:     maxAge,
		Compress:   compress,
	}

	encCfg := zap.NewProductionEncoderConfig()
	if debug {
		encCfg = zap.NewDevelopmentEncoderConfig()
	}
	encCfg.TimeKey = "ts"
	encCfg.EncodeTime = zapcore.TimeEncoderOfLayout(time.RFC3339)
	enc := zapcore.NewConsoleEncoder(encCfg)

	ws := zapcore.AddSync(rot)

	baseLevel := zap.InfoLevel
	if debug {
		baseLevel = zap.DebugLevel
	}

	filters := ParseLogFilters(logFilters)
	coreLevel := baseLevel
	for _, lvl := range filters {
		if lvl < coreLevel {
			coreLevel = lvl
		}
	}

	core := zapcore.NewCore(enc, ws, coreLevel)
	core = NewComponentFilterCore(core, baseLevel, filters)
	logger := zap.New(core, zap.AddCaller(), zap.Fields(
		zap.Uint("coreId", coreId),
	))

	return logger, rot, nil
}
