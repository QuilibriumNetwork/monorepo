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
	filename string,
) (
	*zap.Logger,
	io.Closer,
	error,
) {
	if dir == "" {
		dir = "./logs"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, err
	}

	if filename == "" {
		filename = filenameForCore(coreId)
	}

	path := filepath.Join(dir, filename)

	rot := &lumberjack.Logger{
		Filename:   path,
		MaxSize:    50,   // megabytes per file before rotation
		MaxBackups: 5,    // number of old files to keep
		MaxAge:     14,   // days
		Compress:   true, // gzip old files
	}

	encCfg := zap.NewProductionEncoderConfig()
	if debug {
		encCfg = zap.NewDevelopmentEncoderConfig()
	}
	encCfg.TimeKey = "ts"
	encCfg.EncodeTime = zapcore.TimeEncoderOfLayout(time.RFC3339)
	enc := zapcore.NewConsoleEncoder(encCfg)

	ws := zapcore.AddSync(rot)
	core := zapcore.NewCore(enc, ws, zap.DebugLevel)
	logger := zap.New(core, zap.AddCaller(), zap.Fields(
		zap.Uint("coreId", coreId),
	))

	return logger, rot, nil
}
