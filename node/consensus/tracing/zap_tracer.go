package tracing

import (
	"slices"
	"time"

	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
)

type ZapTracer struct {
	logger *zap.Logger
	params []consensus.LogParam
}

// Error implements consensus.TraceLogger.
func (z *ZapTracer) Error(
	message string,
	err error,
	params ...consensus.LogParam,
) {
	combined := logParamsToZap(z.params)
	combined = append(combined, logParamsToZap(params)...)
	combined = append(combined, zap.Error(err))
	z.logger.Error(message, combined...)
}

// Trace implements consensus.TraceLogger.
func (z *ZapTracer) Trace(message string, params ...consensus.LogParam) {
	combined := logParamsToZap(z.params)
	combined = append(combined, logParamsToZap(params)...)
	z.logger.Debug(message, combined...)
}

// With implements consensus.TraceLogger.
func (z *ZapTracer) With(params ...consensus.LogParam) consensus.TraceLogger {
	return &ZapTracer{
		logger: z.logger,
		params: slices.Concat(z.params, params),
	}
}

func NewZapTracer(logger *zap.Logger) *ZapTracer {
	return &ZapTracer{logger: logger}
}

func logParamsToZap(params []consensus.LogParam) []zap.Field {
	fs := []zap.Field{}
	for _, p := range params {
		fs = append(fs, logParamToZap(p))
	}
	return fs
}

func logParamToZap(p consensus.LogParam) zap.Field {
	switch p.GetKind() {
	case "uint64":
		return zap.Uint64(p.GetKey(), p.GetValue().(uint64))
	case "uint32":
		return zap.Uint32(p.GetKey(), p.GetValue().(uint32))
	case "int64":
		return zap.Int64(p.GetKey(), p.GetValue().(int64))
	case "int32":
		return zap.Int32(p.GetKey(), p.GetValue().(int32))
	case "string":
		return zap.String(p.GetKey(), p.GetValue().(string))
	case "time":
		return zap.Time(p.GetKey(), p.GetValue().(time.Time))
	}
	return zap.Any(p.GetKey(), p.GetValue())
}

var _ consensus.TraceLogger = (*ZapTracer)(nil)
