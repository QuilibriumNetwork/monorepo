package consensus

import (
	"encoding/hex"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// TraceLogger defines a simple tracing interface
type TraceLogger interface {
	Trace(message string, params ...LogParam)
	Error(message string, err error, params ...LogParam)
	With(params ...LogParam) TraceLogger
}

type LogParam struct {
	key   string
	value any
	kind  string
}

func StringParam(key string, value string) LogParam {
	return LogParam{
		key:   key,
		value: value,
		kind:  "string",
	}
}

func Uint64Param(key string, value uint64) LogParam {
	return LogParam{
		key:   key,
		value: value,
		kind:  "uint64",
	}
}

func Uint32Param(key string, value uint32) LogParam {
	return LogParam{
		key:   key,
		value: value,
		kind:  "uint32",
	}
}

func Int64Param(key string, value int64) LogParam {
	return LogParam{
		key:   key,
		value: value,
		kind:  "int64",
	}
}

func Int32Param(key string, value int32) LogParam {
	return LogParam{
		key:   key,
		value: value,
		kind:  "int32",
	}
}

func IdentityParam(key string, value models.Identity) LogParam {
	return LogParam{
		key:   key,
		value: hex.EncodeToString([]byte(value)),
		kind:  "string",
	}
}

func HexParam(key string, value []byte) LogParam {
	return LogParam{
		key:   key,
		value: hex.EncodeToString(value),
		kind:  "string",
	}
}

func TimeParam(key string, value time.Time) LogParam {
	return LogParam{
		key:   key,
		value: value,
		kind:  "time",
	}
}

func (l LogParam) GetKey() string {
	return l.key
}

func (l LogParam) GetValue() any {
	return l.value
}

func (l LogParam) GetKind() string {
	return l.kind
}

type nilTracer struct{}

func (nilTracer) Trace(message string)            {}
func (nilTracer) Error(message string, err error) {}
