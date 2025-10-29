package consensus

// TraceLogger defines a simple tracing interface
type TraceLogger interface {
	Trace(message string)
	Error(message string, err error)
}

type nilTracer struct{}

func (nilTracer) Trace(message string)            {}
func (nilTracer) Error(message string, err error) {}
