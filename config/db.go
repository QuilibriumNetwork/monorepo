package config

const (
	defaultWorkerPathPrefix    = "worker-store/%d"
	defaultNoticePercentage    = 70
	defaultWarnPercentage      = 90
	defaultTerminatePercentage = 95
)

type DBConfig struct {
	Path string `yaml:"path"`
	// Path prefix for worker stores, with %d for worker core id
	WorkerPathPrefix string `yaml:"workerPathPrefix"`
	// Optional manual override for worker store paths
	WorkerPaths []string `yaml:"workerPaths"`
	// Storage capacity thresholds for emitting notices
	NoticePercentage int `yaml:"noticePercentage"`
	// Storage capacity thresholds for emitting warnings
	WarnPercentage int `yaml:"warnPercentage"`
	// Storage capacity thresholds for terminating the process
	TerminatePercentage int `yaml:"terminatePercentage"`

	// Test-only parameters, do not enable outside of tests
	InMemoryDONOTUSE bool
}

// WithDefaults returns a copy of the DBConfig with any missing fields set to
// their default values.
func (c DBConfig) WithDefaults() DBConfig {
	cpy := c
	if cpy.WorkerPathPrefix == "" {
		// If Path is set and WorkerPathPrefix is not, derive it from Path
		if cpy.Path != "" {
			// Extract the base directory from Path (which ends with /store)
			if len(cpy.Path) > 6 && cpy.Path[len(cpy.Path)-6:] == "/store" {
				basePath := cpy.Path[:len(cpy.Path)-6]
				cpy.WorkerPathPrefix = basePath + "/" + defaultWorkerPathPrefix
			} else {
				cpy.WorkerPathPrefix = defaultWorkerPathPrefix
			}
		} else {
			cpy.WorkerPathPrefix = defaultWorkerPathPrefix
		}
	}
	if cpy.NoticePercentage == 0 {
		cpy.NoticePercentage = defaultNoticePercentage
	}
	if cpy.WarnPercentage == 0 {
		cpy.WarnPercentage = defaultWarnPercentage
	}
	if cpy.TerminatePercentage == 0 {
		cpy.TerminatePercentage = defaultTerminatePercentage
	}
	return cpy
}
