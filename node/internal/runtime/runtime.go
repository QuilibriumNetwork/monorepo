package runtime

import (
	"runtime"

	"source.quilibrium.com/quilibrium/monorepo/node/utils"
)

const minimumCores = 3

// WorkerCount returns the number of workers to use CPU bound tasks.
// It will use GOMAXPROCS as a base, and then subtract a number of CPUs
// which are meant to be left for other tasks, such as networking.
func WorkerCount(requested int, validate bool) int {
	logger := utils.GetLogger()
	n := runtime.GOMAXPROCS(0)
	if validate {
		if n < minimumCores {
			logger.Panic("invalid system configuration, must have at least 3 cores")
		}
		if requested > 0 && requested < minimumCores {
			logger.Panic("invalid worker count, must have at least 3 workers")
		}
	}
	if requested > 0 {
		return min(requested, n)
	}
	switch {
	case n == 1:
		return 1
	case n <= 4:
		return n - 1
	case n <= 16:
		return n - 2
	case n <= 32:
		return n - 3
	case n <= 64:
		return n - 4
	default:
		return n - 5
	}
}
