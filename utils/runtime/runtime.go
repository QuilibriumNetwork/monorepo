package runtime

import (
	"log"
	"runtime"
	"strconv"
)

const minCores = 4
const minWorkers = minCores - 1

// WorkerCount returns the number of workers to use CPU bound tasks.
// It will use GOMAXPROCS as a base, and then subtract a number of CPUs
// which are meant to be left for other tasks, such as networking.
func WorkerCount(requested int, validate bool, legacy bool) int {
	cores := runtime.GOMAXPROCS(0)
	if validate {
		if cores < minCores {
			log.Panic("invalid system configuration, must have at least " +
				strconv.Itoa(minCores) + " cores")
		}
		if requested > 0 && requested < minWorkers {
			log.Panic("invalid worker count, must have at least " +
				strconv.Itoa(minWorkers) + " workers")
		}
	}
	if requested > 0 {
		return min(requested, cores)
	}

	if legacy {
		switch {
		case cores == 1:
			return 1
		case cores <= 4:
			return cores - 1
		case cores <= 16:
			return cores - 2
		case cores <= 32:
			return cores - 3
		case cores <= 64:
			return cores - 4
		default:
			return cores - 5
		}
	}

	if cores == 1 {
		return 1
	}

	return cores - 1
}
