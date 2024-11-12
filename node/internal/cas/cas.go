package cas

import "sync/atomic"

// IfLessThanInt64 sets the value of a to lt if the current value of a is less than lt.
func IfLessThanUint64(a *uint64, lt uint64) {
	for val := atomic.LoadUint64(a); val < lt; val = atomic.LoadUint64(a) {
		if atomic.CompareAndSwapUint64(a, val, lt) {
			return
		}
	}
}
