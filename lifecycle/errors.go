package lifecycle

import (
	"errors"
	"fmt"
)

// ErrComponentRunning is returned by a component that has already been started
// and has had Startable.Start called a second time.
var ErrComponentRunning = errors.New("component is already running")

// ErrComponentShutdown is returned by a component that has already shut down.
var ErrComponentShutdown = fmt.Errorf("component has already shut down")
