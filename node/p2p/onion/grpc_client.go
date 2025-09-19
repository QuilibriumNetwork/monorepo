package onion

import (
	"io"
	"net"
	"sync"
	"time"
)

// our gRPC wrapper
type onionConn struct {
	r *OnionRouter
	c *Circuit
	s *onionStream

	deadlineMx *sync.Mutex
	rdl, wdl   time.Time

	// in-order read stash to avoid re-queue races
	pending []byte
	readMx  sync.Mutex
}

func (oc *onionConn) Read(p []byte) (int, error) {
	oc.readMx.Lock()
	defer oc.readMx.Unlock()

	// Serve from pending first
	if len(oc.pending) > 0 {
		n := copy(p, oc.pending)
		oc.pending = oc.pending[n:]
		return n, nil
	}

	// Block until next chunk or channel close
	b, ok := <-oc.s.readCh
	if !ok {
		// true EOF only when producer has closed readCh
		return 0, io.EOF
	}
	if len(b) == 0 {
		// Defensive: skip empty chunks
		return 0, nil
	}

	n := copy(p, b)
	if n < len(b) {
		// Stash leftover; do NOT push back into a channel
		oc.pending = append(oc.pending[:0], b[n:]...)
	}
	return n, nil
}

func (oc *onionConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	select {
	case <-oc.s.closed:
		return 0, io.ErrClosedPipe
	case oc.s.writeCh <- append([]byte(nil), p...):
		return len(p), nil
	}
}

func (oc *onionConn) Close() error {
	_ = oc.r.sendRelay(oc.c, relayHeader{
		Cmd:      CmdEnd,
		StreamID: oc.s.streamID,
		Length:   0,
	})

	oc.r.closeStream(oc.c, oc.s)
	return nil
}

func (oc *onionConn) LocalAddr() net.Addr {
	return onionAddr("onion")
}

func (oc *onionConn) RemoteAddr() net.Addr {
	return onionAddr("onion")
}

func (oc *onionConn) SetDeadline(t time.Time) error {
	oc.deadlineMx.Lock()
	oc.rdl, oc.wdl = t, t
	oc.deadlineMx.Unlock()
	return nil
}

func (oc *onionConn) SetReadDeadline(t time.Time) error {
	oc.deadlineMx.Lock()
	oc.rdl = t
	oc.deadlineMx.Unlock()
	return nil
}

func (oc *onionConn) SetWriteDeadline(t time.Time) error {
	oc.deadlineMx.Lock()
	oc.wdl = t
	oc.deadlineMx.Unlock()
	return nil
}

type onionAddr string

func (onionAddr) Network() string {
	return "onion"
}

func (a onionAddr) String() string {
	return string(a)
}
