package ferret

import (
	"fmt"

	"github.com/pkg/errors"
	generated "source.quilibrium.com/quilibrium/monorepo/ferret/generated/ferret"
)

//go:generate ./generate.sh

const (
	ALICE = 1
	BOB   = 2
)

type FerretOT struct {
	party     int
	ferretCOT *generated.FerretCotManager
	netio     *generated.NetIoManager
}

func NewFerretOT(
	party int,
	address string,
	port int,
	threads int,
	length uint64,
	choices []bool,
	malicious bool,
) (*FerretOT, error) {
	if threads > 1 {
		fmt.Println(
			"!!!WARNING!!! THERE BE DRAGONS. RUNNING MULTITHREADED MODE IN SOME " +
				"SITUATIONS HAS LEAD TO CRASHES AND OTHER ISSUES. IF YOU STILL WISH " +
				"TO DO THIS, YOU WILL NEED TO MANUALLY UPDATE THE BUILD AND REMOVE " +
				"THIS CHECK. DO SO AT YOUR OWN RISK",
		)
		return nil, errors.Wrap(errors.New("invalid thread count"), "new ferret ot")
	}

	var addr *string
	if address != "" {
		addrCopy := address
		addr = &addrCopy
	}

	netio := generated.CreateNetioManager(
		int32(party),
		addr,
		int32(port),
	)

	ferretCOT := generated.CreateFerretCotManager(
		int32(party),
		int32(threads),
		length,
		choices,
		netio,
		malicious,
	)

	return &FerretOT{
		party:     party,
		ferretCOT: ferretCOT,
		netio:     netio,
	}, nil
}

func (ot *FerretOT) SendCOT() error {
	if ot.party != ALICE {
		return errors.New("incorrect party")
	}

	ot.ferretCOT.SendCot()

	return nil
}

func (ot *FerretOT) RecvCOT() error {
	if ot.party != BOB {
		return errors.New("incorrect party")
	}

	ot.ferretCOT.RecvCot()

	return nil
}

func (ot *FerretOT) SendROT() error {
	ot.ferretCOT.SendRot()
	return nil
}

func (ot *FerretOT) RecvROT() error {
	ot.ferretCOT.RecvRot()
	return nil
}

func (ot *FerretOT) SenderGetBlockData(choice bool, index uint64) []byte {
	c := uint8(0)
	if choice {
		c = 1
	}
	return ot.ferretCOT.GetBlockData(c, index)
}

func (ot *FerretOT) ReceiverGetBlockData(index uint64) []byte {
	return ot.ferretCOT.GetBlockData(0, index)
}

// FerretBufferOT is a buffer-based Ferret OT that uses message passing
// instead of direct TCP connections. This allows routing OT traffic through
// an external transport (e.g., message channels, proxies).
type FerretBufferOT struct {
	party     int
	ferretCOT *generated.FerretCotBufferManager
	bufferIO  *generated.BufferIoManager
}

// NewFerretBufferOT creates a new buffer-based Ferret OT.
// Unlike NewFerretOT, this doesn't establish any network connections.
// Instead, the caller is responsible for:
// 1. Calling DrainSend() to get outgoing data
// 2. Transmitting that data to the peer via their own transport
// 3. Receiving data from peer and calling FillRecv() with it
func NewFerretBufferOT(
	party int,
	threads int,
	length uint64,
	choices []bool,
	malicious bool,
	initialBufferCap int64,
) (*FerretBufferOT, error) {
	if threads > 1 {
		fmt.Println(
			"!!!WARNING!!! THERE BE DRAGONS. RUNNING MULTITHREADED MODE IN SOME " +
				"SITUATIONS HAS LEAD TO CRASHES AND OTHER ISSUES. IF YOU STILL WISH " +
				"TO DO THIS, YOU WILL NEED TO MANUALLY UPDATE THE BUILD AND REMOVE " +
				"THIS CHECK. DO SO AT YOUR OWN RISK",
		)
		return nil, errors.Wrap(errors.New("invalid thread count"), "new ferret buffer ot")
	}

	bufferIO := generated.CreateBufferIoManager(initialBufferCap)

	ferretCOT := generated.CreateFerretCotBufferManager(
		int32(party),
		int32(threads),
		length,
		choices,
		bufferIO,
		malicious,
	)

	return &FerretBufferOT{
		party:     party,
		ferretCOT: ferretCOT,
		bufferIO:  bufferIO,
	}, nil
}

// FillRecv fills the receive buffer with data from an external transport.
// Call this when you receive data from the peer.
func (ot *FerretBufferOT) FillRecv(data []byte) bool {
	return ot.bufferIO.FillRecv(data)
}

// DrainSend drains up to maxLen bytes from the send buffer.
// Call this to get data that needs to be sent to the peer.
func (ot *FerretBufferOT) DrainSend(maxLen uint64) []byte {
	return ot.bufferIO.DrainSend(maxLen)
}

// SendSize returns the number of bytes waiting to be sent.
func (ot *FerretBufferOT) SendSize() uint64 {
	return ot.bufferIO.SendSize()
}

// RecvAvailable returns the number of bytes available in the receive buffer.
func (ot *FerretBufferOT) RecvAvailable() uint64 {
	return ot.bufferIO.RecvAvailable()
}

// SetTimeout sets the timeout for blocking receive operations (in milliseconds).
// Set to -1 for no timeout (blocking forever until data arrives).
func (ot *FerretBufferOT) SetTimeout(timeoutMs int64) {
	ot.bufferIO.SetTimeout(timeoutMs)
}

// SetError sets an error state that will cause receive operations to fail.
// Useful for signaling that the connection has been closed.
func (ot *FerretBufferOT) SetError(message string) {
	ot.bufferIO.SetError(message)
}

// Clear clears all buffers.
func (ot *FerretBufferOT) Clear() {
	ot.bufferIO.Clear()
}

// Setup runs the OT setup protocol. Must be called after both parties have
// their BufferIO message transport active (can send/receive data).
// This is deferred from construction because BufferIO-based OT needs
// the message channel to be ready before setup can exchange data.
// Returns true on success, false on error.
func (ot *FerretBufferOT) Setup() bool {
	return ot.ferretCOT.Setup()
}

// IsSetup returns true if the OT setup has been completed.
func (ot *FerretBufferOT) IsSetup() bool {
	return ot.ferretCOT.IsSetup()
}

// StateSize returns the size in bytes needed to store the OT state.
func (ot *FerretBufferOT) StateSize() int64 {
	return ot.ferretCOT.StateSize()
}

// AssembleState serializes the OT state for persistent storage.
// This allows storing setup data externally instead of in files.
// Returns nil if serialization fails.
func (ot *FerretBufferOT) AssembleState() []byte {
	return ot.ferretCOT.AssembleState()
}

// DisassembleState restores the OT state from a buffer (created by AssembleState).
// This must be called INSTEAD of Setup, not after.
// Returns true on success.
func (ot *FerretBufferOT) DisassembleState(data []byte) bool {
	return ot.ferretCOT.DisassembleState(data)
}

func (ot *FerretBufferOT) SendCOT() error {
	if ot.party != ALICE {
		return errors.New("incorrect party")
	}

	if !ot.ferretCOT.SendCot() {
		return errors.New("send COT failed")
	}

	return nil
}

func (ot *FerretBufferOT) RecvCOT() error {
	if ot.party != BOB {
		return errors.New("incorrect party")
	}

	if !ot.ferretCOT.RecvCot() {
		return errors.New("recv COT failed")
	}

	return nil
}

func (ot *FerretBufferOT) SendROT() error {
	if !ot.ferretCOT.SendRot() {
		return errors.New("send ROT failed")
	}
	return nil
}

func (ot *FerretBufferOT) RecvROT() error {
	if !ot.ferretCOT.RecvRot() {
		return errors.New("recv ROT failed")
	}
	return nil
}

func (ot *FerretBufferOT) SenderGetBlockData(choice bool, index uint64) []byte {
	c := uint8(0)
	if choice {
		c = 1
	}
	return ot.ferretCOT.GetBlockData(c, index)
}

func (ot *FerretBufferOT) ReceiverGetBlockData(index uint64) []byte {
	return ot.ferretCOT.GetBlockData(0, index)
}

func (ot *FerretBufferOT) Destroy() {
	if ot.ferretCOT != nil {
		ot.ferretCOT.Destroy()
	}
	if ot.bufferIO != nil {
		ot.bufferIO.Destroy()
	}
}
