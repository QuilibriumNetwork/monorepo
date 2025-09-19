//
// ot.go
//
// Copyright (c) 2023 Markku Rossi
//
// All rights reserved.

package ot

// OT defines Oblivious Transfer protocol.
type OT interface {
	// InitSender initializes the OT sender.
	InitSender(io IO) error

	// InitReceiver initializes the OT receiver.
	InitReceiver(io IO) error

	// Send sends the wire labels with OT.
	Send(wires []Wire) error

	// Receive receives the wire labels with OT based on the flag values.
	Receive(flags []bool, result []Label) error
}
