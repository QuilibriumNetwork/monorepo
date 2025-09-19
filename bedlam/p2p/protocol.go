//
// Copyright (c) 2019-2023 Markku Rossi
//
// All rights reserved.
//

package p2p

import (
	"io"
	"sync/atomic"

	"source.quilibrium.com/quilibrium/monorepo/bedlam/ot"
)

var (
	_ ot.IO = &Conn{}
)

const (
	numBuffers   = 3
	writeBufSize = 64 * 1024
	readBufSize  = 1024 * 1024
)

// Conn implements a protocol connection.
type Conn struct {
	conn      io.ReadWriter
	WriteBuf  []byte
	WritePos  int
	ReadBuf   []byte
	ReadStart int
	ReadEnd   int
	Stats     IOStats

	fromWriter chan []byte
	toWriter   chan []byte
	writerErr  error
}

// IOStats implements I/O statistics.
type IOStats struct {
	Sent    *atomic.Uint64
	Recvd   *atomic.Uint64
	Flushed *atomic.Uint64
}

// NewIOStats creates a new I/O statistics object.
func NewIOStats() IOStats {
	return IOStats{
		Sent:    new(atomic.Uint64),
		Recvd:   new(atomic.Uint64),
		Flushed: new(atomic.Uint64),
	}
}

// Add adds the argument stats to this IOStats and returns the sum.
func (stats IOStats) Add(o IOStats) IOStats {
	sent := new(atomic.Uint64)
	sent.Store(stats.Sent.Load() + o.Sent.Load())

	recvd := new(atomic.Uint64)
	recvd.Store(stats.Recvd.Load() + o.Recvd.Load())

	flushed := new(atomic.Uint64)
	flushed.Store(stats.Flushed.Load() + o.Flushed.Load())

	return IOStats{
		Sent:    sent,
		Recvd:   recvd,
		Flushed: flushed,
	}
}

// Sum returns sum of sent and received bytes.
func (stats IOStats) Sum() uint64 {
	return stats.Sent.Load() + stats.Recvd.Load()
}

// NewConn creates a new connection around the argument connection.
func NewConn(conn io.ReadWriter) *Conn {
	c := &Conn{
		conn:       conn,
		ReadBuf:    make([]byte, readBufSize),
		fromWriter: make(chan []byte, numBuffers),
		toWriter:   make(chan []byte, numBuffers),
		Stats:      NewIOStats(),
	}

	go c.writer()

	c.WriteBuf = <-c.fromWriter

	return c
}

func (c *Conn) writer() {
	for i := 0; i < numBuffers; i++ {
		c.fromWriter <- make([]byte, writeBufSize)
	}

	for buf := range c.toWriter {
		_, err := c.conn.Write(buf)
		if err != nil {
			c.writerErr = err
		}
		c.fromWriter <- buf[0:cap(buf)]
	}
	close(c.fromWriter)
}

// NeedSpace ensures the write buffer has space for count bytes. The
// function flushes the output if needed.
func (c *Conn) NeedSpace(count int) error {
	if c.WritePos+count > len(c.WriteBuf) {
		return c.Flush()
	}
	return nil
}

// Flush flushed any pending data in the connection.
func (c *Conn) Flush() error {
	if c.WritePos > 0 {
		c.Stats.Sent.Add(uint64(c.WritePos))
		c.toWriter <- c.WriteBuf[0:c.WritePos]

		next := <-c.fromWriter
		if c.writerErr != nil {
			return c.writerErr
		}

		c.WriteBuf = next
		c.WritePos = 0
		c.Stats.Flushed.Add(1)
	}
	return nil
}

// Fill fills the input buffer from the connection. Any unused data in
// the buffer is moved to the beginning of the buffer.
func (c *Conn) Fill(n int) error {
	if c.ReadStart < c.ReadEnd {
		copy(c.ReadBuf[0:], c.ReadBuf[c.ReadStart:c.ReadEnd])
		c.ReadEnd -= c.ReadStart
		c.ReadStart = 0
	} else {
		c.ReadStart = 0
		c.ReadEnd = 0
	}
	for c.ReadStart+n > c.ReadEnd {
		got, err := c.conn.Read(c.ReadBuf[c.ReadEnd:])
		if err != nil {
			return err
		}
		c.Stats.Recvd.Add(uint64(got))
		c.ReadEnd += got
	}
	return nil
}

// Close flushes any pending data and closes the connection.
func (c *Conn) Close() error {
	if err := c.Flush(); err != nil {
		return err
	}
	// Wait that flush completes.
	close(c.toWriter)
	for range <-c.fromWriter {
	}
	if c.writerErr != nil {
		return c.writerErr
	}
	closer, ok := c.conn.(io.Closer)
	if ok {
		return closer.Close()
	}
	return nil
}

// SendByte sends a byte value.
func (c *Conn) SendByte(val byte) error {
	if c.WritePos+1 > len(c.WriteBuf) {
		if err := c.Flush(); err != nil {
			return err
		}
	}
	c.WriteBuf[c.WritePos] = val
	c.WritePos++
	return nil
}

// SendUint16 sends an uint16 value.
func (c *Conn) SendUint16(val int) error {
	if c.WritePos+2 > len(c.WriteBuf) {
		if err := c.Flush(); err != nil {
			return err
		}
	}
	c.WriteBuf[c.WritePos+0] = byte((uint32(val) >> 8) & 0xff)
	c.WriteBuf[c.WritePos+1] = byte(uint32(val) & 0xff)
	c.WritePos += 2
	return nil
}

// SendUint32 sends an uint32 value.
func (c *Conn) SendUint32(val int) error {
	if c.WritePos+4 > len(c.WriteBuf) {
		if err := c.Flush(); err != nil {
			return err
		}
	}
	c.WriteBuf[c.WritePos+0] = byte((uint32(val) >> 24) & 0xff)
	c.WriteBuf[c.WritePos+1] = byte((uint32(val) >> 16) & 0xff)
	c.WriteBuf[c.WritePos+2] = byte((uint32(val) >> 8) & 0xff)
	c.WriteBuf[c.WritePos+3] = byte(uint32(val) & 0xff)
	c.WritePos += 4
	return nil
}

// SendData sends binary data.
func (c *Conn) SendData(val []byte) error {
	if c.WritePos+4+len(val) > len(c.WriteBuf) {
		if err := c.Flush(); err != nil {
			return err
		}
	}
	err := c.SendUint32(len(val))
	if err != nil {
		return err
	}
	copy(c.WriteBuf[c.WritePos:], val)
	c.WritePos += len(val)
	return nil
}

// SendLabel sends an OT label.
func (c *Conn) SendLabel(val ot.Label, data *ot.LabelData) error {
	bytes := val.Bytes(data)
	if c.WritePos+len(bytes) > len(c.WriteBuf) {
		if err := c.Flush(); err != nil {
			return err
		}
	}
	copy(c.WriteBuf[c.WritePos:], bytes)
	c.WritePos += len(bytes)

	return nil
}

// SendString sends a string value.
func (c *Conn) SendString(val string) error {
	return c.SendData([]byte(val))
}

// SendInputSizes sends the input sizes.
func (c *Conn) SendInputSizes(sizes []int) error {
	if err := c.SendUint32(len(sizes)); err != nil {
		return err
	}
	for i := 0; i < len(sizes); i++ {
		if err := c.SendUint32(sizes[i]); err != nil {
			return err
		}
	}
	return nil
}

// ReceiveByte receives a byte value.
func (c *Conn) ReceiveByte() (byte, error) {
	if c.ReadStart+1 > c.ReadEnd {
		if err := c.Fill(1); err != nil {
			return 0, err
		}
	}
	val := c.ReadBuf[c.ReadStart]
	c.ReadStart++
	return val, nil
}

// ReceiveUint16 receives an uint16 value.
func (c *Conn) ReceiveUint16() (int, error) {
	if c.ReadStart+2 > c.ReadEnd {
		if err := c.Fill(2); err != nil {
			return 0, err
		}
	}
	val := uint32(c.ReadBuf[c.ReadStart+0])
	val <<= 8
	val |= uint32(c.ReadBuf[c.ReadStart+1])
	c.ReadStart += 2

	return int(val), nil
}

// ReceiveUint32 receives an uint32 value.
func (c *Conn) ReceiveUint32() (int, error) {
	if c.ReadStart+4 > c.ReadEnd {
		if err := c.Fill(4); err != nil {
			return 0, err
		}
	}
	val := uint32(c.ReadBuf[c.ReadStart+0])
	val <<= 8
	val |= uint32(c.ReadBuf[c.ReadStart+1])
	val <<= 8
	val |= uint32(c.ReadBuf[c.ReadStart+2])
	val <<= 8
	val |= uint32(c.ReadBuf[c.ReadStart+3])
	c.ReadStart += 4

	return int(val), nil
}

// ReceiveData receives binary data.
func (c *Conn) ReceiveData() ([]byte, error) {
	len, err := c.ReceiveUint32()
	if err != nil {
		return nil, err
	}
	if c.ReadStart+len > c.ReadEnd {
		if err := c.Fill(len); err != nil {
			return nil, err
		}
	}

	result := make([]byte, len)
	copy(result, c.ReadBuf[c.ReadStart:c.ReadStart+len])
	c.ReadStart += len

	return result, nil
}

// ReceiveLabel receives an OT label.
func (c *Conn) ReceiveLabel(val *ot.Label, data *ot.LabelData) error {
	if c.ReadStart+len(data) > c.ReadEnd {
		if err := c.Fill(len(data)); err != nil {
			return err
		}
	}
	copy(data[:], c.ReadBuf[c.ReadStart:c.ReadStart+len(data)])
	c.ReadStart += len(data)

	val.SetData(data)
	return nil
}

// ReceiveString receives a string value.
func (c *Conn) ReceiveString() (string, error) {
	data, err := c.ReceiveData()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ReceiveInputSizes receives input sizes.
func (c *Conn) ReceiveInputSizes() ([]int, error) {
	count, err := c.ReceiveUint32()
	if err != nil {
		return nil, err
	}
	result := make([]int, count)
	for i := 0; i < count; i++ {
		size, err := c.ReceiveUint32()
		if err != nil {
			return nil, err
		}
		result[i] = size
	}
	return result, nil
}
