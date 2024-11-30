package fragmentation

import (
	"bytes"
	"errors"

	"github.com/klauspost/reedsolomon"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

// ClockFrameSplitter is an interface for splitting a ClockFrame into fragments.
type ClockFrameSplitter interface {
	// SplitClockFrame splits a ClockFrame into fragments.
	// The fragments are unsigned, and must be signed before being sent.
	SplitClockFrame(frame *protobufs.ClockFrame) ([]*protobufs.ClockFrameFragment, error)
}

type reedSolomonClockFrameSplitter struct {
	dataShardCount   int
	parityShardCount int
}

// NewReedSolomonClockFrameSplitter creates a new ReedSolomonClockFrameSplitter.
func NewReedSolomonClockFrameSplitter(
	dataShardCount int,
	parityShardCount int,
) (ClockFrameSplitter, error) {
	if dataShardCount == 0 {
		return nil, errors.New("dataShardCount must be greater than 0")
	}
	if parityShardCount == 0 {
		return nil, errors.New("parityShardCount must be greater than 0")
	}
	if dataShardCount+parityShardCount > 256 {
		return nil, errors.New("dataShardCount + parityShardCount must be less than or equal to 256")
	}
	return &reedSolomonClockFrameSplitter{
		dataShardCount:   dataShardCount,
		parityShardCount: parityShardCount,
	}, nil
}

// SplitClockFrame implements ClockFrameSplitter.
func (r *reedSolomonClockFrameSplitter) SplitClockFrame(frame *protobufs.ClockFrame) ([]*protobufs.ClockFrameFragment, error) {
	bs, err := proto.Marshal(frame)
	if err != nil {
		return nil, err
	}
	fragmentSize := len(bs) / r.dataShardCount
	if len(bs)%r.dataShardCount != 0 {
		fragmentSize++
	}
	if fragmentSize == 0 {
		return nil, errors.New("ClockFrame is too small")
	}
	if n := fragmentSize % 64; n != 0 {
		fragmentSize += 64 - n
	}
	shards := make([][]byte, r.dataShardCount+r.parityShardCount)
	for i := 0; i < len(bs); i += fragmentSize {
		shard := bs[i:]
		if len(shard) > fragmentSize {
			shard = shard[:fragmentSize]
		}
		shards[i/fragmentSize] = shard
	}
	for i := len(bs) / fragmentSize; i < r.dataShardCount; i++ {
		if n := len(shards[i]); n < fragmentSize {
			shards[i] = append(shards[i], make([]byte, fragmentSize-n)...)
		}
	}
	for i := r.dataShardCount; i < r.dataShardCount+r.parityShardCount; i++ {
		shards[i] = make([]byte, fragmentSize)
	}
	enc, err := reedsolomon.New(
		r.dataShardCount,
		r.parityShardCount,
		reedsolomon.WithAutoGoroutines(fragmentSize),
	)
	if err != nil {
		return nil, err
	}
	if err := enc.Encode(shards); err != nil {
		return nil, err
	}
	h := hash(bs)
	fragments := make([]*protobufs.ClockFrameFragment, r.dataShardCount+r.parityShardCount)
	for i, shard := range shards {
		fragments[i] = &protobufs.ClockFrameFragment{
			Filter:      frame.Filter,
			FrameNumber: frame.FrameNumber,
			Timestamp:   frame.Timestamp,
			FrameHash:   h,
			Encoding: &protobufs.ClockFrameFragment_ReedSolomon{
				ReedSolomon: &protobufs.ClockFrameFragment_ReedSolomonEncoding{
					FrameSize:                uint64(len(bs)),
					FragmentShard:            uint64(i),
					FragmentDataShardCount:   uint64(r.dataShardCount),
					FragmentParityShardCount: uint64(r.parityShardCount),
					FragmentData:             shard,
				},
			},
		}
	}
	return fragments, nil
}

// ClockFrameAssembler is an interface for assembling a ClockFrame from fragments.
type ClockFrameAssembler interface {
	// AssembleClockFrame assembles a ClockFrame from fragments.
	AssembleClockFrame(fragments []*protobufs.ClockFrameFragment) (*protobufs.ClockFrame, error)
}

type reedSolomonClockFrameAssembler struct{}

// NewReedSolomonClockFrameAssembler creates a new ReedSolomonClockFrameAssembler.
func NewReedSolomonClockFrameAssembler() ClockFrameAssembler {
	return &reedSolomonClockFrameAssembler{}
}

// AssembleClockFrame implements ClockFrameAssembler.
func (r *reedSolomonClockFrameAssembler) AssembleClockFrame(fragments []*protobufs.ClockFrameFragment) (*protobufs.ClockFrame, error) {
	if len(fragments) == 0 {
		return nil, errors.New("no fragments")
	}
	var (
		frameNumber                      uint64
		filter                           []byte
		timestamp                        int64
		frameHash                        []byte
		dataShardCount, parityShardCount int
		fragmentSize                     int
		frameSize                        int
	)
	for _, fragment := range fragments {
		if fragment == nil {
			return nil, errors.New("fragment is nil")
		}
		switch {
		case frameNumber == 0:
			frameNumber = fragment.FrameNumber
		case frameNumber != fragment.FrameNumber:
			return nil, errors.New("inconsistent frame number")
		case len(filter) == 0:
			filter = fragment.Filter
		case !bytes.Equal(filter, fragment.Filter):
			return nil, errors.New("inconsistent filter")
		case timestamp == 0:
			timestamp = fragment.Timestamp
		case timestamp != fragment.Timestamp:
			return nil, errors.New("inconsistent timestamp")
		case len(frameHash) == 0:
			frameHash = fragment.FrameHash
		case !bytes.Equal(frameHash, fragment.FrameHash):
			return nil, errors.New("inconsistent frame hash")
		}
		fragment := fragment.GetReedSolomon()
		if fragment == nil {
			return nil, errors.New("fragment is not ReedSolomon")
		}
		switch {
		case dataShardCount == 0:
			dataShardCount = int(fragment.FragmentDataShardCount)
			parityShardCount = int(fragment.FragmentParityShardCount)
		case dataShardCount != int(fragment.FragmentDataShardCount):
			return nil, errors.New("inconsistent data shard count")
		case parityShardCount != int(fragment.FragmentParityShardCount):
			return nil, errors.New("inconsistent parity shard count")
		case dataShardCount+parityShardCount <= int(fragment.FragmentShard):
			return nil, errors.New("shard out of bounds")
		case fragmentSize == 0:
			fragmentSize = len(fragment.FragmentData)
		case len(fragment.FragmentData) != fragmentSize:
			return nil, errors.New("inconsistent fragment size")
		case frameSize == 0:
			frameSize = int(fragment.FrameSize)
		case int(fragment.FrameSize) != frameSize:
			return nil, errors.New("inconsistent frame size")
		}
	}
	shards := make([][]byte, dataShardCount+parityShardCount)
	for _, fragment := range fragments {
		fragment := fragment.GetReedSolomon()
		shard := fragment.FragmentShard
		if shards[shard] != nil {
			return nil, errors.New("duplicate shard")
		}
		shards[shard] = fragment.FragmentData
	}
	enc, err := reedsolomon.New(
		dataShardCount,
		parityShardCount,
		reedsolomon.WithAutoGoroutines(fragmentSize),
	)
	if err != nil {
		return nil, err
	}
	if err := enc.ReconstructData(shards); err != nil {
		return nil, err
	}
	bs := make([]byte, 0, dataShardCount*fragmentSize)
	for _, shard := range shards[:dataShardCount] {
		bs = append(bs, shard...)
	}
	bs = bs[:frameSize]
	if h := hash(bs); !bytes.Equal(h, frameHash) {
		return nil, errors.New("frame hash mismatch")
	}
	frame := &protobufs.ClockFrame{}
	if err := proto.Unmarshal(bs, frame); err != nil {
		return nil, err
	}
	return frame, nil
}

// ClockFrameFragmentBuffer is an interface for buffering ClockFrameFragments and assembling ClockFrames.
type ClockFrameFragmentBuffer interface {
	// AccumulateClockFrameFragment accumulates a ClockFrameFragment.
	// If sufficient fragments are available, the ClockFrame is returned.
	// How fragments from different frames are handled is implementation-specific.
	AccumulateClockFrameFragment(fragment *protobufs.ClockFrameFragment) (*protobufs.ClockFrame, error)
}

type clockFrameFragmentCircularBuffer struct {
	newBuffer func() ClockFrameFragmentBuffer
	maxSize   int
	buffers   map[[hashSize]byte]ClockFrameFragmentBuffer
	keys      [][hashSize]byte
	built     map[[hashSize]byte]struct{}
	builtKeys [][hashSize]byte
}

// NewClockFrameFragmentCircularBuffer creates a new ClockFrameFragmentBuffer.
// The newBuffer function is called to create a new ClockFrameFragmentBuffer.
// The maxSize parameter specifies the maximum number of buffers to keep.
// If maxSize buffers are already in use, the oldest buffer is removed.
func NewClockFrameFragmentCircularBuffer(
	newBuffer func() ClockFrameFragmentBuffer,
	maxSize int,
) (ClockFrameFragmentBuffer, error) {
	if newBuffer == nil {
		return nil, errors.New("newBuffer is nil")
	}
	if maxSize <= 0 {
		return nil, errors.New("maxSize must be greater than 0")
	}
	return &clockFrameFragmentCircularBuffer{
		newBuffer: newBuffer,
		maxSize:   maxSize,
		buffers:   make(map[[hashSize]byte]ClockFrameFragmentBuffer, maxSize),
		keys:      make([][hashSize]byte, 0, maxSize),
		built:     make(map[[hashSize]byte]struct{}, maxSize),
		builtKeys: make([][hashSize]byte, 0, maxSize),
	}, nil
}

// AccumulateClockFrameFragment implements ClockFrameFragmentBuffer.
func (c *clockFrameFragmentCircularBuffer) AccumulateClockFrameFragment(fragment *protobufs.ClockFrameFragment) (*protobufs.ClockFrame, error) {
	if fragment == nil {
		return nil, errors.New("fragment is nil")
	}
	if len(fragment.FrameHash) != hashSize {
		return nil, errors.New("invalid frame hash size")
	}
	key := [hashSize]byte(fragment.FrameHash)
	if _, ok := c.built[key]; ok {
		return nil, nil
	}
	buffer, ok := c.buffers[key]
	if !ok {
		if len(c.buffers) == c.maxSize {
			delete(c.buffers, c.keys[0])
			c.keys = append(c.keys[:0], c.keys[1:]...)
		}
		buffer = c.newBuffer()
		c.buffers[key] = buffer
		c.keys = append(c.keys, key)
	}
	frame, err := buffer.AccumulateClockFrameFragment(fragment)
	if err != nil {
		return nil, err
	}
	if frame != nil {
		delete(c.buffers, key)
		for i, k := range c.keys {
			if k == key {
				c.keys = append(c.keys[:i], c.keys[i+1:]...)
				break
			}
		}
		if len(c.built) == c.maxSize {
			delete(c.built, c.builtKeys[0])
			c.builtKeys = append(c.builtKeys[:0], c.builtKeys[1:]...)
		}
		c.built[key] = struct{}{}
		c.builtKeys = append(c.builtKeys, key)
	}
	return frame, nil
}

type reedSolomonClockFrameFragmentBuffer struct {
	fragments []*protobufs.ClockFrameFragment
	have      map[uint64]struct{}
}

// NewReedSolomonClockFrameFragmentBuffer creates a new ReedSolomonClockFrameFragmentBuffer.
func NewReedSolomonClockFrameFragmentBuffer() ClockFrameFragmentBuffer {
	return &reedSolomonClockFrameFragmentBuffer{
		fragments: make([]*protobufs.ClockFrameFragment, 0, 256),
		have:      make(map[uint64]struct{}, 256),
	}
}

// AccumulateClockFrameFragment implements ClockFrameFragmentBuffer.
func (r *reedSolomonClockFrameFragmentBuffer) AccumulateClockFrameFragment(fragment *protobufs.ClockFrameFragment) (*protobufs.ClockFrame, error) {
	if fragment == nil {
		return nil, errors.New("fragment is nil")
	}
	if fragment.GetReedSolomon() == nil {
		return nil, errors.New("fragment is not ReedSolomon")
	}
	var templateRS *protobufs.ClockFrameFragment_ReedSolomonEncoding
	if len(r.fragments) == 0 {
		templateRS = fragment.GetReedSolomon()
	} else {
		template := r.fragments[0]
		if !bytes.Equal(template.Filter, fragment.Filter) {
			return nil, errors.New("inconsistent filter")
		}
		if template.FrameNumber != fragment.FrameNumber {
			return nil, errors.New("inconsistent frame number")
		}
		if template.Timestamp != fragment.Timestamp {
			return nil, errors.New("inconsistent timestamp")
		}
		if !bytes.Equal(template.FrameHash, fragment.FrameHash) {
			return nil, errors.New("inconsistent frame hash")
		}
		templateRS = template.GetReedSolomon()
		fragmentRS := fragment.GetReedSolomon()
		if templateRS.FrameSize != fragmentRS.FrameSize {
			return nil, errors.New("inconsistent frame size")
		}
		if templateRS.FragmentDataShardCount+templateRS.FragmentParityShardCount <= fragmentRS.FragmentShard {
			return nil, errors.New("shard out of bounds")
		}
		if _, ok := r.have[fragmentRS.FragmentShard]; ok {
			return nil, errors.New("duplicate shard")
		}
		if templateRS.FragmentDataShardCount != fragmentRS.FragmentDataShardCount {
			return nil, errors.New("inconsistent data shard count")
		}
		if templateRS.FragmentParityShardCount != fragmentRS.FragmentParityShardCount {
			return nil, errors.New("inconsistent parity shard count")
		}
		if len(templateRS.FragmentData) != len(fragmentRS.FragmentData) {
			return nil, errors.New("inconsistent fragment size")
		}
	}
	r.fragments = append(r.fragments, fragment)
	r.have[templateRS.FragmentShard] = struct{}{}
	if len(r.fragments) < int(templateRS.FragmentDataShardCount) {
		return nil, nil
	}
	assembler := NewReedSolomonClockFrameAssembler()
	frame, err := assembler.AssembleClockFrame(r.fragments)
	r.fragments = r.fragments[:0]
	clear(r.have)
	return frame, err
}
