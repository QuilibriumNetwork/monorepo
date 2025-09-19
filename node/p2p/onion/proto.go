package onion

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

// Relay header (inside layered encryption): 1 + 2 + 2 + payload
// | Cmd (1) | StreamID (2) | Length (2) | Data (<= payloadMax) |
// Marshaled header is variable (but final cell is padded to CellSize at the
// link).
type relayHeader struct {
	Cmd      byte
	StreamID uint16
	Length   uint16
	Data     []byte
}

func marshalRelay(h relayHeader, payloadMax int) ([]byte, error) {
	if int(h.Length) != len(h.Data) || len(h.Data) > payloadMax {
		return nil, errors.New("invalid relay header length")
	}
	buf := make([]byte, 1+2+2+len(h.Data))
	buf[0] = h.Cmd
	binary.BigEndian.PutUint16(buf[1:3], h.StreamID)
	binary.BigEndian.PutUint16(buf[3:5], h.Length)
	copy(buf[5:], h.Data)
	return buf, nil
}

func unmarshalRelay(b []byte) (relayHeader, error) {
	if len(b) < 5 {
		return relayHeader{}, errors.New("short relay header")
	}
	cmd := b[0]
	sid := binary.BigEndian.Uint16(b[1:3])
	l := binary.BigEndian.Uint16(b[3:5])
	if int(5+int(l)) > len(b) {
		return relayHeader{}, errors.New("relay length overflow")
	}
	return relayHeader{Cmd: cmd, StreamID: sid, Length: l, Data: b[5 : 5+l]}, nil
}
