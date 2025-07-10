package tries

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"strings"
	"sync"

	"github.com/pkg/errors"
)

type RewardNode struct {
	Internal *RewardInternalNode
	External *RewardExternalNode
}

type RewardInternalNode struct {
	Child      [2]RewardNode
	ByteNumber uint32
	Bits       byte
}

type RewardExternalNode struct {
	Key           []byte
	EarliestFrame uint64
	LatestFrame   uint64
	Total         uint64
}

type RewardCritbitTrie struct {
	Root *RewardNode
	mu   sync.RWMutex
}

func (t *RewardCritbitTrie) Serialize() ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var b bytes.Buffer
	enc := gob.NewEncoder(&b)

	if err := enc.Encode(t.Root); err != nil {
		return nil, errors.Wrap(err, "serialize")
	}

	return b.Bytes(), nil
}

func (t *RewardCritbitTrie) Deserialize(buf []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	var b bytes.Buffer
	b.Write(buf)
	dec := gob.NewDecoder(&b)

	if err := dec.Decode(&t.Root); err != nil {
		return errors.Wrap(err, "deserialize")
	}

	return nil
}

func (t *RewardCritbitTrie) Contains(address []byte) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p := t.findNearest(address)
	return p != nil &&
		p.External != nil &&
		bytes.Equal(p.External.Key, address)
}

func (t *RewardCritbitTrie) Get(
	address []byte,
) (earliestFrame uint64, latestFrame uint64, total uint64) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p := t.findNearest(address)

	if p != nil &&
		p.External != nil &&
		bytes.Equal(p.External.Key, address) {
		return p.External.EarliestFrame, p.External.LatestFrame, p.External.Total
	}

	return 0, 0, 0
}

func (t *RewardCritbitTrie) findNearest(
	address []byte,
) *RewardNode {
	blen := uint32(len(address))
	p := t.Root

	if p == nil {
		return nil
	}

	for p.Internal != nil {
		right := p.Internal.ByteNumber < blen &&
			address[p.Internal.ByteNumber]&p.Internal.Bits != 0
		if right {
			p = &p.Internal.Child[1]
		} else {
			p = &p.Internal.Child[0]
		}
	}

	return p
}

func (t *RewardCritbitTrie) Add(
	address []byte,
	latestFrame uint64,
	reward uint64,
) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Root == nil {
		t.Root = &RewardNode{
			External: &RewardExternalNode{
				Key:           address,
				EarliestFrame: latestFrame,
				LatestFrame:   latestFrame,
				Total:         reward,
			},
		}
		return
	}

	p := t.findNearest(address)
	byteNumber, bits := p.critBit(address)
	if byteNumber < 0 {
		if p.External.LatestFrame < latestFrame {
			p.External.LatestFrame = latestFrame
		}
		if p.External.EarliestFrame > latestFrame {
			p.External.EarliestFrame = latestFrame
		}
		p.External.Total += reward
		return
	}

	node := &RewardInternalNode{
		ByteNumber: uint32(byteNumber),
		Bits:       bits,
	}

	blen := uint32(len(address))
	right := node.ByteNumber < blen &&
		address[node.ByteNumber]&node.Bits != 0
	e := &RewardExternalNode{
		Key:           address,
		EarliestFrame: latestFrame,
		LatestFrame:   latestFrame,
		Total:         reward,
	}
	if right {
		node.Child[1].External = e
	} else {
		node.Child[0].External = e
	}

	p = t.Root
	for m := p.Internal; m != nil; m = p.Internal {
		if m.ByteNumber > uint32(byteNumber) ||
			m.ByteNumber == uint32(byteNumber) && m.Bits < bits {
			break
		}

		if m.ByteNumber < blen && address[m.ByteNumber]&m.Bits != 0 {
			p = &m.Child[1]
		} else {
			p = &m.Child[0]
		}
	}

	if p.Internal != nil {
		// inverse the direction
		if right {
			node.Child[0].Internal = p.Internal
		} else {
			node.Child[1].Internal = p.Internal
		}
	} else {
		if right {
			node.Child[0].External = p.External
		} else {
			node.Child[1].External = p.External
			p.External = nil
		}
	}

	p.Internal = node
}

func (t *RewardCritbitTrie) Remove(address []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.Root == nil {
		return
	}

	blen := uint32(len(address))
	var gp *RewardNode
	p := t.Root
	var right bool

	for m := p.Internal; m != nil; m = p.Internal {
		right = p.Internal.ByteNumber < blen &&
			address[p.Internal.ByteNumber]&p.Internal.Bits != 0
		if right {
			gp, p = p, &m.Child[1]
		} else {
			gp, p = p, &m.Child[0]
		}
	}

	if !bytes.Equal(p.External.Key, address) {
		return
	}

	if gp == nil {
		p.External = nil
	} else {
		if right {
			gp.External, gp.Internal = gp.Internal.Child[0].External,
				gp.Internal.Child[0].Internal
		} else {
			gp.External, gp.Internal = gp.Internal.Child[1].External,
				gp.Internal.Child[1].Internal
		}
	}
}

func (n *RewardNode) String() string {
	if n.External != nil {
		return hex.EncodeToString(n.External.Key)
	} else {
		nodes := []string{}
		for i := range n.Internal.Child {
			nodes = append(nodes, n.Internal.Child[i].String())
		}
		return strings.Join(nodes, ",")
	}
}

func (n *RewardNode) Bits() []byte {
	if n.External != nil {
		return n.External.Key
	} else {
		return nil
	}
}

func (n *RewardNode) Info() (latestFrame uint64, total uint64) {
	if n.External != nil {
		return n.External.LatestFrame, n.External.Total
	} else {
		return 0, 0
	}
}

func (n *RewardNode) critBit(
	address []byte,
) (byteNumber int, bits byte) {
	smallestLen := len(n.External.Key)
	if len(address) < smallestLen {
		smallestLen = len(address)
	}

	for byteNumber = 0; byteNumber < smallestLen; byteNumber++ {
		if l, r := address[byteNumber], n.External.Key[byteNumber]; l != r {
			b := l ^ r
			b |= b >> 1
			b |= b >> 2
			b |= b >> 4
			bits = b &^ (b >> 1)
			return
		}
	}

	if len(n.External.Key) < len(address) {
		b := address[byteNumber]
		b |= b >> 1
		b |= b >> 2
		b |= b >> 4
		bits = b &^ (b >> 1)
	} else if len(n.External.Key) > len(address) {
		b := n.External.Key[byteNumber]
		b |= b >> 1
		b |= b >> 2
		b |= b >> 4
		bits = b &^ (b >> 1)
	} else {
		byteNumber = -1
	}
	return
}
