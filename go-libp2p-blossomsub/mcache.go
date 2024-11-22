package blossomsub

import (
	"bytes"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
)

// NewMessageCache creates a sliding window cache that remembers messages for as
// long as `history` slots.
//
// When queried for messages to advertise, the cache only returns messages in
// the last `gossip` slots.
//
// The `gossip` parameter must be smaller or equal to `history`, or this
// function will panic.
//
// The slack between `gossip` and `history` accounts for the reaction time
// between when a message is advertised via IHAVE gossip, and the peer pulls it
// via an IWANT command.
func NewMessageCache(gossip, history int) *MessageCache {
	if gossip > history {
		err := fmt.Errorf("invalid parameters for message cache; gossip slots (%d) cannot be larger than history slots (%d)",
			gossip, history)
		panic(err)
	}
	return &MessageCache{
		msgs:    make(map[string]*Message),
		peertx:  make(map[string]map[peer.ID]int),
		history: make([][]CacheEntry, history),
		gossip:  gossip,
		msgID: func(msg *Message) []byte {
			return DefaultMsgIdFn(msg.Message)
		},
	}
}

type MessageCache struct {
	msgs    map[string]*Message
	peertx  map[string]map[peer.ID]int
	history [][]CacheEntry
	gossip  int
	msgID   func(*Message) []byte
}

func (mc *MessageCache) SetMsgIdFn(msgID func(*Message) []byte) {
	mc.msgID = msgID
}

type CacheEntry struct {
	mid     []byte
	bitmask []byte
}

func (mc *MessageCache) Put(msg *Message) {
	mid := mc.msgID(msg)
	mc.msgs[string(mid)] = msg
	for _, bitmask := range SliceBitmask(msg.GetBitmask()) {
		mc.history[0] = append(mc.history[0], CacheEntry{mid: mid, bitmask: bitmask})
	}
}

func (mc *MessageCache) Get(mid []byte) (*Message, bool) {
	m, ok := mc.msgs[string(mid)]
	return m, ok
}

func (mc *MessageCache) GetForPeer(mid []byte, p peer.ID) (*Message, int, bool) {
	m, ok := mc.msgs[string(mid)]
	if !ok {
		return nil, 0, false
	}

	tx, ok := mc.peertx[string(mid)]
	if !ok {
		tx = make(map[peer.ID]int)
		mc.peertx[string(mid)] = tx
	}
	tx[p]++

	return m, tx[p], true
}

func (mc *MessageCache) GetGossipIDs(bitmask []byte) [][]byte {
	var mids [][]byte
	for _, entries := range mc.history[:mc.gossip] {
		for _, entry := range entries {
			if bytes.Equal(entry.bitmask, bitmask) {
				mids = append(mids, entry.mid)
			}
		}
	}
	return mids
}

func (mc *MessageCache) Shift() {
	last := mc.history[len(mc.history)-1]
	for _, entry := range last {
		delete(mc.msgs, string(entry.mid))
		delete(mc.peertx, string(entry.mid))
	}
	for i := len(mc.history) - 2; i >= 0; i-- {
		mc.history[i+1] = mc.history[i]
	}
	mc.history[0] = last[:0]
}
