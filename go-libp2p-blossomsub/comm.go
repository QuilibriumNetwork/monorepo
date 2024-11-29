package blossomsub

import (
	"context"
	"encoding/binary"
	"io"
	"time"

	pool "github.com/libp2p/go-buffer-pool"
	"github.com/multiformats/go-varint"
	"google.golang.org/protobuf/proto"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"

	pb "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
)

// get the initial RPC containing all of our subscriptions to send to new peers
func (p *PubSub) getHelloPacket() *RPC {
	var rpc = &RPC{
		RPC: new(pb.RPC),
	}

	subscriptions := make(map[string]bool)

	for t := range p.mySubs {
		subscriptions[t] = true
	}

	for t := range p.myRelays {
		subscriptions[t] = true
	}

	for t := range subscriptions {
		as := &pb.RPC_SubOpts{
			Bitmask:   []byte(t),
			Subscribe: true,
		}
		rpc.Subscriptions = append(rpc.Subscriptions, as)
	}
	return rpc
}

func (p *PubSub) handleNewStream(s network.Stream) {
	peer := s.Conn().RemotePeer()

	p.inboundStreamsMx.Lock()
	other, dup := p.inboundStreams[peer]
	if dup {
		log.Debugf("duplicate inbound stream from %s; resetting other stream", peer)
		other.Reset()
	}
	p.inboundStreams[peer] = s
	p.inboundStreamsMx.Unlock()

	r := msgio.NewVarintReaderSize(s, p.hardMaxMessageSize)
	for {
		msgbytes, err := r.ReadMsg()
		if err != nil {
			r.ReleaseMsg(msgbytes)
			if err != io.EOF {
				s.Reset()
				log.Debugf("error reading rpc from %s: %s", s.Conn().RemotePeer(), err)
			} else {
				// Just be nice. They probably won't read this
				// but it doesn't hurt to send it.
				s.Close()
			}

			p.inboundStreamsMx.Lock()
			if p.inboundStreams[peer] == s {
				delete(p.inboundStreams, peer)
			}
			p.inboundStreamsMx.Unlock()
			return
		}
		if len(msgbytes) == 0 {
			r.ReleaseMsg(msgbytes)
			continue
		}

		rpc := &RPC{
			RPC: new(pb.RPC),
		}
		err = rpc.Unmarshal(msgbytes)
		r.ReleaseMsg(msgbytes)
		if err != nil {
			s.Reset()
			log.Warnf("bogus rpc from %s: %s", s.Conn().RemotePeer(), err)
			p.inboundStreamsMx.Lock()
			if p.inboundStreams[peer] == s {
				delete(p.inboundStreams, peer)
			}
			p.inboundStreamsMx.Unlock()
			return
		}

		rpc.from = peer
		select {
		case p.incoming <- rpc:
		case <-p.ctx.Done():
			// Close is useless because the other side isn't reading.
			s.Reset()
			p.inboundStreamsMx.Lock()
			if p.inboundStreams[peer] == s {
				delete(p.inboundStreams, peer)
			}
			p.inboundStreamsMx.Unlock()
			return
		}
	}
}

func (p *PubSub) notifyPeerDead(pid peer.ID) {
	p.peerDeadPrioLk.RLock()
	p.peerDeadMx.Lock()
	p.peerDeadPend[pid] = struct{}{}
	p.peerDeadMx.Unlock()
	p.peerDeadPrioLk.RUnlock()

	select {
	case p.peerDead <- struct{}{}:
	default:
	}
}

func (p *PubSub) handleNewPeer(ctx context.Context, pid peer.ID, q *rpcQueue) {
	s, err := p.host.NewStream(p.ctx, pid, p.rt.Protocols()...)
	if err != nil {
		log.Debug("opening new stream to peer: ", err, pid)

		select {
		case p.newPeerError <- pid:
		case <-ctx.Done():
		}

		return
	}

	go p.handleSendingMessages(ctx, s, q)
	go p.handlePeerDead(s)
	select {
	case p.newPeerStream <- s:
	case <-ctx.Done():
	}
}

func (p *PubSub) handleNewPeerWithBackoff(ctx context.Context, pid peer.ID, backoff time.Duration, q *rpcQueue) {
	select {
	case <-time.After(backoff):
		p.handleNewPeer(ctx, pid, q)
	case <-ctx.Done():
		return
	}
}

func (p *PubSub) handlePeerDead(s network.Stream) {
	pid := s.Conn().RemotePeer()

	_, err := s.Read([]byte{0})
	if err == nil {
		log.Debugf("unexpected message from %s", pid)
	}

	s.Reset()
	p.notifyPeerDead(pid)
}

func (p *PubSub) handleSendingMessages(ctx context.Context, s network.Stream, q *rpcQueue) {
	getBuffer, returnLastBuffer := makeBufferSource()
	defer returnLastBuffer()
	writeRPC := func(rpc *RPC) error {
		size := uint64(rpc.Size())
		buf := getBuffer(varint.UvarintSize(size) + int(size))
		n := binary.PutUvarint(buf, size)
		_, err := rpc.MarshalTo(buf[n:])
		if err != nil {
			return err
		}
		_, err = s.Write(buf)
		return err
	}
	defer s.Close()
	defer s.Reset()
	for {
		rpc, err := q.Pop(ctx)
		if err != nil {
			log.Debugf("pop RPC from queue: %s", err)
			return
		}
		if err := writeRPC(rpc); err != nil {
			log.Debugf("writing message to %s: %s", s.Conn().RemotePeer(), err)
			return
		}
	}
}

func rpcWithSubs(subs ...*pb.RPC_SubOpts) *RPC {
	return &RPC{
		RPC: &pb.RPC{
			Subscriptions: subs,
		},
	}
}

func rpcWithMessages(msgs ...*pb.Message) *RPC {
	return &RPC{RPC: &pb.RPC{Publish: msgs}}
}

func rpcWithControl(msgs []*pb.Message,
	ihave []*pb.ControlIHave,
	iwant []*pb.ControlIWant,
	graft []*pb.ControlGraft,
	prune []*pb.ControlPrune,
	idontwant []*pb.ControlIDontWant) *RPC {
	return &RPC{
		RPC: &pb.RPC{
			Publish: msgs,
			Control: &pb.ControlMessage{
				Ihave:     ihave,
				Iwant:     iwant,
				Graft:     graft,
				Prune:     prune,
				Idontwant: idontwant,
			},
		},
	}
}

func copyRPC(rpc *RPC) *RPC {
	res := new(RPC)
	*res = *rpc
	res.RPC = (proto.Clone(rpc.RPC)).(*pb.RPC)
	return res
}

// makeBufferSource returns a function that can be used to allocate buffers of
// a given size, and a function that can be used to return the last buffer
// allocated.
// The returned function will attempt to reuse the last buffer allocated if
// the requested size is less than or equal to the capacity of the last buffer.
// If the requested size is greater than the capacity of the last buffer, the
// last buffer is returned to the pool and a new buffer is allocated.
// If the requested size is less than or equal to half the capacity of the last
// buffer, the last buffer is returned to the pool and a new buffer is allocated.
func makeBufferSource() (func(int) []byte, func()) {
	b := pool.Get(0)
	mk := func(n int) []byte {
		if c := cap(b); c/2 < n && n <= c {
			return b[:n]
		}
		pool.Put(b)
		b = pool.Get(n)
		return b
	}
	rt := func() {
		pool.Put(b)
	}
	return mk, rt
}
