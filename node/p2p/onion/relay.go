package onion

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
)

type ValidEndpointFn func(ma multiaddr.Multiaddr) bool

type routeState struct {
	hk       *hopKeys            // this relay's hop keys for the circuit
	upPeer   string              // immediate upstream neighbor (who sent CREATE)
	upCirc   uint32              // circID used on upstream link
	downPeer string              // immediate downstream neighbor (set by ROUTE)
	downCirc uint32              // circID used on downstream link
	streamUp map[uint16]net.Conn // exit only: sid -> conn
}

type introPoint struct {
	// Circuit from service -> this intro relay
	upPeer string
	upCirc uint32
}

type rendWait struct {
	// recorded by rendezvous relay on REND1 (client half)
	upPeer string
	upCirc uint32
	sid    uint16
}

type spliceKey struct {
	circ uint32
	sid  uint16
}

type splicePair struct {
	// two half-streams joined at rendezvous
	aUpPeer string
	aUpCirc uint32
	aSid    uint16
	bUpPeer string
	bUpCirc uint32
	bSid    uint16
}

// Relay node that participates as a hop.
type Relay struct {
	logger          *zap.Logger
	selfID          string
	link            Transport
	keyFn           KeyFn
	secretFn        SharedSecretFn
	validEndpointFn ValidEndpointFn

	routingKey crypto.Agreement

	// State: per-link circID -> hop keys for this relay
	mu     sync.Mutex
	routes map[uint32]*routeState // keyed by upCirc OR downCirc

	// rendezvous listeners
	intro map[[32]byte]*introPoint  // serviceID -> intro registration
	rend  map[[16]byte]rendWait     // cookie -> client half
	sp    map[spliceKey]*splicePair // (circ,sid) -> pair (both directions)
}

func NewRelay(
	logger *zap.Logger,
	selfID string,
	t Transport,
	keyManager keys.KeyManager,
	keyFn KeyFn,
	secretFn SharedSecretFn,
	opts ...RelayOption,
) *Relay {
	r := &Relay{
		logger:   logger,
		selfID:   selfID,
		link:     t,
		keyFn:    keyFn,
		secretFn: secretFn,
		routes:   make(map[uint32]*routeState),
		intro:    make(map[[32]byte]*introPoint),
		rend:     make(map[[16]byte]rendWait),
		sp:       make(map[spliceKey]*splicePair),
	}

	routingKey, err := keyManager.GetAgreementKey("onion-routing-key")
	if err != nil {
		routingKey, err = keyManager.CreateAgreementKey(
			"onion-routing-key",
			crypto.KeyTypeX448,
		)

		if err != nil {
			panic(err)
		}
	}

	r.routingKey = routingKey

	for _, o := range opts {
		o(r)
	}

	// Register this relay as the receiver on its Transport
	t.OnReceive(r.onReceive)
	return r
}

type RelayOption func(*Relay)

// WithPermissiveValidator will accept all multiaddrs, used only for testing
func WithPermissiveValidator() RelayOption {
	return func(r *Relay) {
		r.validEndpointFn = func(ma multiaddr.Multiaddr) bool { return true }
	}
}

// WithDHTValidator validates multiaddrs based on both correctness of address,
// non-local access, and membership in the DHT.
func WithDHTValidator(dht *dht.IpfsDHT) RelayOption {
	dhtValidatorFn := func(ma multiaddr.Multiaddr) bool {
		// TODO(2.1.1+): when we support protocols outside of IPv4/6, this needs to
		// be updated
		ipComponent, err := ma.ValueForProtocol(multiaddr.P_IP4)
		if err != nil {
			ipComponent, err = ma.ValueForProtocol(multiaddr.P_IP6)
			if err != nil {
				return false
			}
		}

		ip := net.ParseIP(ipComponent)
		if ip == nil {
			return false
		}

		// Private or localhost
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() {
			return false
		}

		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil || info == nil {
			return false
		}

		// verify multiaddr is network member
		pi, err := dht.FindPeer(context.Background(), info.ID)
		if err != nil {
			return false
		}

		// If ma does not appear in set, we'll abort (TODO(2.1.1+): should we
		// consider this for aborting with prejudice?)
		found := false
		for _, a := range pi.Addrs {
			if a.Equal(ma) {
				found = true
				break
			}
		}

		// Only if found is it safe to proceed – (TODO(2.2+): MPCTLS would
		// differentiate on this)
		return found
	}

	return func(r *Relay) { r.validEndpointFn = dhtValidatorFn }
}

func (r *Relay) onReceive(srcPeerID []byte, circID uint32, cell []byte) {
	// Link-level control: CREATE -> CREATED
	if len(cell) >= 3 {
		cmd := cell[0]
		l := int(binary.BigEndian.Uint16(cell[1:3]))
		if 3+l <= len(cell) {
			switch cmd {
			case CmdCreate:
				r.handleCreate(srcPeerID, circID, cell[3:3+l])
				return
			case CmdCreated:
				// This must be a CREATED coming from our downstream link
				r.mu.Lock()
				// we aliased routes[downCirc] = rs when we sent CREATE down
				rs := r.routes[circID]
				r.mu.Unlock()
				if rs == nil || rs.upPeer == "" || rs.upCirc == 0 {
					return
				}
				// Wrap into RELAY EXTENDED and send upstream with Kb
				createdPayload := cell[3 : 3+l]
				raw, err := marshalRelay(relayHeader{
					Cmd:      CmdExtended,
					StreamID: 0,
					Length:   uint16(len(createdPayload)),
					Data:     createdPayload,
				}, payloadMax())
				if err != nil {
					return
				}

				r.mu.Lock()
				nonce := nonceFrom(rs.hk.kb.nonce, rs.hk.bCtr)
				rs.hk.bCtr++
				aeadB := rs.hk.kb.aead
				r.mu.Unlock()
				sealed := aeadB.Seal(nil, nonce, raw, nil)
				_ = r.link.Send(
					context.Background(),
					[]byte(rs.upPeer),
					rs.upCirc,
					sealed,
				)
				return
			}
		}
	}

	// Relay path (must have keys for this circ on this relay)
	r.mu.Lock()
	rs := r.routes[circID]
	r.mu.Unlock()
	if rs == nil {
		return
	}

	isForward := (circID == rs.upCirc) || (rs.upCirc == 0 && circID != rs.downCirc)

	if isForward {
		// Forward direction (client -> exit): peel one Kf layer and forward.
		var nonce []byte
		var aeadF cipherAEAD
		r.mu.Lock()
		nonce = nonceFrom(rs.hk.kf.nonce, rs.hk.fCtr)
		rs.hk.fCtr++
		aeadF = rs.hk.kf.aead
		r.mu.Unlock()

		plain, err := aeadF.Open(nil, nonce, cell, nil)
		if err != nil {
			return
		}

		h, err := unmarshalRelay(plain)
		if err != nil {
			// transit to deeper hop (still layered) – only forward if we already know
			// downstream
			if rs.downPeer != "" && rs.downCirc != 0 {
				_ = r.link.Send(
					context.Background(),
					[]byte(rs.downPeer),
					rs.downCirc,
					plain,
				)
			}

			return
		}

		switch h.Cmd {
		case CmdExtend:
			// Payload = nextPeerID || createPayload (last 121 bytes)
			if len(h.Data) < 121 {
				return
			}
			nextPeer := string(h.Data[:len(h.Data)-121])
			createPayload := h.Data[len(h.Data)-121:]

			// Allocate downstream circID local to this link
			downCirc := uint32(randUint(rand.Reader, 1<<32))

			r.mu.Lock()
			rs.downPeer = nextPeer
			rs.downCirc = downCirc
			r.routes[downCirc] = rs // alias lookup by downstream circ
			r.mu.Unlock()

			// Send link-level CREATE to next hop
			buf := make([]byte, 1+2+len(createPayload))
			buf[0] = CmdCreate
			binary.BigEndian.PutUint16(buf[1:3], uint16(len(createPayload)))
			copy(buf[3:], createPayload)

			_ = r.link.Send(context.Background(), []byte(nextPeer), downCirc, buf)
			return

		case CmdBegin, CmdData, CmdEnd:
			// If this (circ,sid) belongs to a rendezvous splice, forward across it.
			if h.Cmd == CmdData || h.Cmd == CmdEnd {
				r.mu.Lock()
				pair := r.sp[spliceKey{circ: circID, sid: h.StreamID}]
				r.mu.Unlock()

				if pair != nil {
					// Rewrite StreamID to the peer-local stream ID of the other half
					fwd := append([]byte(nil), plain...) // |Cmd|SID|Len|Data|
					var dstPeer string
					var dstCirc uint32
					var dstSid uint16

					if circID == pair.aUpCirc && h.StreamID == pair.aSid {
						dstPeer, dstCirc, dstSid = pair.bUpPeer, pair.bUpCirc, pair.bSid
					} else {
						dstPeer, dstCirc, dstSid = pair.aUpPeer, pair.aUpCirc, pair.aSid
					}

					binary.BigEndian.PutUint16(fwd[1:3], dstSid)

					r.mu.Lock()
					rsDst := r.routes[dstCirc]
					nonce := nonceFrom(rsDst.hk.kb.nonce, rsDst.hk.bCtr)
					rsDst.hk.bCtr++
					aeadB := rsDst.hk.kb.aead
					r.mu.Unlock()

					sealed := aeadB.Seal(nil, nonce, fwd, nil)
					_ = r.link.Send(
						context.Background(),
						[]byte(dstPeer),
						dstCirc,
						sealed,
					)

					return
				}
			}

			// Otherwise, treat as normal exit TCP handling
			r.exitHandlePlain(rs, h)

			return

		case CmdIntroEstablish:
			// Service registers an intro point at this relay
			if len(h.Data) != 32 {
				return
			}

			var sid [32]byte
			copy(sid[:], h.Data[:32])
			r.mu.Lock()
			r.intro[sid] = &introPoint{upPeer: rs.upPeer, upCirc: rs.upCirc}
			r.mu.Unlock()

			// Ack back to service over this circuit (Kb)
			raw, _ := marshalRelay(relayHeader{
				Cmd:      CmdIntroAck,
				StreamID: h.StreamID,
				Length:   0,
			}, payloadMax())
			r.mu.Lock()
			nonce := nonceFrom(rs.hk.kb.nonce, rs.hk.bCtr)
			rs.hk.bCtr++
			aeadB := rs.hk.kb.aead
			r.mu.Unlock()
			sealed := aeadB.Seal(nil, nonce, raw, nil)
			_ = r.link.Send(
				context.Background(),
				[]byte(rs.upPeer),
				rs.upCirc,
				sealed,
			)

			return

		case CmdRend1:
			// Client creates a rendezvous cookie at this relay
			if len(h.Data) != 16+2 {
				return
			}
			var cookie [16]byte
			copy(cookie[:], h.Data[:16])
			clientSid := binary.BigEndian.Uint16(h.Data[16:18])
			r.mu.Lock()
			r.rend[cookie] = rendWait{
				upPeer: rs.upPeer,
				upCirc: rs.upCirc,
				sid:    clientSid,
			}
			r.mu.Unlock()
			// (optional ack omitted)
			return

		case CmdIntroduce:
			// Client asks an intro relay to notify the service to rendezvous here
			if len(h.Data) < 32+1+16+2 {
				return
			}

			var sid [32]byte
			off := 0
			copy(sid[:], h.Data[off:off+32])
			off += 32
			nameLen := int(h.Data[off])
			off++

			if len(h.Data) < 32+1+nameLen+16+2 {
				return
			}

			// rendPeer := string(h.Data[off : off+nameLen])
			off += nameLen
			var cookie [16]byte
			copy(cookie[:], h.Data[off:off+16])
			off += 16

			// clientSid := binary.BigEndian.Uint16(h.Data[off : off+2])
			// Look up intro point (service must have registered here)
			r.mu.Lock()
			ip := r.intro[sid]
			r.mu.Unlock()
			if ip == nil {
				return
			}

			// Relay the INTRODUCE payload to the service over its intro circuit
			raw, err := marshalRelay(relayHeader{
				Cmd:      CmdIntroduce,
				StreamID: h.StreamID,
				Length:   uint16(len(h.Data)),
				Data:     append([]byte(nil), h.Data...),
			}, payloadMax())
			if err != nil {
				return
			}

			r.mu.Lock()

			ipRS := r.routes[ip.upCirc]
			if ipRS == nil {
				r.mu.Unlock()
				return
			}

			nonce := nonceFrom(ipRS.hk.kb.nonce, ipRS.hk.bCtr)
			ipRS.hk.bCtr++
			aeadB := ipRS.hk.kb.aead

			r.mu.Unlock()

			sealed := aeadB.Seal(nil, nonce, raw, nil)
			_ = r.link.Send(
				context.Background(),
				[]byte(ip.upPeer),
				ip.upCirc,
				sealed,
			)

			return

		case CmdRend2:
			// Service completes rendezvous at this relay; splice streams
			if len(h.Data) != 16+2 {
				return
			}
			var cookie [16]byte
			copy(cookie[:], h.Data[:16])
			serviceSid := binary.BigEndian.Uint16(h.Data[16:18])
			r.mu.Lock()
			w, ok := r.rend[cookie]
			if ok {
				pair := &splicePair{
					aUpPeer: w.upPeer, aUpCirc: w.upCirc, aSid: w.sid, // client
					bUpPeer: rs.upPeer, bUpCirc: rs.upCirc, bSid: serviceSid, // service
				}
				r.sp[spliceKey{circ: w.upCirc, sid: w.sid}] = pair
				r.sp[spliceKey{circ: rs.upCirc, sid: serviceSid}] = pair
				delete(r.rend, cookie)
			}
			r.mu.Unlock()
			if !ok {
				return
			}

			// Notify both sides that splice is ready
			notify := func(upPeer string, upCirc uint32, sid uint16) {
				raw, _ := marshalRelay(relayHeader{
					Cmd:      CmdRendEstablished,
					StreamID: sid,
					Length:   0,
				}, payloadMax())

				r.mu.Lock()
				rs2 := r.routes[upCirc]
				nonce := nonceFrom(rs2.hk.kb.nonce, rs2.hk.bCtr)
				rs2.hk.bCtr++
				aeadB := rs2.hk.kb.aead
				r.mu.Unlock()

				sealed := aeadB.Seal(nil, nonce, raw, nil)
				_ = r.link.Send(context.Background(), []byte(upPeer), upCirc, sealed)
			}
			notify(w.upPeer, w.upCirc, w.sid)
			notify(rs.upPeer, rs.upCirc, serviceSid)

			return

		default:
			// ignore other relay commands
			return
		}
	}

	// Backward direction (exit -> client): add our Kb layer and send upstream
	if circID == rs.downCirc {
		r.mu.Lock()
		nonce := nonceFrom(rs.hk.kb.nonce, rs.hk.bCtr)
		rs.hk.bCtr++
		aeadB := rs.hk.kb.aead
		r.mu.Unlock()

		sealed := aeadB.Seal(nil, nonce, cell, nil)
		_ = r.link.Send(context.Background(), []byte(rs.upPeer), rs.upCirc, sealed)
		return
	}
}

// exitHandlePlain processes a peeled relay header at the exit hop.
func (r *Relay) exitHandlePlain(
	rs *routeState,
	h relayHeader,
) {
	switch h.Cmd {
	case CmdBegin:
		ma, err := multiaddr.StringCast(string(h.Data))
		if err != nil || !r.validEndpointFn(ma) {
			r.exitSendEnd(rs, h.StreamID)
			return
		}

		conn, err := mn.Dial(ma)
		if err != nil {
			r.exitSendEnd(rs, h.StreamID)
			return
		}

		r.mu.Lock()
		rs.streamUp[h.StreamID] = conn
		r.mu.Unlock()
		go r.exitPumpUpstream(rs, h.StreamID, conn)

	case CmdData:
		// Forward client data to remote server.
		r.mu.Lock()
		conn := rs.streamUp[h.StreamID]
		r.mu.Unlock()
		if conn == nil || len(h.Data) == 0 {
			return
		}

		rest := h.Data
		for len(rest) > 0 {
			n, err := conn.Write(rest)
			if err != nil {
				_ = conn.Close()
				r.mu.Lock()
				delete(rs.streamUp, h.StreamID)
				r.mu.Unlock()
				r.exitSendEnd(rs, h.StreamID)
				return
			}
			rest = rest[n:]
		}

	case CmdEnd:
		// Client is closing; close remote and cleanup.
		r.mu.Lock()
		if c := rs.streamUp[h.StreamID]; c != nil {
			r.exitSendEnd(rs, h.StreamID)
			if cw, ok := any(c).(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			} else {
				_ = c.Close()
				delete(rs.streamUp, h.StreamID)
			}
		}
		r.mu.Unlock()
	}
}

// exitPumpUpstream reads from the remote server and sends DATA cells upstream,
// layering this hop's Kb (backward key). When the remote closes, it sends END.
func (r *Relay) exitPumpUpstream(rs *routeState, sid uint16, conn net.Conn) {
	defer func() {
		_ = conn.Close()
		r.mu.Lock()
		delete(rs.streamUp, sid)
		r.mu.Unlock()
		r.exitSendEnd(rs, sid)
	}()

	buf := make([]byte, 32<<10)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			data := buf[:n]
			for len(data) > 0 {
				chunk := data
				if len(chunk) > payloadMax() {
					chunk = chunk[:payloadMax()]
				}
				raw, mErr := marshalRelay(relayHeader{
					Cmd:      CmdData,
					StreamID: sid,
					Length:   uint16(len(chunk)),
					Data:     chunk,
				}, payloadMax())
				if mErr != nil {
					return
				}

				r.mu.Lock()
				nonce := nonceFrom(rs.hk.kb.nonce, rs.hk.bCtr)
				rs.hk.bCtr++
				aeadB := rs.hk.kb.aead
				r.mu.Unlock()

				sealed := aeadB.Seal(nil, nonce, raw, nil)
				_ = r.link.Send(
					context.Background(),
					[]byte(rs.upPeer),
					rs.upCirc,
					sealed,
				)

				if len(data) <= len(chunk) {
					break
				}
				data = data[len(chunk):]
			}
		}
		if err != nil {
			return
		}
	}
}

// exitSendEnd sends a CmdEnd upstream for a stream, layering with Kb.
func (r *Relay) exitSendEnd(rs *routeState, sid uint16) {
	raw, err := marshalRelay(relayHeader{
		Cmd:      CmdEnd,
		StreamID: sid,
		Length:   0,
		Data:     nil,
	}, payloadMax())
	if err != nil {
		return
	}

	r.mu.Lock()
	nonce := nonceFrom(rs.hk.kb.nonce, rs.hk.bCtr)
	rs.hk.bCtr++
	aeadB := rs.hk.kb.aead
	r.mu.Unlock()

	sealed := aeadB.Seal(nil, nonce, raw, nil)
	_ = r.link.Send(context.Background(), []byte(rs.upPeer), rs.upCirc, sealed)
}

// payload layout: fp(32) || circuitID(16) || clientEph(57) || cNonce(16)
func (r *Relay) handleCreate(srcPeerID []byte, circID uint32, payload []byte) {
	if len(payload) < 32+16+57+16 {
		return
	}

	fp := payload[0:32]
	circuitID := payload[32:48]
	clientEph := payload[48:105]
	cNonce := payload[105:121]

	// Compute shared secret using client eph pub and our onion secret
	shared, err := r.routingKey.AgreeWith(clientEph)
	if err != nil {
		return
	}

	// Make server eph + nonce
	serverEphPub, _, err := r.keyFn()
	if err != nil {
		return
	}

	var sNonce [16]byte
	_, _ = io.ReadFull(rand.Reader, sNonce[:])

	// MAC over transcript
	kMac := hkdfExpand(shared, []byte("QOR-NTOR-X448 v1/handshake-mac"), 32)
	transcript := concat(
		[]byte("QOR-NTOR-X448 v1"),
		circuitID,
		fp,
		clientEph,
		serverEphPub,
		cNonce,
		sNonce[:],
	)
	mac := hmacSHA256(kMac, transcript)

	// Derive per-hop keys and store under (this link, circID)
	hk, err := deriveHopKeys(circuitID, []byte(r.selfID), shared)
	if err != nil {
		return
	}

	// Register route state for this circuit, keyed by the upstream circID
	rs := &routeState{
		hk:       &hk,
		upPeer:   string(srcPeerID),
		upCirc:   circID,
		streamUp: make(map[uint16]net.Conn),
	}
	r.mu.Lock()
	r.routes[circID] = rs
	r.mu.Unlock()

	// Send CREATED (serverEph || sNonce || mac)
	resp := make([]byte, 0, 57+16+32)
	resp = append(resp, serverEphPub...)
	resp = append(resp, sNonce[:]...)
	resp = append(resp, mac...)
	buf := make([]byte, 1+2+len(resp))
	buf[0] = CmdCreated
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(resp)))
	copy(buf[3:], resp)
	_ = r.link.Send(context.Background(), srcPeerID, circID, buf)
}
