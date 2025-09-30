package onion

import (
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
)

type createdWaitKey struct {
	peer string
	circ uint32
}

// OnionRouter provides TOR-style onion routing as a flexible transport
// mechanism, pluggable with other Capabilities. It has very familiar
// communication semantics to TOR. Uses ChaCha20-Poly1305 instead of AES-GCM
// to provide better performance where hardware acceleration is unavailable.
type OnionRouter struct {
	logger     *zap.Logger
	peers      p2p.PeerInfoManager
	signers    consensus.SignerRegistry
	keyManager keys.KeyManager
	link       Transport
	keyFn      KeyFn
	secretFn   SharedSecretFn
	keyUsage   string
	rng        io.Reader

	// circuits and streams
	mu          sync.RWMutex
	circuits    map[[16]byte]*Circuit
	streams     map[uint32]*onionStream        // key: circuitID||streamID packed
	linkCirc    map[string]map[uint32]*Circuit // peerID -> circID -> circuit
	createdWait map[createdWaitKey]chan []byte // waits for CREATED payloads
}

type Option func(*OnionRouter)

func WithTransport(t Transport) Option {
	return func(r *OnionRouter) { r.link = t }
}

func WithKeyConstructor(f KeyFn) Option {
	return func(r *OnionRouter) { r.keyFn = f }
}

func WithSharedSecret(f SharedSecretFn) Option {
	return func(r *OnionRouter) { r.secretFn = f }
}

func NewOnionRouter(
	logger *zap.Logger,
	peerManager p2p.PeerInfoManager,
	signerRegistry consensus.SignerRegistry,
	keyManager keys.KeyManager,
	opts ...Option,
) *OnionRouter {
	r := &OnionRouter{
		logger:     logger,
		peers:      peerManager,
		signers:    signerRegistry,
		keyManager: keyManager,
		keyUsage:   DefaultOnionKeyPurpose,
		rng:        rand.Reader,
		circuits:   make(map[[16]byte]*Circuit),
		streams:    make(map[uint32]*onionStream),
		linkCirc:   make(map[string]map[uint32]*Circuit),
	}

	for _, o := range opts {
		o(r)
	}

	if r.link != nil {
		r.link.OnReceive(r.handleInboundCell)
	}

	return r
}

type hopKeys struct {
	// AEADs for this hop
	kf, kb aead // forward/backward
	// per-direction nonces (monotonic counters)
	fCtr, bCtr uint64
}

type hopState struct {
	peerID  []byte
	onionPK []byte
	keys    hopKeys
}

type Circuit struct {
	ID          [16]byte
	Hops        []hopState // entry -> ... -> exit
	EntryCircID uint32
	CreatedAt   time.Time
	LinkCirc    map[string]uint32 // peerID(string) -> link-local circID

	// Guards per-hop nonce counters during forward (client->exit) layering
	// and backward (exit->client) peeling. These avoid concurrent increments
	// from e.g. the write pump and Close() sending END, and from multiple
	// inbound cells arriving concurrently.
	fwdMu sync.Mutex
	bwdMu sync.Mutex
}

// AEAD wrapper
type aead struct {
	aead  cipherAEAD
	nonce [12]byte // prefix; last 8 bytes overwritten by counter
}

type cipherAEAD interface {
	Seal(dst, nonce, plaintext, ad []byte) []byte
	Open(dst, nonce, ciphertext, ad []byte) ([]byte, error)
}

// Build a circuit using Tor-like telescoping: for each hop, do a one-way DH
// with that hop’s onion key -> HKDF -> derive Kf/Kb and per-hop nonce prefixes.
func (r *OnionRouter) BuildCircuit(ctx context.Context, hops int) (
	*Circuit,
	error,
) {
	if r.secretFn == nil {
		return nil, errors.Wrap(
			errors.New("shared secret fn required"),
			"build circuit",
		)
	}

	cands, err := r.selectRoutingPeers()
	if err != nil {
		return nil, err
	}

	if len(cands) < hops {
		return nil, errors.Wrap(
			fmt.Errorf("need %d routing peers, have %d", hops, len(cands)),
			"build circuit",
		)
	}

	var id [16]byte
	if _, err := io.ReadFull(r.rng, id[:]); err != nil {
		return nil, err
	}

	c := &Circuit{ID: id, CreatedAt: time.Now(), LinkCirc: map[string]uint32{}}

	// Choose entry hop and register link-local circ on client<->entry link
	entryPM := cands[0]
	r.registerEntryCirc(c, entryPM.PeerId)
	c.LinkCirc[string(entryPM.PeerId)] = c.EntryCircID
	// assign circIDs for the other hops
	for _, pm := range cands[1:hops] {
		c.LinkCirc[string(pm.PeerId)] = uint32(randUint(r.rng, 1<<32))
	}

	// Handshake telescopically
	for i, pm := range cands[:hops] {
		onionPub, err := r.resolveOnionKey(pm.PeerId)
		if err != nil {
			return nil, errors.Wrap(err, "build circuit")
		}

		// Ephemeral and shared secret per hop
		clientEphPub, ephPriv, err := r.keyFn()
		if err != nil {
			return nil, errors.Wrap(err, "build circuit")
		}
		shared, err := r.secretFn(ephPriv, onionPub)
		if err != nil {
			return nil, errors.Wrap(err, "build circuit")
		}

		// Nonce for transcript
		var cNonce [16]byte
		if _, err := io.ReadFull(r.rng, cNonce[:]); err != nil {
			return nil, err
		}

		createPayload := r.buildCreatePayload(c, onionPub, clientEphPub, cNonce)

		if i == 0 {
			// First hop: direct CREATE/CREATED
			hk, err := r.extendToHop(ctx, c, pm.PeerId, onionPub)
			if err != nil {
				return nil, errors.Wrap(err, "build circuit")
			}
			c.Hops = append(c.Hops, hopState{
				peerID:  slices.Clone(pm.PeerId),
				onionPK: slices.Clone(onionPub),
				keys:    hk,
			})
			continue
		}

		// Hop i>0: send relay EXTEND via entry
		// Register wait for EXTENDED arriving on entry link
		key := createdWaitKey{peer: string(c.Hops[0].peerID), circ: c.EntryCircID}
		ch := make(chan []byte, 1)
		r.mu.Lock()
		if r.createdWait == nil {
			r.createdWait = make(map[createdWaitKey]chan []byte)
		}
		r.createdWait[key] = ch
		r.mu.Unlock()

		// Pack EXTEND payload: nextHopID || createPayload (createPayload is fixed
		// 121 bytes)
		extendData := append(append([]byte{}, pm.PeerId...), createPayload...)

		if err := r.sendRelay(c, relayHeader{
			Cmd:      CmdExtend,
			StreamID: 0,
			Length:   uint16(len(extendData)),
			Data:     extendData,
		}); err != nil {
			return nil, errors.Wrap(err, "send extend")
		}

		// Wait for EXTENDED (CREATED wrapped in a relay cell) on entry
		var resp []byte
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case resp = <-ch: // resp is the CREATED payload: 57||16||32
		}

		// Verify MAC
		if len(resp) < 57+16+32 {
			return nil, errors.New("extended: short payload")
		}
		serverEph := resp[0:57]
		var sNonce [16]byte
		copy(sNonce[:], resp[57:73])
		mac := resp[73:105]

		kMac := hkdfExpand(shared, []byte("QOR-NTOR-X448 v1/handshake-mac"), 32)
		hash := sha256.Sum256(onionPub)
		transcript := concat([]byte("QOR-NTOR-X448 v1"), c.ID[:],
			hash[:], clientEphPub, serverEph, cNonce[:], sNonce[:])
		if !hmacEqual(mac, hmacSHA256(kMac, transcript)) {
			return nil, errors.New("extended: MAC mismatch")
		}

		// Derive hop keys
		hk, err := deriveHopKeys(c.ID[:], pm.PeerId, shared)
		if err != nil {
			return nil, err
		}

		c.Hops = append(c.Hops, hopState{
			peerID:  slices.Clone(pm.PeerId),
			onionPK: slices.Clone(onionPub),
			keys:    hk,
		})

		// cleanup waiter
		r.mu.Lock()
		delete(r.createdWait, key)
		r.mu.Unlock()
	}

	r.mu.Lock()
	r.circuits[c.ID] = c
	r.mu.Unlock()

	r.logger.Info(
		"built circuit",
		zap.String("id", hex.EncodeToString(c.ID[:])),
		zap.Int("hops", len(c.Hops)),
	)
	return c, nil
}

// BuildCircuitToExit constructs a circuit of length hops whose exit hop is
// exitPeerID. It performs the same Tor-like telescoping used by BuildCircuit,
// but with a deterministic exit.
func (r *OnionRouter) BuildCircuitToExit(
	ctx context.Context,
	hops int,
	exitPeerID []byte,
) (*Circuit, error) {
	if r.secretFn == nil || r.keyFn == nil {
		return nil, errors.Wrap(
			errors.New("key constructor and shared secret functions are required"),
			"build circuit to exit",
		)
	}

	if hops < 1 {
		return nil, errors.Wrap(
			errors.New("hops must be >= 1"),
			"build circuit to exit",
		)
	}

	// Ensure the exit peer exists and is routing-capable.
	exitPM := r.peers.GetPeerInfo(exitPeerID)
	if exitPM == nil || !hasCapability(exitPM, ProtocolRouting) {
		return nil, errors.Wrap(
			errors.New("exit peer unavailable or lacks routing capability"),
			"build circuit to exit",
		)
	}

	// Gather candidates for the *non-exit* hops.
	cands, err := r.selectRoutingPeers()
	if err != nil {
		return nil, err
	}

	// Filter out the chosen exit.
	filtered := make([]*p2p.PeerInfo, 0, len(cands))
	for _, pm := range cands {
		if string(pm.PeerId) == string(exitPeerID) {
			continue
		}
		filtered = append(filtered, pm)
	}

	if (hops - 1) > len(filtered) {
		return nil, errors.Wrap(
			fmt.Errorf(
				"need %d routing peers (excluding exit), have %d",
				hops-1,
				len(filtered),
			),
			"build circuit to exit",
		)
	}

	// Pick first (hops-1) from filtered (already shuffled in selectRoutingPeers),
	// then append exit at the end.
	route := make([]*p2p.PeerInfo, 0, hops)
	if hops > 1 {
		route = append(route, filtered[:hops-1]...)
	}
	route = append(route, exitPM) // exit last

	// Allocate circuit ID and per-link circ ids (same pattern as BuildCircuit).
	var id [16]byte
	if _, err := io.ReadFull(r.rng, id[:]); err != nil {
		return nil, err
	}

	c := &Circuit{ID: id, CreatedAt: time.Now(), LinkCirc: map[string]uint32{}}

	// Entry hop registration
	entryPM := route[0]
	r.registerEntryCirc(c, entryPM.PeerId)
	c.LinkCirc[string(entryPM.PeerId)] = c.EntryCircID

	// Assign circIDs for other hops on their respective links
	for _, pm := range route[1:] {
		c.LinkCirc[string(pm.PeerId)] = uint32(randUint(r.rng, 1<<32))
	}

	// Telescoping handshake over the chosen route
	for i, pm := range route {
		onionPub, err := r.resolveOnionKey(pm.PeerId)
		if err != nil {
			return nil, errors.Wrap(err, "build circuit to exit")
		}
		if i == 0 {
			// First hop via CREATE/CREATED
			hk, err := r.extendToHop(ctx, c, pm.PeerId, onionPub)
			if err != nil {
				return nil, errors.Wrap(err, "build circuit to exit")
			}
			c.Hops = append(c.Hops, hopState{
				peerID:  slices.Clone(pm.PeerId),
				onionPK: slices.Clone(onionPub),
				keys:    hk,
			})
			continue
		}

		// Hop i>0: relay EXTEND via entry.
		// Prepare per-hop ephemeral + shared secret.
		clientEphPub, ephPriv, err := r.keyFn()
		if err != nil {
			return nil, errors.Wrap(err, "build circuit to exit")
		}

		shared, err := r.secretFn(ephPriv, onionPub)
		if err != nil {
			return nil, errors.Wrap(err, "build circuit to exit")
		}

		var cNonce [16]byte
		if _, err := io.ReadFull(r.rng, cNonce[:]); err != nil {
			return nil, err
		}

		createPayload := r.buildCreatePayload(c, onionPub, clientEphPub, cNonce)

		// Waiter for EXTENDED arriving on the entry link.
		key := createdWaitKey{peer: string(c.Hops[0].peerID), circ: c.EntryCircID}
		ch := make(chan []byte, 1)
		r.mu.Lock()
		if r.createdWait == nil {
			r.createdWait = make(map[createdWaitKey]chan []byte)
		}
		r.createdWait[key] = ch
		r.mu.Unlock()

		defer func() {
			r.mu.Lock()
			delete(r.createdWait, key)
			r.mu.Unlock()
		}()

		// Pack EXTEND payload: nextHopID || createPayload (createPayload is 121
		// bytes).
		extendData := append(append([]byte{}, pm.PeerId...), createPayload...)
		if err := r.sendRelay(c, relayHeader{
			Cmd:      CmdExtend,
			StreamID: 0,
			Length:   uint16(len(extendData)),
			Data:     extendData,
		}); err != nil {
			return nil, errors.Wrap(err, "build circuit to exit")
		}

		// Await EXTENDED.
		var resp []byte
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case resp = <-ch:
		}

		// Verify MAC and derive hop keys (same as BuildCircuit).
		if len(resp) < 57+16+32 {
			return nil, errors.Wrap(
				errors.New("extended: short payload"),
				"build circuit to exit",
			)
		}

		serverEph := resp[0:57]
		var sNonce [16]byte
		copy(sNonce[:], resp[57:73])
		mac := resp[73:105]
		kMac := hkdfExpand(shared, []byte("QOR-NTOR-X448 v1/handshake-mac"), 32)
		hash := sha256.Sum256(onionPub)

		transcript := concat(
			[]byte("QOR-NTOR-X448 v1"),
			c.ID[:],
			hash[:],
			clientEphPub,
			serverEph,
			cNonce[:],
			sNonce[:],
		)

		if !hmacEqual(mac, hmacSHA256(kMac, transcript)) {
			return nil, errors.Wrap(
				errors.New("extended: MAC mismatch"),
				"build circuit to exit",
			)
		}

		hk, err := deriveHopKeys(c.ID[:], pm.PeerId, shared)
		if err != nil {
			return nil, err
		}

		c.Hops = append(c.Hops, hopState{
			peerID:  slices.Clone(pm.PeerId),
			onionPK: slices.Clone(onionPub),
			keys:    hk,
		})

		// Clean createdWait for this hop before next iteration.
		r.mu.Lock()
		delete(r.createdWait, key)
		r.mu.Unlock()
	}

	r.mu.Lock()
	r.circuits[c.ID] = c
	r.mu.Unlock()

	r.logger.Info(
		"built circuit (to exit)",
		zap.String("id", hex.EncodeToString(c.ID[:])),
		zap.Int("hops", len(c.Hops)),
		zap.Binary("exit", exitPeerID),
	)
	return c, nil
}

// RegisterIntro builds a circuit to the given intro relay and registers this
// node as an introduction point for the provided 32-byte serviceID. Keep the
// returned circuit alive on the caller side if you want the intro to persist.
func (r *OnionRouter) RegisterIntro(
	ctx context.Context,
	introPeerID []byte,
	serviceID [32]byte,
) (*Circuit, error) {
	if len(introPeerID) == 0 {
		return nil, errors.Wrap(
			errors.New("intro peer id required"),
			"register intro",
		)
	}

	c, err := r.BuildCircuit(ctx, 3)
	if err != nil {
		return nil, err
	}

	sid := uint16(randUint(r.rng, 1<<16))
	payload := make([]byte, 32)
	copy(payload, serviceID[:])

	if err := r.sendRelay(c, relayHeader{
		Cmd:      CmdIntroEstablish,
		StreamID: sid,
		Length:   32,
		Data:     payload,
	}); err != nil {
		return nil, errors.Wrap(err, "register intro")
	}

	return c, nil
}

// ClientStartRendezvous sends REND1(cookie, clientSid) on the provided circuit
// (to the rendezvous relay).
func (r *OnionRouter) ClientStartRendezvous(
	c *Circuit,
	cookie [16]byte,
	clientSid uint16,
) error {
	data := make([]byte, 18)
	copy(data[:16], cookie[:])
	binary.BigEndian.PutUint16(data[16:18], clientSid)

	return errors.Wrap(
		r.sendRelay(c, relayHeader{
			Cmd:      CmdRend1,
			StreamID: clientSid,
			Length:   uint16(len(data)),
			Data:     data,
		}),
		"client start rendezvous",
	)
}

// ClientIntroduce sends INTRODUCE(serviceID, rendezvousPeer, cookie, clientSid)
// to an intro relay over circuit c.
func (r *OnionRouter) ClientIntroduce(
	c *Circuit,
	serviceID [32]byte,
	rendezvousPeer string,
	cookie [16]byte,
	clientSid uint16,
) error {
	rp := []byte(rendezvousPeer)
	intro := make([]byte, 0, 32+1+len(rp)+16+2)
	intro = append(intro, serviceID[:]...)
	intro = append(intro, byte(len(rp)))
	intro = append(intro, rp...)
	intro = append(intro, cookie[:]...)
	intro = append(intro, byte(clientSid>>8), byte(clientSid))

	return errors.Wrap(
		r.sendRelay(c, relayHeader{
			Cmd:      CmdIntroduce,
			StreamID: 0,
			Length:   uint16(len(intro)),
			Data:     intro,
		}),
		"client introduce",
	)
}

// ServiceCompleteRendezvous sends REND2(cookie, serviceSid) on the provided
// circuit (to the rendezvous relay).
func (r *OnionRouter) ServiceCompleteRendezvous(
	c *Circuit,
	cookie [16]byte,
	serviceSid uint16,
) error {
	data := make([]byte, 18)
	copy(data[:16], cookie[:])
	binary.BigEndian.PutUint16(data[16:18], serviceSid)

	return r.sendRelay(c, relayHeader{
		Cmd:      CmdRend2,
		StreamID: serviceSid,
		Length:   uint16(len(data)),
		Data:     data,
	})
}

// OpenStreamConn returns a net.Conn bound to (circuit, streamID) that
// reads/writes via onion DATA/END. It does NOT send BEGIN; intended for
// rendezvous streams where both sides already know the stream IDs.
func (r *OnionRouter) OpenStreamConn(c *Circuit, sid uint16) net.Conn {
	s := &onionStream{
		circID:   c.ID,
		streamID: sid,
		readCh:   make(chan []byte, 32),
		writeCh:  make(chan []byte, 32),
		errCh:    make(chan error, 1),
		closed:   make(chan struct{}),
	}
	r.mu.Lock()
	r.streams[streamsID(c.ID, sid)] = s
	r.mu.Unlock()

	// Pump writes -> DATA cells
	go func() {
		for {
			select {
			case <-s.closed:
				return

			case b, ok := <-s.writeCh:
				if !ok {
					return
				}

				for len(b) > 0 {
					chunk := b
					max := payloadMax()
					if len(chunk) > max {
						chunk = chunk[:max]
					}

					_ = r.sendRelay(c, relayHeader{
						Cmd:      CmdData,
						StreamID: sid,
						Length:   uint16(len(chunk)),
						Data:     chunk,
					})

					if len(b) <= max {
						break
					}

					b = b[max:]
				}
			}
		}
	}()

	return &onionConn{r: r, c: c, s: s, deadlineMx: &sync.Mutex{}}
}

func (r *OnionRouter) buildCreatePayload(
	c *Circuit,
	onionPub []byte,
	clientEphPub []byte,
	cNonce [16]byte,
) []byte {
	// fp(32) || circuitID(16) || clientEph(57) || cNonce(16) = 121 bytes
	fp := sha256.Sum256(onionPub)
	payload := make([]byte, 0, 32+16+57+16)
	payload = append(payload, fp[:]...)
	payload = append(payload, c.ID[:]...)
	payload = append(payload, clientEphPub...)
	payload = append(payload, cNonce[:]...)
	return payload
}

// extendToHop performs the entry-hop handshake (CREATE/CREATED) and returns
// derived hopKeys.
func (r *OnionRouter) extendToHop(
	ctx context.Context,
	c *Circuit,
	hopPeerID, onionPub []byte,
) (hopKeys, error) {
	if r.keyFn == nil {
		return hopKeys{}, errors.Wrap(
			errors.New("key fn required"),
			"extend to hop",
		)
	}

	if r.secretFn == nil {
		return hopKeys{}, errors.Wrap(
			errors.New("shared secret fn required"),
			"extend to hop",
		)
	}
	if c.EntryCircID == 0 {
		return hopKeys{}, errors.Wrap(
			errors.New("entry circ id not registered"),
			"extend to hop",
		)
	}

	// 1) Ephemeral keypair + DH
	clientEphPub, ephPriv, err := r.keyFn()
	if err != nil {
		return hopKeys{}, errors.Wrap(err, "extend to hop")
	}

	shared, err := r.secretFn(ephPriv, onionPub)
	if err != nil {
		return hopKeys{}, errors.Wrap(err, "extend to hop")
	}

	// 2) Build CREATE payload: fp(server static), circuitID, client eph,
	// client nonce
	fp := sha256.Sum256(onionPub) // 32B fingerprint of server's static key
	var cNonce [16]byte
	if _, err := io.ReadFull(r.rng, cNonce[:]); err != nil {
		return hopKeys{}, errors.Wrap(
			fmt.Errorf("rng: %w", err),
			"extend to hop",
		)
	}

	// Layout: fp(32) || circuitID(16) || clientEph(57) || cNonce(16)
	createPayload := make([]byte, 32+16+57+16)
	off := 0
	copy(createPayload[off:off+32], fp[:])
	off += 32
	copy(createPayload[off:off+16], c.ID[:])
	off += 16
	copy(createPayload[off:off+57], clientEphPub)
	off += 57
	copy(createPayload[off:off+16], cNonce[:])
	off += 16

	// 3) Prepare to await CREATED (demuxed by srcPeerID + circID)
	key := createdWaitKey{
		peer: string(hopPeerID),
		circ: c.LinkCirc[string(hopPeerID)],
	}
	ch := make(chan []byte, 1)
	r.mu.Lock()
	if r.createdWait == nil {
		r.createdWait = make(map[createdWaitKey]chan []byte)
	}
	r.createdWait[key] = ch
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.createdWait, key)
		r.mu.Unlock()
	}()

	circ := c.LinkCirc[string(hopPeerID)]
	if circ == 0 {
		return hopKeys{}, errors.Wrap(
			errors.New("missing per-hop circ id"),
			"extend to hop",
		)
	}

	// 4) Send CREATE as a link-level control cell
	if err := r.sendControl(
		ctx,
		hopPeerID,
		circ,
		CmdCreate,
		createPayload,
	); err != nil {
		return hopKeys{}, err
	}

	// 5) Wait for CREATED
	var resp []byte
	select {
	case <-ctx.Done():
		return hopKeys{}, ctx.Err()
	case resp = <-ch:
	}

	// CREATED payload layout: serverEph(57) || sNonce(16) || mac(32)
	if len(resp) < 57+16+32 {
		return hopKeys{}, errors.Wrap(
			errors.New("created: short payload"),
			"extend to hop",
		)
	}
	serverEph := resp[0:57]
	var sNonce [16]byte
	copy(sNonce[:], resp[57:73])
	mac := resp[73:105]

	// 6) Verify MAC over the handshake transcript
	//    K_mac = HKDF(shared, info="QOR-NTOR-X448 v1/handshake-mac", len=32)
	kMac := hkdfExpand(shared, []byte("QOR-NTOR-X448 v1/handshake-mac"), 32)
	transcript := concat(
		[]byte("QOR-NTOR-X448 v1"),
		c.ID[:],
		fp[:],
		clientEphPub,
		serverEph,
		cNonce[:],
		sNonce[:],
	)

	expMac := hmacSHA256(kMac, transcript)
	if !hmacEqual(mac, expMac) {
		return hopKeys{}, errors.Wrap(
			errors.New("created: MAC mismatch"),
			"extend to hop",
		)
	}

	// 7) Derive relay-layer keys for this hop (forward/backward + nonce prefixes)
	keys, err := deriveHopKeys(c.ID[:], hopPeerID, shared)
	if err != nil {
		return hopKeys{}, errors.Wrap(err, "extend to hop")
	}

	return keys, nil
}

// sendControl constructs a frame with link-level control cell pads to CellSize
// and sends
func (r *OnionRouter) sendControl(
	ctx context.Context,
	peerID []byte,
	circID uint32,
	cmd byte,
	payload []byte,
) error {
	if len(payload) > CellSize-3 {
		return errors.Wrap(
			fmt.Errorf("control payload too large"),
			"send control",
		)
	}

	buf := make([]byte, 1+2+len(payload))
	buf[0] = cmd
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(payload)))
	copy(buf[3:], payload)

	if len(buf) < CellSize {
		pad := make([]byte, CellSize)
		copy(pad, buf)
		buf = pad
	}

	return errors.Wrap(
		r.link.Send(ctx, peerID, circID, buf),
		"send control",
	)
}

func (r *OnionRouter) registerEntryCirc(c *Circuit, entryPeerId []byte) uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := uint32(randUint(r.rng, 1<<32))
	if r.linkCirc == nil {
		r.linkCirc = make(map[string]map[uint32]*Circuit)
	}

	pk := string(entryPeerId)
	if r.linkCirc[pk] == nil {
		r.linkCirc[pk] = make(map[uint32]*Circuit)
	}

	r.linkCirc[pk][id] = c
	c.EntryCircID = id

	return id
}

func (r *OnionRouter) closeStream(c *Circuit, s *onionStream) {
	// Drop from map
	key := streamsID(c.ID, s.streamID)
	r.mu.Lock()
	s.closeOnce.Do(func() { close(s.closed) })
	s.readCloseOnce.Do(func() { close(s.readCh) })
	delete(r.streams, key)
	r.mu.Unlock()
}

func (r *OnionRouter) selectRoutingPeers() ([]*p2p.PeerInfo, error) {
	ids := r.peers.GetPeersBySpeed()
	out := make([]*p2p.PeerInfo, 0, len(ids))
	seen := map[string]struct{}{}

	for _, id := range ids {
		k := string(id)
		if _, ok := seen[k]; ok {
			continue
		}

		seen[k] = struct{}{}

		pm := r.peers.GetPeerInfo(id)
		if pm == nil {
			continue
		}

		if !hasCapability(pm, ProtocolRouting) {
			continue
		}

		out = append(out, pm)
	}

	shuffle(r.rng, out)
	return out, nil
}

func hasCapability(pm *p2p.PeerInfo, x uint32) bool {
	for _, c := range pm.Capabilities {
		if c.ProtocolIdentifier == x {
			return true
		}
	}
	return false
}

func (r *OnionRouter) resolveOnionKey(
	peerIdentityAddr []byte,
) ([]byte, error) {
	keys, err := r.signers.GetSignedKeysByParent(peerIdentityAddr, r.keyUsage)
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 || keys[0].Key.KeyValue == nil ||
		len(keys[0].Key.KeyValue) == 0 {
		return nil, errors.Wrap(
			errors.New("no onion key"),
			"resolve onion key",
		)
	}

	return slices.Clone(keys[0].Key.KeyValue), nil
}

// Derive Tor-like forward/backward keys with independent nonce prefixes.
// Inputs are domain-separated with circuitID and peerID so counters are unique.
func deriveHopKeys(circuitID, peerID, dh []byte) (hopKeys, error) {
	info := append([]byte("QOR-HOP-KEYS v1\x00"), circuitID...)
	info = append(info, peerID...)
	kdf := hkdf.New(sha256.New, dh, nil, info)

	m := make([]byte, 32+12+32+12) // Kf(32) || Nf(12) || Kb(32) || Nb(12)
	if _, err := io.ReadFull(kdf, m); err != nil {
		return hopKeys{}, err
	}

	kfKey, nf := m[0:32], m[32:44]
	kbKey, nb := m[44:76], m[76:88]

	aKf, err := chacha20poly1305.New(kfKey)
	if err != nil {
		return hopKeys{}, err
	}
	aKb, err := chacha20poly1305.New(kbKey)
	if err != nil {
		return hopKeys{}, err
	}

	var nf12, nb12 [12]byte
	copy(nf12[:], nf)
	copy(nb12[:], nb)
	return hopKeys{
		kf:   aead{aead: wrap(aKf), nonce: nf12},
		kb:   aead{aead: wrap(aKb), nonce: nb12},
		fCtr: 0, bCtr: 0,
	}, nil
}

type stdAEAD struct{ a cipher.AEAD }

func wrap(a cipher.AEAD) stdAEAD {
	return stdAEAD{a: a}
}

func (s stdAEAD) Seal(dst, n, p, ad []byte) []byte {
	return s.a.Seal(dst, n, p, ad)
}

func (s stdAEAD) Open(dst, n, c, ad []byte) ([]byte, error) {
	return s.a.Open(dst, n, c, ad)
}

func (s stdAEAD) Noncesize() int { return s.a.NonceSize() }

// Nonce = noncePrefix[0:4] || uint64(counter) big-endian.
// (12 bytes total for ChaCha20-Poly1305)
func nonceFrom(prefix [12]byte, ctr uint64) []byte {
	var n [12]byte
	copy(n[:4], prefix[:4])
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n[:]
}

// applyForward encrypts for exit->...->entry (reverse hop order)
func applyForward(c *Circuit, inner []byte) ([]byte, error) {
	out := inner
	for i := len(c.Hops) - 1; i >= 0; i-- {
		h := &c.Hops[i]
		nonce := nonceFrom(h.keys.kf.nonce, h.keys.fCtr)
		h.keys.fCtr++
		out = h.keys.kf.aead.Seal(nil, nonce, out, nil)
	}

	return out, nil
}

// peelBackward decrypts data coming back from entry (encrypting hop-by-hop with
// Kb)
func peelBackward(c *Circuit, outer []byte) ([]byte, error) {
	in := outer
	for i := 0; i < len(c.Hops); i++ {
		h := &c.Hops[i]
		nonce := nonceFrom(h.keys.kb.nonce, h.keys.bCtr)
		h.keys.bCtr++

		var err error
		in, err = h.keys.kb.aead.Open(nil, nonce, in, nil)
		if err != nil {
			return nil, errors.Wrap(
				fmt.Errorf("open layer %d: %w", i, err),
				"peel backward",
			)
		}
	}

	return in, nil
}

type onionStream struct {
	circID   [16]byte
	streamID uint16

	// app I/O
	readCh  chan []byte
	writeCh chan []byte
	errCh   chan error

	// close
	closeOnce     sync.Once
	closed        chan struct{}
	readCloseOnce sync.Once
}

// streamsID returns packed key for streams map: upper 16 bytes circuitID,
// lower 16 bits streamID.
func streamsID(cID [16]byte, sID uint16) uint32 {
	// short key for map, low collision risk for local process
	return binary.BigEndian.Uint32(cID[12:16]) ^ uint32(sID)<<16 ^ 0x5eed
}

// GRPCDialer returns a grpc.WithContextDialer-compatible function.
func (r *OnionRouter) GRPCDialer(c *Circuit) func(
	ctx context.Context,
	addr string,
) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		// Allocate a new StreamID (simple random 16-bit)
		sid := uint16(randUint(r.rng, 1<<16))
		s := &onionStream{
			circID:   c.ID,
			streamID: sid,
			readCh:   make(chan []byte, 32),
			writeCh:  make(chan []byte, 32),
			errCh:    make(chan error, 1),
			closed:   make(chan struct{}),
		}

		r.mu.Lock()
		r.streams[streamsID(c.ID, sid)] = s
		r.mu.Unlock()

		// Send BEGIN(addr)
		if err := r.sendRelay(c, relayHeader{
			Cmd:      CmdBegin,
			StreamID: sid,
			Length:   uint16(len(addr)),
			Data:     []byte(addr),
		}); err != nil {
			return nil, err
		}

		// Pump writes -> DATA cells
		go func() {
			for {
				select {
				case <-s.closed:
					return
				case b, ok := <-s.writeCh:
					if !ok {
						return
					}

					for len(b) > 0 {
						chunk := b
						max := payloadMax()
						if len(chunk) > max {
							chunk = chunk[:max]
						}

						_ = r.sendRelay(c, relayHeader{
							Cmd:      CmdData,
							StreamID: sid,
							Length:   uint16(len(chunk)),
							Data:     chunk,
						})
						if len(b) <= max {
							break
						}

						b = b[max:]
					}
				}
			}
		}()

		return &onionConn{r: r, c: c, s: s, deadlineMx: &sync.Mutex{}}, nil
	}
}

// sendRelay builds a relay header, layers it, and ships a fixed-size cell to
// the entry hop.
func (r *OnionRouter) sendRelay(c *Circuit, h relayHeader) error {
	max := payloadMax()
	raw, err := marshalRelay(h, max)
	if err != nil {
		return err
	}

	// Protect forward counters while layering this cell
	c.fwdMu.Lock()
	layered, err := applyForward(c, raw)
	c.fwdMu.Unlock()
	if err != nil {
		return err
	}

	entry := c.Hops[0].peerID
	return r.link.Send(context.Background(), entry, c.EntryCircID, layered)
}

func payloadMax() int {
	// AEAD adds 16 bytes tag per layer; but we layer *before* link padding.
	// We packed header+data and then layered; the tag growth is inside the
	// layered blob. To stay simple, we cap relay payload to (CellSize - minimal
	// headers) generously.
	return 256
}

// handleInboundCell handles inbound from link: peel layers and dispatch to
// stream.
func (r *OnionRouter) handleInboundCell(
	srcPeerID []byte,
	circID uint32,
	cell []byte,
) {
	// Link-control fast path
	if len(cell) >= 3 {
		cmd := cell[0]
		l := int(binary.BigEndian.Uint16(cell[1:3]))
		if 3+l <= len(cell) && cmd == CmdCreated {
			payload := cell[3 : 3+l]
			r.onCreated(srcPeerID, circID, payload)
			return
		}
	}

	r.mu.RLock()
	m := r.linkCirc[string(srcPeerID)]
	c := m[circID]
	r.mu.RUnlock()
	if c == nil {
		return
	}

	// Protect backward counters while peeling this cell
	c.bwdMu.Lock()
	plain, err := peelBackward(c, cell)
	c.bwdMu.Unlock()
	if err != nil {
		return
	}

	// parse relay header
	h, err := unmarshalRelay(plain)
	if err != nil {
		return
	}

	// EXTENDED: deliver to the same wait channel used above
	if h.Cmd == CmdExtended {
		r.onCreated(srcPeerID, circID, append([]byte(nil), h.Data...))
		return
	}

	key := streamsID(c.ID, h.StreamID)
	r.mu.Lock()
	s, ok := r.streams[key]
	defer r.mu.Unlock()
	if !ok {
		// might be BEGIN OK control; ignore for brevity
		return
	}

	switch h.Cmd {
	case CmdData:
		select {
		case <-s.closed:
		case s.readCh <- append([]byte(nil), h.Data...):
		}
	case CmdEnd:
		r.mu.Unlock()
		r.closeStream(c, s)
		r.mu.Lock()
	case CmdSendMe:
		// TODO(2.1.1+): metering
	default:
		// ignore or log
	}
}

// onCreated pushes CREATED payload to the waiting goroutine (if any).
func (r *OnionRouter) onCreated(
	srcPeerID []byte,
	circID uint32,
	payload []byte,
) {
	key := createdWaitKey{peer: string(srcPeerID), circ: circID}
	r.mu.RLock()
	ch := r.createdWait[key]
	r.mu.RUnlock()

	if ch != nil {
		select {
		case ch <- append([]byte(nil), payload...):
		default:
		}
	}
}

func shuffle[T any](rng io.Reader, s []T) {
	n := len(s)
	for i := n - 1; i > 0; i-- {
		j := randInt(rng, i+1)
		s[i], s[j] = s[j], s[i]
	}
}

func randInt(r io.Reader, n int) int {
	if n <= 1 {
		return 0
	}
	max := big.NewInt(int64(n))
	v, err := rand.Int(r, max)
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

func randUint(r io.Reader, n uint64) uint64 {
	if n <= 1 {
		return 0
	}
	max := new(big.Int).SetUint64(n)
	v, _ := rand.Int(r, max)
	return v.Uint64()
}

func hkdfExpand(secret, info []byte, n int) []byte {
	r := hkdf.New(sha256.New, secret, nil, info)
	out := make([]byte, n)
	io.ReadFull(r, out)
	return out
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func hmacEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func concat(parts ...[]byte) []byte {
	var tot int
	for _, p := range parts {
		tot += len(p)
	}
	out := make([]byte, 0, tot)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
