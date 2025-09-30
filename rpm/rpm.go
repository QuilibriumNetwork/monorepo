package rpm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"sort"
	"sync"
	"time"

	"filippo.io/edwards25519"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"go.uber.org/zap"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	generated "source.quilibrium.com/quilibrium/monorepo/rpm/generated/rpm"
	"source.quilibrium.com/quilibrium/monorepo/types/consensus"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/types/crypto"
)

//go:generate ./generate.sh

func RPMCombineSharesAndMask(
	ms [][][][][][]uint8,
	rs [][][][]uint8,
	size uint64,
	depth uint64,
	dealers uint64,
) generated.WrappedCombinedSharesAndMask {
	return generated.WrappedRpmCombineSharesAndMask(ms, rs, size, depth, dealers)
}

func RPMFinalize(input [][][]uint8, parties []uint64) [][]uint8 {
	return generated.WrappedRpmFinalize(input, parties)
}

func RPMGenerateInitialShares(
	size uint64,
	depth uint64,
	dealers uint64,
	players uint64,
) generated.WrappedInitialShares {
	return generated.WrappedRpmGenerateInitialShares(size, depth, dealers, players)
}

func RPMPermute(
	maskedInputShares [][][]uint8,
	mb [][][][][]uint8,
	rb [][][]uint8,
	mrmb [][][][][]uint8,
	depthIndex uint64,
	parties []uint64,
) [][][]uint8 {
	return generated.WrappedRpmPermute(
		maskedInputShares,
		mb,
		rb,
		mrmb,
		depthIndex,
		parties,
	)
}

func RPMSketchPropose(
	m [][][][][]uint8,
	r [][][]uint8,
) generated.WrappedSketchProposal {
	return generated.WrappedRpmSketchPropose(m, r)
}

func RPMSketchVerify(
	mcs [][][][][]uint8,
	rcs [][][]uint8,
	dealers uint64,
) bool {
	return generated.WrappedRpmSketchVerify(mcs, rcs, dealers)
}

type RPMMixnet struct {
	protobufs.MixnetServiceServer

	mu     sync.Mutex
	logger *zap.Logger

	// Mixnet status
	state consensus.MixnetState

	// Config/shape (constant per node unless reconfigured)
	depth   int
	players int
	dealers int

	// 25519 agreement key
	agreementKey qcrypto.Agreement

	// Parties are 1..players
	proverRegistry consensus.ProverRegistry
	selfParty      uint64
	parties        []uint64                 // len==players
	partyMap       map[string]uint64        // optional external id → party id
	peers          map[uint64]*peerEndpoint // partyID → endpoint

	// Active round
	roundID []byte

	// Accepted plaintext ciphertext bundles (from external users) for THIS round.
	// We store them as they come, they get merged after sketch verify ->
	// collecting.
	messages [][]byte

	// Node signing identity
	signer crypto.Signer

	// Mixnet peer-set selector / filter
	filter []byte

	// Active round state
	round *activeRound

	// Per-message waiters keyed by client-provided unique ephemeral pk (hex)
	waiters map[string]*messageWaiter

	// cached local combine/mask outputs for permute
	localMc  [][][][][]uint8
	localRc  [][][]uint8
	localMrm [][][][][]uint8
}

type MsgStore struct {
	RoundID []byte `json:"rid"`
	Data    []byte `json:"data"`
}

type MsgStoreAck struct {
	RoundID []byte `json:"rid"`
	Party   uint32 `json:"party"`
	Ok      bool   `json:"ok"`
}

func NewRPMMixnet(
	logger *zap.Logger,
	signer crypto.Signer,
	proverRegistry consensus.ProverRegistry,
	filter []byte,
) *RPMMixnet {
	return &RPMMixnet{
		logger:         logger,
		selfParty:      0,
		players:        9,
		dealers:        3,
		depth:          15,
		state:          consensus.MixnetStateIdle,
		signer:         signer,
		filter:         filter,
		proverRegistry: proverRegistry,
		partyMap:       make(map[string]uint64),
		peers:          make(map[uint64]*peerEndpoint),
		waiters:        make(map[string]*messageWaiter),
	}
}

// PutMessage accepts encrypted shards for each party and the message
// ciphertext. It blocks ONLY this caller until finalize resolves (success or
// no-decrypt), but does not block other PutMessage calls or round progress.
func (r *RPMMixnet) PutMessage(
	ctx context.Context,
	req *protobufs.PutMessageRequest,
) (*protobufs.PutMessageResponse, error) {
	if req == nil || len(req.MessageShards) == 0 || len(req.Message) == 0 ||
		len(req.EphemeralPublicKey) == 0 {
		return nil, errors.New("invalid request")
	}

	epkHex := hex.EncodeToString(req.EphemeralPublicKey)

	r.mu.Lock()
	// ensure active round
	if r.round == nil {
		return nil, errors.New("invalid state")
	}
	// Record waiter for this message
	if _, exists := r.waiters[epkHex]; !exists {
		r.waiters[epkHex] = &messageWaiter{done: make(chan putResult, 1)}
	}
	w := r.waiters[epkHex]
	curRoundID := slices.Clone(r.roundID)
	r.messages = append(r.messages, slices.Clone(req.Message))

	// Hand off to ingest goroutine: this does *not* block.
	r.round.ingestMsg <- &clientBundle{
		roundID:            slices.Clone(curRoundID),
		ephemeralPublicKey: slices.Clone(req.EphemeralPublicKey),
		message:            slices.Clone(req.Message),
		shards:             cloneShards(req.MessageShards),
	}
	r.mu.Unlock()
	env, _ := packWire(kindMessageBundle, &wireMessageBundle{
		RoundID:            slices.Clone(curRoundID),
		EphemeralPublicKey: slices.Clone(req.EphemeralPublicKey),
		Message:            slices.Clone(req.Message),
		Shards:             cloneShards(req.MessageShards),
	})
	for _, p := range r.peers {
		if p == nil || p.closed {
			continue
		}
		p.sendQ <- env
	}

	// Block this caller until their message resolves or ctx cancels
	select {
	case res := <-w.done:
		if res.err != nil {
			return nil, res.err
		}
		return &protobufs.PutMessageResponse{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// RoundStream is a bidirectional, long-lived stream per peer.
// We register the peer, spin up a writer goroutine, and feed inbound messages
// into the active round’s dispatcher.
func (r *RPMMixnet) RoundStream(
	srv protobufs.MixnetService_RoundStreamServer,
) error {
	defer func() {
		if a := recover(); r != nil {
			r.logger.Error("error in mixnet encountered", zap.Any("panic", a))
		}
	}()
	peer := newPeerEndpoint(srv, r.logger)

	// 1) Handshake: expect or send Hello to bind a party id.
	if err := r.roundstreamHandshake(peer); err != nil {
		return err
	}

	// 2) Start writer goroutine
	go peer.writer()

	// 3) Reader loop
	for {
		env, err := srv.Recv()
		if err != nil {
			peer.close()
			r.detachPeer(peer.partyID)
			return err
		}
		msg, kind, err := unpackWire(env)
		if err != nil {
			r.logger.Warn("discarding malformed envelope", zap.Error(err))
			continue
		}
		r.dispatchWire(peer, kind, msg)
	}
}

// GetMessages returns finalized, successfully decrypted messages of the
// last completed round.
func (r *RPMMixnet) GetMessages() []*protobufs.Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.round == nil {
		return nil
	}
	return r.round.getFinalMessages()
}

// GetState reports current state.
func (r *RPMMixnet) GetState() consensus.MixnetState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

// PrepareMixnet either starts a fresh round (Idle/Ready) or fast-forwards a
// reset back to Preparing.
func (r *RPMMixnet) PrepareMixnet() error {
	defer func() {
		if a := recover(); r != nil {
			r.logger.Error("error in mixnet encountered", zap.Any("panic", a))
		}
	}()
	r.mu.Lock()
	defer r.mu.Unlock()

	switch r.state {
	case consensus.MixnetStateIdle,
		consensus.MixnetStateReady,
		consensus.MixnetStateError:
		info, err := r.proverRegistry.GetActiveProvers(r.filter)
		if err != nil {
			return err
		}

		myIndex := -1
		addrbi, err := poseidon.HashBytes(r.signer.Public().([]byte))
		if err != nil {
			return err
		}

		partyCount := 0
		for i := range info {
			if bytes.Equal(info[i].Address, addrbi.FillBytes(make([]byte, 32))) {
				myIndex = i
			}
			partyCount++
		}

		r.selfParty = uint64(myIndex + 1)
		r.players = partyCount
		r.dealers = int(math.Sqrt(float64(partyCount)))

		r.bumpRoundLocked()
		r.ensureRoundLocked()
		r.state = consensus.MixnetStatePreparing
		go r.startDealerPhase(r.round)
		r.broadcast(&wireAckState{
			RoundID: r.roundID,
			State:   uint32(consensus.MixnetStatePreparing),
		})
		return nil
	case consensus.MixnetStatePreparing,
		consensus.MixnetStateCollecting,
		consensus.MixnetStateMixing:
		// already moving
		return nil
	default:
		return nil
	}
}

var _ consensus.Mixnet = (*RPMMixnet)(nil)

type activeRound struct {
	players int
	dealers int
	depth   int

	// Dealer phase fan-in (per player we collect dealers’ outputs)
	dealerIn chan *wireDealerShares

	// Sketch phase
	sketchIn chan *wireSketchProposal

	// Client message ingestion (external PutMessage bundles)
	ingestMsg chan *clientBundle

	// Permute/step fan-in per round step
	permuteIn chan *wirePermuteOut

	// Finalize signal from step depth-1
	finalize chan struct{}

	// Final outputs (decrypted OK)
	finalMu      sync.Mutex
	final        [][]byte
	finalBuilt   bool
	finalBuiltAt time.Time

	// Ingested messages
	clientMu sync.Mutex
	clientQ  []*clientBundle
}

func newActiveRound(players, dealers, depth int) *activeRound {
	return &activeRound{
		players:   players,
		dealers:   dealers,
		depth:     depth,
		dealerIn:  make(chan *wireDealerShares, 1024),
		sketchIn:  make(chan *wireSketchProposal, 1024),
		ingestMsg: make(chan *clientBundle, 2048),
		permuteIn: make(chan *wirePermuteOut, 2048),
		finalize:  make(chan struct{}, 1),
		clientQ:   make([]*clientBundle, 0, 256),
	}
}

func (ar *activeRound) getFinalMessages() []*protobufs.Message {
	ar.finalMu.Lock()
	defer ar.finalMu.Unlock()
	if !ar.finalBuilt {
		return nil
	}
	out := make([]*protobufs.Message, 0, len(ar.final))
	for _, m := range ar.final {
		out = append(out, &protobufs.Message{Payload: slices.Clone(m)})
	}
	return out
}

type peerEndpoint struct {
	partyID []byte
	srv     protobufs.MixnetService_RoundStreamServer
	logger  *zap.Logger

	// writer queue (non-blocking path for hot loop)
	sendQ chan *protobufs.Message

	closedMu sync.Mutex
	closed   bool
}

func newPeerEndpoint(
	srv protobufs.MixnetService_RoundStreamServer,
	logger *zap.Logger,
) *peerEndpoint {
	return &peerEndpoint{
		srv:    srv,
		logger: logger,
		sendQ:  make(chan *protobufs.Message, 1024),
	}
}

func (p *peerEndpoint) writer() {
	for env := range p.sendQ {
		if err := p.srv.Send(env); err != nil {
			p.logger.Warn("RoundStream send failed", zap.Error(err))
			p.close()
			return
		}
	}
}

func (p *peerEndpoint) send(env *protobufs.Message) {
	p.closedMu.Lock()
	defer p.closedMu.Unlock()
	if p.closed {
		return
	}
	select {
	case p.sendQ <- env:
	default:
		// backpressure fallback: drop oldest
		select {
		case <-p.sendQ:
		default:
		}
		p.sendQ <- env
	}
}

func (p *peerEndpoint) close() {
	p.closedMu.Lock()
	defer p.closedMu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	close(p.sendQ)
}

func (r *RPMMixnet) attachPeer(partyID []byte, ep *peerEndpoint) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ep.partyID = partyID
	info, err := r.proverRegistry.GetActiveProvers(r.filter)
	if err != nil {
		r.logger.Error("could not get active provers", zap.Error(err))
		return
	}
	for i := range info {
		if bytes.Equal(info[i].Address, partyID) {
			r.peers[uint64(i)] = ep
			return
		}
	}
}

func (r *RPMMixnet) detachPeer(partyID []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	info, err := r.proverRegistry.GetActiveProvers(r.filter)
	if err != nil {
		r.logger.Error("could not get active provers", zap.Error(err))
		return
	}
	for i := range info {
		if bytes.Equal(info[i].Address, partyID) {
			delete(r.peers, uint64(i))
			return
		}
	}
}

type wireKind string

const (
	kindHello         wireKind = "Hello"
	kindDealerShares  wireKind = "DealerShares"
	kindSketchProp    wireKind = "SketchProposal"
	kindSketchReset   wireKind = "SketchReset"
	kindAckState      wireKind = "AckState"
	kindMessageBundle wireKind = "MessageBundle"
	kindPermuteOut    wireKind = "PermuteOut"
	kindFinalize      wireKind = "Finalize"
)

type wireHello struct {
	PartyID []byte `json:"pid"`
}

type wireDealerShares struct {
	RoundID []byte `json:"rid"`
	From    uint64 `json:"from"`
	// Dealer payload: ms[depth][10][10][10][32], rs[depth][100][32] sliced per
	// receiver. Here we send only the slices intended for the recipient; channel
	// is pairwise already.
	Ms [][][][][]uint8 `json:"ms"`
	Rs [][][]uint8     `json:"rs"`
}

type wireSketchProposal struct {
	RoundID []byte                 `json:"rid"`
	From    uint64                 `json:"from"`
	Mp      [][][][]uint8          `json:"mp"`
	Rp      [][]uint8              `json:"rp"`
	M       [][][][][]uint8        `json:"m,omitempty"`
	R       [][][]uint8            `json:"r,omitempty"`
	Mrms    [][][][][]uint8        `json:"mrm,omitempty"`
	Parties []uint64               `json:"pt,omitempty"`
	Step    uint32                 `json:"st,omitempty"`
	Extra   map[string]interface{} `json:"x,omitempty"`
}

type wireSketchReset struct {
	RoundID []byte `json:"rid"`
	Reason  string `json:"why"`
}

type wireAckState struct {
	RoundID []byte `json:"rid"`
	State   uint32 `json:"st"`
}

type wireMessageBundle struct {
	RoundID            []byte                       `json:"rid"`
	EphemeralPublicKey []byte                       `json:"epk"`
	Message            []byte                       `json:"msg"`
	Shards             []*protobufs.MessageKeyShard `json:"shards"`
}

type wirePermuteOut struct {
	RoundID []byte    `json:"rid"`
	From    uint64    `json:"from"`
	Step    uint32    `json:"step"`
	Out     [][]uint8 `json:"out"` // [100][32]
}

type wireFinalize struct {
	RoundID []byte     `json:"rid"`
	Out     [][][]byte `json:"out"` // [players][N][32] or per-party slice
}

func packWire(kind wireKind, msg any) (*protobufs.Message, error) {
	b, err := marshal(msg)
	if err != nil {
		return nil, err
	}

	anyv := &anypb.Any{
		TypeUrl: string(kind),
		Value:   b,
	}

	payload, err := proto.Marshal(anyv)
	if err != nil {
		return nil, err
	}

	return &protobufs.Message{Payload: payload}, nil
}

func unpackWire(env *protobufs.Message) (any, wireKind, error) {
	if env == nil || env.Payload == nil {
		return nil, "", errors.New("empty envelope")
	}

	payload := &anypb.Any{}
	err := proto.Unmarshal(env.Payload, payload)
	if err != nil {
		return nil, "", err
	}

	k := wireKind(payload.TypeUrl)
	switch k {
	case kindHello:
		var v wireHello
		if err := unmarshal(payload.Value, &v); err != nil {
			return nil, "", err
		}
		return &v, k, nil
	case kindDealerShares:
		var v wireDealerShares
		if err := unmarshal(payload.Value, &v); err != nil {
			return nil, "", err
		}
		return &v, k, nil
	case kindSketchProp:
		var v wireSketchProposal
		if err := unmarshal(payload.Value, &v); err != nil {
			return nil, "", err
		}
		return &v, k, nil
	case kindSketchReset:
		var v wireSketchReset
		if err := unmarshal(payload.Value, &v); err != nil {
			return nil, "", err
		}
		return &v, k, nil
	case kindAckState:
		var v wireAckState
		if err := unmarshal(payload.Value, &v); err != nil {
			return nil, "", err
		}
		return &v, k, nil
	case kindMessageBundle:
		var v wireMessageBundle
		if err := unmarshal(payload.Value, &v); err != nil {
			return nil, "", err
		}
		return &v, k, nil
	case kindPermuteOut:
		var v wirePermuteOut
		if err := unmarshal(payload.Value, &v); err != nil {
			return nil, "", err
		}
		return &v, k, nil
	case kindFinalize:
		var v wireFinalize
		if err := unmarshal(payload.Value, &v); err != nil {
			return nil, "", err
		}
		return &v, k, nil
	default:
		return nil, "", fmt.Errorf("unknown type url %s", payload.TypeUrl)
	}
}

func (r *RPMMixnet) roundstreamHandshake(peer *peerEndpoint) error {
	// We don't know the remote PartyID yet. We accept either:
	//  - they send Hello first (we bind to that id), or
	//  - we proactively send Hello with our id and wait for their Hello reply
	// For simplicity, proactively send our Hello if we already know selfParty.
	if r.selfParty != 0 {
		env, _ := packWire(kindHello, &wireHello{
			PartyID: r.signer.Public().([]byte),
		})
		peer.send(env)
	}
	// Try to read one msg synchronously for Hello
	env, err := peer.srv.Recv()
	if err != nil {
		return err
	}
	msg, kind, err := unpackWire(env)
	if err != nil {
		return err
	}
	if kind != kindHello {
		return errors.New("expected Hello first on RoundStream")
	}
	hello := msg.(*wireHello)
	if len(hello.PartyID) == 0 {
		return errors.New("invalid party id")
	}
	r.attachPeer(hello.PartyID, peer)
	return nil
}

func (r *RPMMixnet) dispatchWire(
	peer *peerEndpoint,
	kind wireKind,
	payload any,
) {
	switch kind {
	case kindDealerShares:
		if r.round != nil {
			r.round.dealerIn <- payload.(*wireDealerShares)
		}
	case kindSketchProp:
		if r.round != nil {
			r.round.sketchIn <- payload.(*wireSketchProposal)
		}
	case kindSketchReset:
		r.resetToPreparing("peer requested reset")
	case kindAckState:
		// could track quorum acks if needed
	case kindMessageBundle:
		if r.round != nil {
			w := payload.(*wireMessageBundle)
			r.round.ingestMsg <- &clientBundle{
				roundID:            slices.Clone(w.RoundID),
				ephemeralPublicKey: slices.Clone(w.EphemeralPublicKey),
				message:            slices.Clone(w.Message),
				shards:             cloneShards(w.Shards),
			}
		}
	case kindPermuteOut:
		if r.round != nil {
			r.round.permuteIn <- payload.(*wirePermuteOut)
		}
	case kindFinalize:
		// Normally not used; each peer finalizes locally
	default:
		// ignore unknown
	}
}

func (r *RPMMixnet) startDealerPhase(ar *activeRound) {
	// If this party is a dealer, generate & broadcast initial shares to each
	// player.
	if r.isDealer(r.selfParty) {
		is := RPMGenerateInitialShares(
			100,
			uint64(r.depth),
			uint64(r.dealers),
			uint64(r.players),
		)
		// For each player i, slice out ms[i], rs[i] and send.
		for pid := 1; pid <= r.players; pid++ {
			i := pid - 1
			msi := sliceDealerMsForPlayer(is.Ms, i) // [][][][][][]byte
			rsi := sliceDealerRsForPlayer(is.Rs, i) // [][][][]byte
			env, err := packWire(kindDealerShares, &wireDealerShares{
				RoundID: r.roundID,
				From:    r.selfParty,
				Ms:      msi,
				Rs:      rsi,
			})
			if err == nil {
				if p := r.peers[uint64(pid)]; p != nil {
					p.send(env)
				}
			}
		}
	}

	// Wait until each player (including self) has all dealer shares, then
	// combine, mask, sketch propose/verify.
	go r.combineAndSketch(ar)
}

func (r *RPMMixnet) combineAndSketch(ar *activeRound) {
	type perPlayer struct {
		got int
		ms  [][][][][][]uint8 // dealers merged per spec
		rs  [][][][]uint8
	}

	byPlayer := make([]*perPlayer, r.players)
	for i := range byPlayer {
		byPlayer[i] = &perPlayer{
			ms: make([][][][][][]uint8, r.dealers),
			rs: make([][][][]uint8, r.dealers),
		}
	}

	// fan-in dealer shares until each player has dealers from all dealer ids
	dealerSeen := make(map[[2]int]bool) // (player-1, dealerPartyID-1)

	for {
		select {
		case ds := <-ar.dealerIn:
			if len(ds.Ms) == 0 || len(ds.Rs) == 0 {
				continue
			}
			// Map ds.From (dealer) to dealer index [0..dealers-1]
			dIdx := r.dealerIndex(ds.From)
			if dIdx < 0 {
				continue
			}
			// Destination player is "self" for our combination
			selfIdx := int(r.selfParty - 1)
			key := [2]int{selfIdx, dIdx}
			if !dealerSeen[key] {
				byPlayer[selfIdx].ms[dIdx] = ds.Ms
				byPlayer[selfIdx].rs[dIdx] = ds.Rs
				byPlayer[selfIdx].got++
				dealerSeen[key] = true
			}
			// Once "self" has all dealer shares, combine+mask and propose sketch
			if byPlayer[selfIdx].got == r.dealers {
				cs := RPMCombineSharesAndMask(
					byPlayer[selfIdx].ms,
					byPlayer[selfIdx].rs,
					100,
					uint64(r.depth),
					uint64(r.dealers),
				)
				// cache for permute
				r.mu.Lock()
				r.localMc = cs.Ms
				r.localRc = cs.Rs
				r.localMrm = cs.Mrms
				r.mu.Unlock()
				sp := RPMSketchPropose(cs.Ms, cs.Rs)
				w := &wireSketchProposal{
					RoundID: r.roundID,
					From:    r.selfParty,
					Mp:      sp.Mp,
					Rp:      sp.Rp,
				}
				env, _ := packWire(kindSketchProp, w)
				r.broadcastEnv(env)
				// Locally push as well to our verify loop
				ar.sketchIn <- w
				// Move to Collecting after verify succeeds (handled below)
			}
		case sp := <-ar.sketchIn:
			// Accumulate sketch proposals from all players; verify once we have all
			// For speed, verify incrementally; fail-fast triggers reset.
			ok := r.tryVerifySketch(sp, r.dealers)
			if !ok {
				r.broadcast(&wireSketchReset{
					RoundID: r.roundID,
					Reason:  "sketch verify failed",
				})
				r.resetToPreparing("sketch verify failed")
				return
			}
			// When we've verified all peers’ sketches (including ours), move to
			// Collecting
			if r.haveAllSketches() {
				r.setState(consensus.MixnetStateCollecting)
				r.broadcast(&wireAckState{
					RoundID: r.roundID,
					State:   uint32(consensus.MixnetStateCollecting),
				})
				// Start merging incoming client bundles and then Permute
				go r.collectAndPermute(ar)
				return
			}
		}
	}
}

func (r *RPMMixnet) collectAndPermute(ar *activeRound) {
	// Merge client message shares, then enter Mixing and run depth steps. We keep
	// xs as the current vector, and at each step gather Out from all peers
	// (including self).
	r.setState(consensus.MixnetStateMixing)
	r.broadcast(&wireAckState{
		RoundID: r.roundID,
		State:   uint32(consensus.MixnetStateMixing),
	})

	ar.clientMu.Lock()
	for b := range ar.ingestMsg {
		ar.clientQ = append(ar.clientQ, b)
	}
	ar.clientMu.Unlock()

	// Build xs from merged message shares
	xs := r.buildInitialXsFromClientBundles(ar)

	// Repeatedly run permute rounds
	for step := 0; step < r.depth; step++ {
		// Locally compute our permute out
		selfOut := RPMPermute(
			xs,
			r.localMc,
			r.localRc,
			r.localMrm,
			uint64(step),
			r.parties,
		)

		// Broadcast our out[0] ([][]uint8)
		env, _ := packWire(kindPermuteOut, &wirePermuteOut{
			RoundID: r.roundID,
			From:    r.selfParty,
			Step:    uint32(step),
			Out:     clone2D(selfOut[0]),
		})
		r.broadcastEnv(env)

		// Collect Out from all players for this step
		collected := make([][][]uint8, r.players)
		got := 0

		// include our own
		collected[int(r.selfParty-1)] = clone2D(selfOut[0])
		got++

		// Fast, low-latency fan-in (no large timeouts)
		for got < r.players {
			select {
			case po := <-ar.permuteIn:
				if int(po.Step) != step {
					continue
				}
				idx := int(po.From - 1)
				if collected[idx] == nil {
					collected[idx] = clone2D(po.Out)
					got++
				}
			}
		}
		// New xs becomes the set of collected outs (like your test’s ys)
		xs = collected

		// Finalize on last step
		if step == r.depth-1 {
			r.finalizeRound(ar, xs)
			return
		}
	}
}

func (r *RPMMixnet) finalizeRound(ar *activeRound, xs [][][]uint8) {
	// Try all keys produced by finalize to decrypt the message set.
	keys := RPMFinalize(xs, r.parties) // [][]uint8
	final := r.decryptMessagesWithKeys(ar, keys)

	ar.finalMu.Lock()
	ar.final = final
	ar.finalBuilt = true
	ar.finalBuiltAt = time.Now()
	ar.finalMu.Unlock()

	// Notify PutMessage waiters
	r.notifyWaiters(ar, final)

	// Move to Ready & auto-prepare next round
	r.setState(consensus.MixnetStateReady)
	r.broadcast(&wireAckState{
		RoundID: r.roundID,
		State:   uint32(consensus.MixnetStateReady),
	})
	r.localMc, r.localRc, r.localMrm = nil, nil, nil

	// Immediately kick the next round in the background
	r.bumpRoundLocked()
	r.ensureRoundLocked()
	r.state = consensus.MixnetStatePreparing
	go r.startDealerPhase(r.round)
	r.broadcast(&wireAckState{
		RoundID: r.roundID,
		State:   uint32(consensus.MixnetStatePreparing),
	})
}

func (r *RPMMixnet) isDealer(partyID uint64) bool {
	return int(partyID) >= 1 && int(partyID) <= r.dealers
}

func (r *RPMMixnet) dealerIndex(partyID uint64) int {
	if !r.isDealer(partyID) {
		return -1
	}
	return int(partyID - 1)
}

func (r *RPMMixnet) setState(s consensus.MixnetState) {
	r.mu.Lock()
	r.state = s
	r.mu.Unlock()
}

func (r *RPMMixnet) broadcast(msg any) {
	env, _ := packWire(kindAckState, msg)
	r.broadcastEnv(env)
}

func (r *RPMMixnet) broadcastEnv(env *protobufs.Message) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.peers {
		p.send(env)
	}
}

func (r *RPMMixnet) resetToPreparing(why string) {
	r.mu.Lock()
	r.state = consensus.MixnetStatePreparing
	r.bumpRoundLocked()
	r.ensureRoundLocked()
	r.mu.Unlock()
	r.broadcast(&wireSketchReset{RoundID: r.roundID, Reason: why})
	go r.startDealerPhase(r.round)
}

func (r *RPMMixnet) bumpRoundLocked() {
	r.roundID = make([]byte, 16)
	_, _ = rand.Read(r.roundID)
	// Clear waiters/messages for the old round
	r.waiters = make(map[string]*messageWaiter)
	r.messages = nil
}

func (r *RPMMixnet) ensureRoundLocked() {
	if r.round == nil {
		r.round = newActiveRound(r.players, r.dealers, r.depth)
	}
}

func (r *RPMMixnet) tryVerifySketch(p *wireSketchProposal, dealers int) bool {
	// In a full implementation: accumulate the set of Mp/Rp from all peers
	// and then call rpm.RPMSketchVerify(mccs, rccs, uint64(dealers)).
	// Here we optimistically return true — wire up to your accumulator.
	return true
}

func (r *RPMMixnet) haveAllSketches() bool {
	// Track count of unique From in received sketch proposals; compare to players.
	// For brevity, return true — wire up to your real counter/bitmap.
	return true
}

type clientBundle struct {
	roundID            []byte
	ephemeralPublicKey []byte
	message            []byte
	shards             []*protobufs.MessageKeyShard
}

type messageWaiter struct {
	done chan putResult
}

type putResult struct {
	err error
}

func (r *RPMMixnet) buildInitialXsFromClientBundles(
	ar *activeRound,
) [][][]uint8 {
	sort.Slice(ar.clientQ, func(i, j int) bool {
		return bytes.Compare(
			ar.clientQ[i].ephemeralPublicKey,
			ar.clientQ[j].ephemeralPublicKey,
		) < 0
	})

	players := r.players
	xs := make([][][]uint8, players)
	for j := 0; j < players; j++ {
		xs[j] = make([][]uint8, 100)
		for i := 0; i < 100; i++ {
			ecdh, err := r.agreementKey.AgreeWith(
				ar.clientQ[i].ephemeralPublicKey,
			)
			if err != nil {
				r.logger.Error("could not agree", zap.Error(err))
				xs[j][i] = r.localRc[0][i]
				continue
			}
			share, ok := decrypt(
				ecdh,
				r.roundID,
				ar.clientQ[i].shards[r.selfParty].EncryptedKey,
			)
			if !ok {
				r.logger.Error("could not decrypt")
				xs[j][i] = r.localRc[0][i]
				continue
			}
			rc := r.localRc[0][i]
			sum := ed25519ScalarAdd(share, rc)
			xs[j][i] = sum
		}
	}
	return xs
}

func (r *RPMMixnet) decryptMessagesWithKeys(
	ar *activeRound,
	keys [][]uint8,
) [][]byte {
	if len(ar.clientQ) == 0 || len(keys) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(ar.clientQ))
	for _, b := range ar.clientQ {
		epk := b.ephemeralPublicKey
		// try all keys until one succeeds
		for _, k := range keys {
			pt, ok := decryptBundleWithKey(epk, k, r.roundID, b.message)
			if ok {
				out = append(out, pt)
				break
			}
		}
	}
	return out
}

func (r *RPMMixnet) notifyWaiters(ar *activeRound, final [][]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for epk, w := range r.waiters {
		select {
		case w.done <- putResult{err: nil}:
		default:
			_ = epk
		}
	}
}

func cloneShards(in []*protobufs.MessageKeyShard) []*protobufs.MessageKeyShard {
	out := make([]*protobufs.MessageKeyShard, len(in))
	for i, s := range in {
		if s == nil {
			continue
		}
		cp := &protobufs.MessageKeyShard{
			PartyIdentifier: s.PartyIdentifier,
			EncryptedKey:    slices.Clone(s.EncryptedKey),
		}
		out[i] = cp
	}
	return out
}

func clone2D(a [][]byte) [][]byte {
	out := make([][]byte, len(a))
	for i := range a {
		if a[i] != nil {
			out[i] = slices.Clone(a[i])
		}
	}
	return out
}

// Slice helper to produce the per-player view from dealer outputs.
func sliceDealerMsForPlayer(
	ms [][][][][][]byte,
	playerIdx int,
) [][][][][]uint8 {
	return slices.Clone(ms[playerIdx])
}
func sliceDealerRsForPlayer(rs [][][][]byte, playerIdx int) [][][]uint8 {
	return slices.Clone(rs[playerIdx])
}

func marshal(v any) ([]byte, error)   { return json.Marshal(v) }
func unmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// ed25519ScalarAdd returns (a + b) mod ℓ as 32 bytes (canonical).
func ed25519ScalarAdd(a, b []byte) []byte {
	sa := new(edwards25519.Scalar)
	sb := new(edwards25519.Scalar)
	// SetCanonicalBytes enforces canonical reduction mod ℓ
	if _, err := sa.SetCanonicalBytes(a); err != nil {
		// fall back to zero if malformed
		sa = new(edwards25519.Scalar)
	}
	if _, err := sb.SetCanonicalBytes(b); err != nil {
		sb = new(edwards25519.Scalar)
	}
	out := new(edwards25519.Scalar).Add(sa, sb)
	return out.Bytes()
}

// ed25519PubToX25519 converts an Ed25519 encoded public key to a Montgomery X25519 public key.
func ed25519PubToX25519(edPub []byte) ([]byte, error) {
	var P edwards25519.Point
	if _, err := P.SetBytes(edPub); err != nil {
		return nil, err
	}
	return P.BytesMontgomery(), nil
}

// clampX25519 clamps a 32-byte scalar for X25519 usage.
func clampX25519(k []byte) []byte {
	d := make([]byte, 32)
	copy(d, k)
	d[0] &^= 7
	d[31] &^= 0x80
	d[31] |= 0x40
	return d
}

// decryptBundleWithKey derives a symmetric key via
// ECDH(ephemeralEd25519Pub, finalizeKeyScalar), then
// HKDF-SHA256(salt=roundID, info="rpm-mixnet-ecdh"), and AES-256-GCM decrypts
// message.
// Message format: 12-byte nonce || ciphertext || tag.
func decryptBundleWithKey(
	ephemeralEd25519Pub []byte,
	finalizeKey []byte,
	roundID []byte,
	msg []byte,
) ([]byte, bool) {
	if len(msg) < 12+16 { // nonce + tag at least
		return nil, false
	}

	xPub, err := ed25519PubToX25519(ephemeralEd25519Pub)
	if err != nil {
		return nil, false
	}

	xPriv := clampX25519(finalizeKey)
	shared, err := curve25519.X25519(xPriv, xPub)
	if err != nil {
		return nil, false
	}

	return decrypt(shared, roundID, msg)
}

func decrypt(shared []byte, roundID []byte, msg []byte) ([]byte, bool) {
	// HKDF derive 32-byte AES key
	hk := hkdf.New(sha256.New, shared, roundID, []byte("rpm-mixnet-ecdh"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hk, key); err != nil {
		return nil, false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false
	}
	nonce := msg[:12]
	ct := msg[12:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, false
	}
	return pt, true
}
