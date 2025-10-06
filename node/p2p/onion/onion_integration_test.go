package onion_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	health "google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"source.quilibrium.com/quilibrium/monorepo/node/consensus/registration"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p/onion"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	tkeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

type inbound struct {
	src    string
	circID uint32
	cell   []byte
}

type mesh struct {
	mu       sync.RWMutex
	handlers map[string]func(srcPeerID []byte, circID uint32, cell []byte)
	queues   map[string]chan inbound // per-destination FIFO
}

func newMesh() *mesh {
	return &mesh{handlers: map[string]func([]byte, uint32, []byte){}, queues: map[string]chan inbound{}}
}

func (m *mesh) register(peer string, h func([]byte, uint32, []byte)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[peer] = h
	if _, ok := m.queues[peer]; !ok {
		q := make(chan inbound, 1024)
		m.queues[peer] = q
		go func(dest string, ch <-chan inbound) {
			for in := range ch {
				m.mu.RLock()
				cb := m.handlers[dest]
				m.mu.RUnlock()
				if cb != nil {
					cb([]byte(in.src), in.circID, in.cell)
				}
			}
		}(peer, q)
	}
}

func (m *mesh) deliver(src, dst string, circID uint32, cell []byte) error {
	m.mu.RLock()
	q := m.queues[dst]
	m.mu.RUnlock()
	if q == nil {
		return fmt.Errorf("no handler for %s", dst)
	}
	q <- inbound{src: src, circID: circID, cell: append([]byte(nil), cell...)}
	return nil
}

type meshPeerTransport struct {
	mesh   *mesh
	selfID string
}

func (t *meshPeerTransport) Send(ctx context.Context, peerID []byte, circID uint32, cell []byte) error {
	return t.mesh.deliver(t.selfID, string(peerID), circID, cell)
}
func (t *meshPeerTransport) OnReceive(cb func(srcPeerID []byte, circID uint32, cell []byte)) {
	l := func(srcPeerID []byte, circID uint32, cell []byte) {
		cb(srcPeerID, circID, cell)
	}
	t.mesh.register(t.selfID, l)
}

type memKeyStore struct {
	signed map[string][]*protobufs.SignedX448Key // parentAddr(string) -> keys
}

// DeleteSignedDecaf448Key implements store.KeyStore.
func (m *memKeyStore) DeleteSignedDecaf448Key(txn store.Transaction, address []byte) error {
	panic("unimplemented")
}

// DeleteSignedX448Key implements store.KeyStore.
func (m *memKeyStore) DeleteSignedX448Key(txn store.Transaction, address []byte) error {
	panic("unimplemented")
}

// GetSignedDecaf448Key implements store.KeyStore.
func (m *memKeyStore) GetSignedDecaf448Key(address []byte) (*protobufs.SignedDecaf448Key, error) {
	panic("unimplemented")
}

// GetSignedDecaf448KeysByParent implements store.KeyStore.
func (m *memKeyStore) GetSignedDecaf448KeysByParent(parentKeyAddress []byte, keyPurpose string) ([]*protobufs.SignedDecaf448Key, error) {
	panic("unimplemented")
}

// GetSignedX448Key implements store.KeyStore.
func (m *memKeyStore) GetSignedX448Key(address []byte) (*protobufs.SignedX448Key, error) {
	panic("unimplemented")
}

// PutSignedDecaf448Key implements store.KeyStore.
func (m *memKeyStore) PutSignedDecaf448Key(txn store.Transaction, address []byte, key *protobufs.SignedDecaf448Key) error {
	panic("unimplemented")
}

// RangeSignedDecaf448Keys implements store.KeyStore.
func (m *memKeyStore) RangeSignedDecaf448Keys(parentKeyAddress []byte, keyPurpose string) (store.TypedIterator[*protobufs.SignedDecaf448Key], error) {
	panic("unimplemented")
}

// DeleteSignedKey implements store.KeyStore.
func (m *memKeyStore) DeleteSignedKey(txn store.Transaction, address []byte) error {
	panic("unimplemented")
}

// GetCrossSignatureByIdentityKey implements store.KeyStore.
func (m *memKeyStore) GetCrossSignatureByIdentityKey(identityKeyAddress []byte) ([]byte, error) {
	panic("unimplemented")
}

// GetCrossSignatureByProvingKey implements store.KeyStore.
func (m *memKeyStore) GetCrossSignatureByProvingKey(provingKeyAddress []byte) ([]byte, error) {
	panic("unimplemented")
}

// NewTransaction implements store.KeyStore.
func (m *memKeyStore) NewTransaction() (store.Transaction, error) {
	panic("unimplemented")
}

// ReapExpiredKeys implements store.KeyStore.
func (m *memKeyStore) ReapExpiredKeys() error {
	panic("unimplemented")
}

func newMemKeyStore() *memKeyStore {
	return &memKeyStore{signed: make(map[string][]*protobufs.SignedX448Key)}
}

func (m *memKeyStore) GetSignedX448KeysByParent(parentKeyAddress []byte, keyPurpose string) ([]*protobufs.SignedX448Key, error) {
	return m.signed[string(parentKeyAddress)], nil
}

// Stubs to satisfy store.KeyStore used by CachedSignerRegistry in this path.
func (m *memKeyStore) RangeProvingKeys() (store.TypedIterator[*protobufs.BLS48581SignatureWithProofOfPossession], error) {
	return nil, nil
}
func (m *memKeyStore) RangeIdentityKeys() (store.TypedIterator[*protobufs.Ed448PublicKey], error) {
	return nil, nil
}
func (m *memKeyStore) RangeSignedX448Keys([]byte, string) (store.TypedIterator[*protobufs.SignedX448Key], error) {
	return nil, nil
}
func (m *memKeyStore) GetIdentityKey([]byte) (*protobufs.Ed448PublicKey, error) { return nil, nil }
func (m *memKeyStore) GetProvingKey([]byte) (*protobufs.BLS48581SignatureWithProofOfPossession, error) {
	return nil, nil
}
func (m *memKeyStore) GetSignedKey([]byte) (*protobufs.SignedX448Key, error) { return nil, nil }

func (m *memKeyStore) GetKeyRegistry([]byte) (*protobufs.KeyRegistry, error)         { return nil, nil }
func (m *memKeyStore) GetKeyRegistryByProver([]byte) (*protobufs.KeyRegistry, error) { return nil, nil }
func (m *memKeyStore) PutIdentityKey(store.Transaction, []byte, *protobufs.Ed448PublicKey) error {
	return nil
}
func (m *memKeyStore) PutProvingKey(store.Transaction, []byte, *protobufs.BLS48581SignatureWithProofOfPossession) error {
	return nil
}
func (m *memKeyStore) PutCrossSignature(store.Transaction, []byte, []byte, []byte, []byte) error {
	return nil
}
func (m *memKeyStore) PutSignedX448Key(store.Transaction, []byte, *protobufs.SignedX448Key) error {
	return nil
}
func (m *memKeyStore) GetSignedX448KeysByParentAndPurpose([]byte, string) ([]*protobufs.SignedX448Key, error) {
	return nil, nil
}
func (m *memKeyStore) Begin() (store.Transaction, error) { return nil, nil }

// NOTE: keys.KeyManager / crypto.Agreement may expose more methods in your repo.
// If your compiler asks for them, add no-op stubs here.

type testKM struct {
	mu sync.Mutex
	ks map[string]*keys.X448Key
}

// Aggregate implements keys.KeyManager.
func (km *testKM) Aggregate(publicKeys [][]byte, signatures [][]byte) (crypto.BlsAggregateOutput, error) {
	panic("unimplemented")
}

// CreateSigningKey implements keys.KeyManager.
func (km *testKM) CreateSigningKey(id string, keyType crypto.KeyType) (key crypto.Signer, popk []byte, err error) {
	panic("unimplemented")
}

// DeleteKey implements keys.KeyManager.
func (km *testKM) DeleteKey(id string) error {
	panic("unimplemented")
}

// GetRawKey implements keys.KeyManager.
func (km *testKM) GetRawKey(id string) (*tkeys.Key, error) {
	panic("unimplemented")
}

// GetSigningKey implements keys.KeyManager.
func (km *testKM) GetSigningKey(id string) (crypto.Signer, error) {
	panic("unimplemented")
}

// ListKeys implements keys.KeyManager.
func (km *testKM) ListKeys() ([]*tkeys.Key, error) {
	panic("unimplemented")
}

// PutRawKey implements keys.KeyManager.
func (km *testKM) PutRawKey(key *tkeys.Key) error {
	panic("unimplemented")
}

// ValidateSignature implements keys.KeyManager.
func (km *testKM) ValidateSignature(keyType crypto.KeyType, publicKey []byte, message []byte, signature []byte, domain []byte) (bool, error) {
	panic("unimplemented")
}

var _ tkeys.KeyManager = (*testKM)(nil) // If this fails, add the missing methods.

func newTestKM() *testKM {
	return &testKM{ks: map[string]*keys.X448Key{}}
}

func (km *testKM) GetAgreementKey(name string) (crypto.Agreement, error) {
	km.mu.Lock()
	defer km.mu.Unlock()
	sk, ok := km.ks[name]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return sk, nil
}

func (km *testKM) CreateAgreementKey(name string, typ crypto.KeyType) (crypto.Agreement, error) {
	if typ != crypto.KeyTypeX448 {
		return nil, fmt.Errorf("unsupported type")
	}
	km.mu.Lock()
	defer km.mu.Unlock()
	k := keys.NewX448Key()
	km.ks[name] = k
	return k, nil
}

func TestOnionGRPC_RealRelayAndKeys(t *testing.T) {
	logger := zap.NewNop()

	// 1) Spin up a real gRPC health server (ephemeral port)
	lis, err := net.Listen("tcp", "127.0.0.1:8080")
	require.NoError(t, err)
	s := grpc.NewServer()
	hs := health.NewServer()
	// Set a long string to ensure payload size is larger than a cell > 512B
	hs.SetServingStatus(strings.Repeat("test", 256), healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(s, hs)
	go s.Serve(lis)
	defer s.Stop()

	// exit multiaddr for the relay
	targetMA, _ := multiaddr.StringCast(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", lis.Addr().(*net.TCPAddr).Port))

	// 2) Ordered mesh + per-peer transports
	m := newMesh()
	tClient := &meshPeerTransport{mesh: m, selfID: "client"}
	tR1 := &meshPeerTransport{mesh: m, selfID: "relay1"}
	tR2 := &meshPeerTransport{mesh: m, selfID: "relay2"}
	tR3 := &meshPeerTransport{mesh: m, selfID: "relay3"}

	// 3) Build signer registry that returns onion pubs for relays
	ks := newMemKeyStore()
	registry, err := registration.NewCachedSignerRegistry(
		ks,
		nil, // keys.KeyManager not needed by this path
		nil, // bls constructor not needed
		nil, // bulletproof prover not needed
		zap.NewNop(),
	)
	require.NoError(t, err)

	// 4) Create relays with real X448 agreement keys coming from a KeyManager
	km := newTestKM()

	for _, id := range []string{"relay1", "relay2", "relay3"} {
		_ = onion.NewRelay(
			logger,
			id,
			map[string]*meshPeerTransport{"relay1": tR1, "relay2": tR2, "relay3": tR3}[id],
			km, // real Agreement via KeyManager
			func() (ephemeralPub []byte, ephemeralPriv []byte, err error) {
				x := keys.NewX448Key()
				return x.Public(), x.Private(), nil
			}, // serverEph for transcript binding
			func(ephemeralPriv, peerOnionPub []byte) (sharedSecret []byte, err error) {
				k, _ := keys.X448KeyFromBytes(ephemeralPriv)
				return k.AgreeWith(peerOnionPub)
			},
			onion.WithPermissiveValidator(),
		)
	}

	// 5) Publish onion *public* keys for relays into signer registry (so client can resolve)
	for _, id := range []string{"relay1", "relay2", "relay3"} {
		// Grab the created agreement pub from the key manager
		_, err := km.GetAgreementKey("onion-routing-key")
		require.NoError(t, err)

		km.mu.Lock()
		pub := km.ks["onion-routing-key"]
		km.mu.Unlock()

		ks.signed[id] = []*protobufs.SignedX448Key{
			{Key: &protobufs.X448PublicKey{KeyValue: pub.Public()}, ParentKeyAddress: []byte(id)},
		}
	}

	// 6) PeerInfoManager ordering (entry->middle->exit)
	pm := p2p.NewInMemoryPeerInfoManager(logger)
	pm.Start()
	defer pm.Stop()
	pm.AddPeerInfo(&protobufs.PeerInfo{PeerId: []byte("relay1"), Capabilities: []*protobufs.Capability{{ProtocolIdentifier: onion.ProtocolRouting}}})
	pm.AddPeerInfo(&protobufs.PeerInfo{PeerId: []byte("relay2"), Capabilities: []*protobufs.Capability{{ProtocolIdentifier: onion.ProtocolRouting}}})
	pm.AddPeerInfo(&protobufs.PeerInfo{PeerId: []byte("relay3"), Capabilities: []*protobufs.Capability{{ProtocolIdentifier: onion.ProtocolRouting}}})

	// Let peer manager build
	time.Sleep(1 * time.Second)

	// 7) Build client OnionRouter with real X448 key construction
	or := onion.NewOnionRouter(
		logger,
		pm,
		registry,
		nil, // KeyManager unused by client OnionRouter path
		onion.WithTransport(tClient),
		onion.WithKeyConstructor(func() (ephemeralPub []byte, ephemeralPriv []byte, err error) {
			k := keys.NewX448Key()
			return k.Public(), k.Private(), nil
		}),
		onion.WithSharedSecret(func(ephemeralPriv, peerOnionPub []byte) (sharedSecret []byte, err error) {
			e, _ := keys.X448KeyFromBytes(ephemeralPriv)
			return e.AgreeWith(peerOnionPub)
		}),
	)

	// 8) Build a 3-hop circuit
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	circ, err := or.BuildCircuit(ctx, 3)
	require.NoError(t, err)

	// 9) gRPC dial through onion using MULTIADDR as "addr" (relay expects MA bytes in BEGIN)
	dialer := or.GRPCDialer(circ)
	conn, err := grpc.DialContext(
		ctx,
		targetMA.String(), // this string is carried to BEGIN (not dialed directly by gRPC)
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	require.NoError(t, err)
	defer conn.Close()

	// 10) Health check end-to-end
	hc := healthpb.NewHealthClient(conn)
	resp, err := hc.Check(ctx, &healthpb.HealthCheckRequest{Service: strings.Repeat("test", 256)})
	require.NoError(t, err)
	require.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.Status)
}

// End-to-end rendezvous splice test
func TestHiddenService_RemoteRendezvous(t *testing.T) {
	t.Parallel()
	logger := zap.NewNop()

	// Mesh & transports
	mesh := newMesh()
	tClient := &meshPeerTransport{mesh: mesh, selfID: "client"}
	tService := &meshPeerTransport{mesh: mesh, selfID: "service"}
	// three intro relays + three rendezvous relays
	tA1 := &meshPeerTransport{mesh: mesh, selfID: "relayA1"}
	tA2 := &meshPeerTransport{mesh: mesh, selfID: "relayA2"}
	tA3 := &meshPeerTransport{mesh: mesh, selfID: "relayA3"}
	tR1 := &meshPeerTransport{mesh: mesh, selfID: "relayR1"}
	tR2 := &meshPeerTransport{mesh: mesh, selfID: "relayR2"}
	tR3 := &meshPeerTransport{mesh: mesh, selfID: "relayR3"}

	// Signer registry backing
	ks := newMemKeyStore()
	reg, err := registration.NewCachedSignerRegistry(ks, nil, nil, nil, logger)
	require.NoError(t, err)

	// Relays
	km := newTestKM()
	newRelay := func(id string, tr *meshPeerTransport) *onion.Relay {
		return onion.NewRelay(
			logger, id, tr, km,
			func() ([]byte, []byte, error) { x := keys.NewX448Key(); return x.Public(), x.Private(), nil },
			func(priv, peerPub []byte) ([]byte, error) {
				k, _ := keys.X448KeyFromBytes(priv)
				return k.AgreeWith(peerPub)
			},
			onion.WithPermissiveValidator(),
		)
	}

	// spin up all 6 relays
	_ = newRelay("relayA1", tA1)
	_ = newRelay("relayA2", tA2)
	_ = newRelay("relayA3", tA3)
	_ = newRelay("relayR1", tR1)
	_ = newRelay("relayR2", tR2)
	_ = newRelay("relayR3", tR3)

	// Publish onion pubkey for both relays
	_, err = km.GetAgreementKey("onion-routing-key")
	require.NoError(t, err)

	km.mu.Lock()
	pub := km.ks["onion-routing-key"].Public()
	km.mu.Unlock()

	// publish the same onion pub to all relays (tests only)
	ks.signed["relayA1"] = []*protobufs.SignedX448Key{{Key: &protobufs.X448PublicKey{KeyValue: pub}, ParentKeyAddress: []byte("relayA1")}}
	ks.signed["relayA2"] = []*protobufs.SignedX448Key{{Key: &protobufs.X448PublicKey{KeyValue: pub}, ParentKeyAddress: []byte("relayA2")}}
	ks.signed["relayA3"] = []*protobufs.SignedX448Key{{Key: &protobufs.X448PublicKey{KeyValue: pub}, ParentKeyAddress: []byte("relayA3")}}
	ks.signed["relayR1"] = []*protobufs.SignedX448Key{{Key: &protobufs.X448PublicKey{KeyValue: pub}, ParentKeyAddress: []byte("relayR1")}}
	ks.signed["relayR2"] = []*protobufs.SignedX448Key{{Key: &protobufs.X448PublicKey{KeyValue: pub}, ParentKeyAddress: []byte("relayR2")}}
	ks.signed["relayR3"] = []*protobufs.SignedX448Key{{Key: &protobufs.X448PublicKey{KeyValue: pub}, ParentKeyAddress: []byte("relayR3")}}

	// Peer managers (client knows R, service knows A then R)
	pmClient := p2p.NewInMemoryPeerInfoManager(logger)
	pmClient.Start()
	defer pmClient.Stop()
	// client knows three rendezvous relays
	for _, id := range [][]byte{[]byte("relayR1"), []byte("relayR2"), []byte("relayR3")} {
		pmClient.AddPeerInfo(&protobufs.PeerInfo{PeerId: id, Capabilities: []*protobufs.Capability{{ProtocolIdentifier: onion.ProtocolRouting}}})
	}
	pmService := p2p.NewInMemoryPeerInfoManager(logger)
	pmService.Start()
	defer pmService.Stop()
	// service knows three intro relays
	for _, id := range [][]byte{[]byte("relayA1"), []byte("relayA2"), []byte("relayA3")} {
		pmService.AddPeerInfo(&protobufs.PeerInfo{PeerId: id, Capabilities: []*protobufs.Capability{{ProtocolIdentifier: onion.ProtocolRouting}}})
	}

	time.Sleep(150 * time.Millisecond)

	// OnionRouters
	orClient := onion.NewOnionRouter(
		logger, pmClient, reg, nil,
		onion.WithTransport(tClient),
		onion.WithKeyConstructor(func() ([]byte, []byte, error) { k := keys.NewX448Key(); return k.Public(), k.Private(), nil }),
		onion.WithSharedSecret(func(priv, pub []byte) ([]byte, error) { e, _ := keys.X448KeyFromBytes(priv); return e.AgreeWith(pub) }),
	)
	orService := onion.NewOnionRouter(
		logger, pmService, reg, nil,
		onion.WithTransport(tService),
		onion.WithKeyConstructor(func() ([]byte, []byte, error) { k := keys.NewX448Key(); return k.Public(), k.Private(), nil }),
		onion.WithSharedSecret(func(priv, pub []byte) ([]byte, error) { e, _ := keys.X448KeyFromBytes(priv); return e.AgreeWith(pub) }),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	var serviceID [32]byte
	copy(serviceID[:], []byte("service-id-32-bytes-------------")[:32])

	_, err = orService.RegisterIntro(ctx, []byte("relayA1"), serviceID)
	require.NoError(t, err)

	// CLIENT: build circuit to rendezvous relay and send REND1
	cR, err := orClient.BuildCircuitToExit(ctx, 3, []byte("relayR1"))
	require.NoError(t, err)
	var cookie [16]byte
	_, _ = rand.Read(cookie[:])
	clientSid := uint16(0xC123)
	require.NoError(t, orClient.ClientStartRendezvous(cR, cookie, clientSid))

	// CLIENT: build circuit to intro relay and send INTRODUCE(serviceID, "relayR", cookie, clientSid)
	pmIntro := p2p.NewInMemoryPeerInfoManager(logger)
	pmIntro.Start()
	defer pmIntro.Stop()
	pmIntro.AddPeerInfo(&protobufs.PeerInfo{PeerId: []byte("relayA1"), Capabilities: []*protobufs.Capability{{ProtocolIdentifier: onion.ProtocolRouting}}})
	pmIntro.AddPeerInfo(&protobufs.PeerInfo{PeerId: []byte("relayA2"), Capabilities: []*protobufs.Capability{{ProtocolIdentifier: onion.ProtocolRouting}}})
	pmIntro.AddPeerInfo(&protobufs.PeerInfo{PeerId: []byte("relayA3"), Capabilities: []*protobufs.Capability{{ProtocolIdentifier: onion.ProtocolRouting}}})
	time.Sleep(150 * time.Millisecond)
	orIntro := onion.NewOnionRouter(logger, pmIntro, reg, nil,
		onion.WithTransport(tClient),
		onion.WithKeyConstructor(func() ([]byte, []byte, error) { k := keys.NewX448Key(); return k.Public(), k.Private(), nil }),
		onion.WithSharedSecret(func(priv, pub []byte) ([]byte, error) { e, _ := keys.X448KeyFromBytes(priv); return e.AgreeWith(pub) }),
	)

	cI, err := orIntro.BuildCircuit(ctx, 3)
	require.NoError(t, err)
	require.NoError(t, orClient.ClientIntroduce(cI, serviceID, "relayR1", cookie, clientSid))

	// SERVICE: now it also knows relayR; build circuit and send REND2
	pmService.AddPeerInfo(&protobufs.PeerInfo{PeerId: []byte("relayR1"), Capabilities: []*protobufs.Capability{{ProtocolIdentifier: onion.ProtocolRouting}}})
	pmService.AddPeerInfo(&protobufs.PeerInfo{PeerId: []byte("relayR2"), Capabilities: []*protobufs.Capability{{ProtocolIdentifier: onion.ProtocolRouting}}})
	pmService.AddPeerInfo(&protobufs.PeerInfo{PeerId: []byte("relayR3"), Capabilities: []*protobufs.Capability{{ProtocolIdentifier: onion.ProtocolRouting}}})
	time.Sleep(150 * time.Millisecond)
	cRS, err := orService.BuildCircuitToExit(ctx, 3, []byte("relayR1"))
	require.NoError(t, err)
	serviceSid := uint16(0xD777)
	require.NoError(t, orService.ServiceCompleteRendezvous(cRS, cookie, serviceSid))

	// Open stream conns on both ends using exported helper
	clientConn := orClient.OpenStreamConn(cR, clientSid)
	defer clientConn.Close()
	serviceConn := orService.OpenStreamConn(cRS, serviceSid)
	defer serviceConn.Close()

	// Write client->service and expect the same bytes
	msg := []byte("hello over rendezvous (public api)")
	_, err = clientConn.Write(msg)
	require.NoError(t, err)
	bufLen := make([]byte, 2)

	// reads may arrive in chunks; read exact len
	got := make([]byte, 0, len(msg))
	tmp := make([]byte, 64)
	dead := time.After(2 * time.Second)

readLoop:
	for len(got) < len(msg) {
		select {
		case <-dead:
			t.Fatalf("timeout waiting for msg, got %q", string(got))
		default:
			n, rerr := serviceConn.Read(tmp)
			if n > 0 {
				got = append(got, tmp[:n]...)
			}
			if rerr != nil && len(got) >= len(msg) {
				break readLoop
			}
		}
	}

	require.Equal(t, msg, got)

	// Also test END propagation by closing client half and expecting EOF at service
	_ = clientConn.Close()
	time.Sleep(100 * time.Millisecond)
	n, rerr := serviceConn.Read(bufLen)
	_ = n
	require.Error(t, rerr) // should eventually be io.EOF
}
