//go:build livetarget
// +build livetarget

package global_test

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	libp2p "github.com/libp2p/go-libp2p"

	"source.quilibrium.com/quilibrium/monorepo/config"
	bspb "source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

const (
	targetIP      = "162.120.18.10"
	targetP2PPort = "8336"
)

// discoverPeerID creates a throwaway libp2p host, dials the target
// multiaddr, and returns the peer ID learned from the security handshake.
func discoverPeerID(t *testing.T, privKey pcrypto.PrivKey) peer.ID {
	t.Helper()

	targetMA, err := ma.NewMultiaddr(fmt.Sprintf(
		"/ip4/%s/udp/%s/quic-v1", targetIP, targetP2PPort,
	))
	require.NoError(t, err)

	h, err := libp2p.New(
		libp2p.Identity(privKey),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/udp/0/quic-v1"),
		libp2p.DisableRelay(),
	)
	require.NoError(t, err)
	defer h.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Peerstore.AddAddr + Connect won't work without a peer ID.
	// Use the Network().DialPeer path via NewStream which discovers
	// the peer ID during the security handshake.
	// Instead, iterate connected peers after a raw dial.

	// libp2p's swarm can dial a multiaddr and discover the peer ID
	// from the handshake. Use the swarm directly.
	peerInfo, err := peer.AddrInfosFromP2pAddrs(targetMA)
	if err != nil || len(peerInfo) == 0 {
		// Multiaddr has no peer ID embedded — we need to discover it.
		// Connect to the address and look at who we connected to.
		//
		// libp2p doesn't support dialing without a peer ID in the
		// standard API. But we can use the network swarm's Listen
		// + manual connect pattern by trying all peers we discover.
		//
		// Alternative: use a simple QUIC dial to extract the peer
		// certificate, similar to the TLS approach but for QUIC/Noise.
		//
		// Simplest: just try each bootstrap peer from mainnet config
		// and see if any of them resolve to this IP, OR require the
		// user to provide the peer ID.
		t.Fatal("Cannot discover peer ID from bare multiaddr without embedded /p2p/ component. " +
			"Please set TARGET_PEER_ID env var or provide the full multiaddr.")
	}

	err = h.Connect(ctx, peerInfo[0])
	require.NoError(t, err, "failed to connect to target")

	return peerInfo[0].ID
}

// TestLivePeerInfoSubscription connects to the target node over libp2p
// QUIC, subscribes to the GLOBAL_PEER_INFO_BITMASK blossomsub topic,
// and waits for PeerInfo messages.
//
// The target's peer ID must be provided via TARGET_PEER_ID env var,
// or embedded in the multiaddr. Discover it by checking the node's
// logs or running `node prover status` against it.
//
// Run:
//
//	TARGET_PEER_ID=QmXXX go test -tags livetarget \
//	  -run TestLivePeerInfoSubscription -v -timeout 120s ./consensus/global/
func TestLivePeerInfoSubscription(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Step 1: Get the target's peer ID.
	targetPeerIDStr := os.Getenv("TARGET_PEER_ID")
	if targetPeerIDStr == "" {
		t.Skip("TARGET_PEER_ID not set — provide the target node's peer ID")
	}

	targetPeerID, err := peer.Decode(targetPeerIDStr)
	require.NoError(t, err, "invalid TARGET_PEER_ID")

	targetMultiaddr := fmt.Sprintf(
		"/ip4/%s/udp/%s/quic-v1/p2p/%s",
		targetIP, targetP2PPort, targetPeerID.String(),
	)
	t.Logf("Target: %s", targetMultiaddr)

	// Step 2: Generate ephemeral key and create a BlossomSub host
	// that bootstraps only through the target.
	priv, _, err := pcrypto.GenerateEd448Key(rand.Reader)
	require.NoError(t, err)
	privBytes, err := priv.Raw()
	require.NoError(t, err)

	engCfg := (&config.EngineConfig{}).WithDefaults()
	configDir := t.TempDir()

	// Pre-seed the connectivity cache so blockUntilConnectivityTest
	// returns immediately instead of running the reachability probe.
	require.NoError(t, os.WriteFile(
		fmt.Sprintf("%s/connectivity-check-0", configDir),
		[]byte("ok"), 0644,
	))

	p2pCfg := (&config.P2PConfig{
		PeerPrivKey:     hex.EncodeToString(privBytes),
		Network:         0,
		BootstrapPeers:  []string{targetMultiaddr},
		ListenMultiaddr: "/ip4/0.0.0.0/udp/0/quic-v1",
	}).WithDefaults()
	p2pCfg.MinBootstrapPeers = 1

	bs := p2p.NewBlossomSub(
		&p2pCfg, &engCfg, logger, 0,
		p2p.ConfigDir(configDir),
	)

	ourPeerID := peer.ID(bs.GetPeerID())
	t.Logf("Our Peer ID: %s", ourPeerID.String())

	// Step 3: Subscribe to GLOBAL_PEER_INFO_BITMASK = {0x00, 0x00, 0x00, 0x00}
	peerInfoBitmask := []byte{0x00, 0x00, 0x00, 0x00}
	msgCh := make(chan []byte, 100)

	err = bs.Subscribe(
		peerInfoBitmask,
		func(msg *bspb.Message) error {
			data := make([]byte, len(msg.Data))
			copy(data, msg.Data)
			select {
			case msgCh <- data:
			default:
			}
			return nil
		},
	)
	require.NoError(t, err, "subscribe to peer info bitmask")
	t.Log("Subscribed to GLOBAL_PEER_INFO_BITMASK {0x00, 0x00, 0x00, 0x00}")

	// Step 4: Wait for the target node's PeerInfo message specifically.
	// Peer info is published every ~5 minutes, so wait up to 10 minutes.
	t.Logf("Waiting for PeerInfo from %s (up to 30m)...", targetPeerID.String())
	msgCount := 0
	timeout := time.After(30 * time.Minute)

	for {
		select {
		case data := <-msgCh:
			msgCount++

			if len(data) < 4 {
				continue
			}
			tp := binary.BigEndian.Uint32(data[:4])
			if tp != protobufs.PeerInfoType {
				t.Logf("  msg %d: non-PeerInfo type 0x%08x, skipping", msgCount, tp)
				continue
			}

			peerInfo := &protobufs.PeerInfo{}
			if err := peerInfo.FromCanonicalBytes(data); err != nil {
				t.Logf("  msg %d: failed to decode PeerInfo: %v", msgCount, err)
				continue
			}

			msgPeerID, err := peer.IDFromBytes(peerInfo.GetPeerId())
			if err != nil {
				t.Logf("  msg %d: invalid peer ID in PeerInfo: %v", msgCount, err)
				continue
			}

			t.Logf("  msg %d: PeerInfo from %s (head=%d, received=%d, reachability=%d entries)",
				msgCount,
				msgPeerID.String(),
				peerInfo.GetLastGlobalHeadFrame(),
				peerInfo.GetLastReceivedFrame(),
				len(peerInfo.GetReachability()),
			)

			if msgPeerID == targetPeerID {
				t.Logf("FOUND target node's PeerInfo!")
				t.Logf("  Peer ID:            %s", msgPeerID.String())
				t.Logf("  Last Global Head:   %d", peerInfo.GetLastGlobalHeadFrame())
				t.Logf("  Last Received:      %d", peerInfo.GetLastReceivedFrame())
				t.Logf("  Version:            %x", peerInfo.GetVersion())
				t.Logf("  Capabilities:       %d", len(peerInfo.GetCapabilities()))
				for i, r := range peerInfo.GetReachability() {
					t.Logf("  Reachability[%d]:", i)
					t.Logf("    Filter:    %x", r.GetFilter())
					t.Logf("    Pubsub:    %v", r.GetPubsubMultiaddrs())
					t.Logf("    Stream:    %v", r.GetStreamMultiaddrs())
				}
				return
			}

		case <-timeout:
			t.Fatalf("DIAGNOSTIC FAILURE: received %d PeerInfo messages in 30 minutes "+
				"but none from target %s — the node is not publishing its peer info",
				msgCount, targetPeerID.String())
		}
	}
}
