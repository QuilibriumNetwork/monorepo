//go:build clientdebug
// +build clientdebug

package datarpc_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
)

// This file is strictly a test client to diagnose connectivity issues. It is
// not intended for normal test purposes.

func TestConnect(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	config, err := config.LoadConfig("../.config1", "", true)
	if err != nil {
		panic(err)
	}

	logger.Info("reconnecting to worker", zap.Uint("core_id", 1))
	addr, err := multiaddr.StringCast("/ip4/127.0.0.1/tcp/61000")
	if err != nil {
		panic(err)
	}

	mga, err := mn.ToNetAddr(addr)
	if err != nil {
		panic(err)
	}

	peerPrivKey, err := hex.DecodeString(config.P2P.PeerPrivKey)
	if err != nil {
		logger.Error("error unmarshaling peerkey", zap.Error(err))
		panic(err)
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		logger.Error("error unmarshaling peerkey", zap.Error(err))
		panic(err)
	}

	pub := privKey.GetPublic()
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		logger.Error("error unmarshaling peerkey", zap.Error(err))
		panic(err)
	}

	creds, err := p2p.NewPeerAuthenticator(
		logger,
		config.P2P,
		nil,
		nil,
		nil,
		nil,
		[][]byte{[]byte(id)},
		map[string]channel.AllowedPeerPolicyType{
			"quilibrium.node.node.pb.DataIPCService": channel.OnlySelfPeer,
		},
		map[string]channel.AllowedPeerPolicyType{},
	).CreateClientTLSCredentials([]byte(id))
	if err != nil {
		panic(err)
	}

	grpcClient, err := grpc.NewClient(
		mga.String(),
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		panic(err)
	}

	cclient := protobufs.NewDataIPCServiceClient(grpcClient)
	proof, err := cclient.CreateJoinProof(context.TODO(), &protobufs.CreateJoinProofRequest{
		Challenge:   make([]byte, 32),
		Difficulty:  160000,
		Ids:         [][]byte{{0}},
		ProverIndex: 0,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x\n", proof.Response)
	t.FailNow()
}
