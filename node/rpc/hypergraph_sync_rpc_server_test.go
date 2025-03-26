package rpc_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"log"
	"math/big"
	"net"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/hypergraph/application"
	internal_grpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/rpc"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

type serverStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *serverStream) Context() context.Context {
	return s.ctx
}

type Operation struct {
	Type      string // "AddVertex", "RemoveVertex", "AddHyperedge", "RemoveHyperedge"
	Vertex    application.Vertex
	Hyperedge application.Hyperedge
}

func TestLoadHypergraphFallback(t *testing.T) {
	clientKvdb := store.NewInMemKVDB()
	serverKvdb := store.NewInMemKVDB()
	logger, _ := zap.NewProduction()
	clientHypergraphStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{Path: ".configtestclient/store"},
		clientKvdb,
		logger,
	)
	serverHypergraphStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{Path: ".configtestserver/store"},
		serverKvdb,
		logger,
	)

	serverLoad, err := serverHypergraphStore.LoadHypergraph()
	assert.NoError(t, err)
	clientLoad, err := clientHypergraphStore.LoadHypergraph()
	assert.NoError(t, err)
	fmt.Printf("%x\n", serverLoad.Commit()[0])
	for k, a := range serverLoad.GetVertexAdds() {
		assert.Equal(t, len(crypto.ConvertAllPreloadedLeaves(string(application.VertexAtomType), string(application.AddsPhaseType), k, serverHypergraphStore, a.GetTree().Root, []int{})), 100000)
	}
	for k, a := range clientLoad.GetVertexAdds() {
		assert.Equal(t, len(crypto.ConvertAllPreloadedLeaves(string(application.VertexAtomType), string(application.AddsPhaseType), k, clientHypergraphStore, a.GetTree().Root, []int{})), 100000)
		fmt.Printf("%x\n", a.GetTree().Commit(true))
	}

	fmt.Println("Should not reattempt")

	serverLoad, err = serverHypergraphStore.LoadHypergraph()
	assert.NoError(t, err)
	clientLoad, err = clientHypergraphStore.LoadHypergraph()
	assert.NoError(t, err)
	t.FailNow()
}

func TestHypergraphSyncServer(t *testing.T) {
	numParties := 3
	numOperations := 1000
	log.Printf("Generating data")
	enc := crypto.NewMPCitHVerifiableEncryptor(1)
	pub, _, _ := ed448.GenerateKey(rand.Reader)
	data := enc.Encrypt(make([]byte, 20), pub)
	verenc := data[0].Compress()
	vertices := make([]application.Vertex, numOperations)
	dataTree := &crypto.VectorCommitmentTree{}
	for _, d := range []application.Encrypted{verenc} {
		dataBytes := d.ToBytes()
		id := sha512.Sum512(dataBytes)
		dataTree.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data)*54)))
	}
	dataTree.Commit(false)
	for i := 0; i < numOperations; i++ {
		b := make([]byte, 32)
		rand.Read(b)
		vertices[i] = application.NewVertex(
			[32]byte{},
			[32]byte(b),
			dataTree.Commit(false),
			dataTree.GetSize(),
		)
	}

	hyperedges := make([]application.Hyperedge, numOperations/10)
	for i := 0; i < numOperations/10; i++ {
		hyperedges[i] = application.NewHyperedge(
			[32]byte{},
			[32]byte{0, 0, byte((i >> 8) / 256), byte(i / 256)},
		)
		for j := 0; j < 3; j++ {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(vertices))))
			v := vertices[n.Int64()]
			hyperedges[i].AddExtrinsic(v)
		}
	}

	shardKey := application.GetShardKey(vertices[0])

	operations1 := make([]Operation, numOperations)
	operations2 := make([]Operation, numOperations)
	for i := 0; i < numOperations; i++ {
		operations1[i] = Operation{Type: "AddVertex", Vertex: vertices[i]}
	}
	for i := 0; i < numOperations; i++ {
		op, _ := rand.Int(rand.Reader, big.NewInt(2))
		switch op.Int64() {
		case 0:
			e, _ := rand.Int(rand.Reader, big.NewInt(int64(len(hyperedges))))
			operations2[i] = Operation{Type: "AddHyperedge", Hyperedge: hyperedges[e.Int64()]}
		case 1:
			e, _ := rand.Int(rand.Reader, big.NewInt(int64(len(hyperedges))))
			operations2[i] = Operation{Type: "RemoveHyperedge", Hyperedge: hyperedges[e.Int64()]}
		}
	}

	clientKvdb := store.NewInMemKVDB()
	serverKvdb := store.NewInMemKVDB()
	controlKvdb := store.NewInMemKVDB()
	logger, _ := zap.NewProduction()
	clientHypergraphStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{Path: ".configtestclient/store"},
		clientKvdb,
		logger,
	)
	serverHypergraphStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{Path: ".configtestserver/store"},
		serverKvdb,
		logger,
	)
	controlHypergraphStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{Path: ".configtestcontrol/store"},
		controlKvdb,
		logger,
	)
	crdts := make([]*application.Hypergraph, numParties)
	crdts[0] = application.NewHypergraph(serverHypergraphStore)
	crdts[1] = application.NewHypergraph(clientHypergraphStore)
	crdts[2] = application.NewHypergraph(controlHypergraphStore)

	txn, _ := serverHypergraphStore.NewTransaction(false)
	for _, op := range operations1[:numOperations/2] {
		switch op.Type {
		case "AddVertex":
			id := op.Vertex.GetID()
			serverHypergraphStore.SaveVertexTree(txn, id[:], dataTree)
			crdts[0].AddVertex(nil, op.Vertex)
		case "RemoveVertex":
			crdts[0].RemoveVertex(nil, op.Vertex)
			// case "AddHyperedge":
			// 	fmt.Printf("server add hyperedge %v\n", time.Now())
			// 	crdts[0].AddHyperedge(nil, op.Hyperedge)
			// case "RemoveHyperedge":
			// 	fmt.Printf("server remove hyperedge %v\n", time.Now())
			// 	crdts[0].RemoveHyperedge(nil, op.Hyperedge)
		}
	}
	txn.Commit()
	for _, op := range operations2[:50] {
		switch op.Type {
		case "AddVertex":
			crdts[0].AddVertex(nil, op.Vertex)
		case "RemoveVertex":
			crdts[0].RemoveVertex(nil, op.Vertex)
			// case "AddHyperedge":
			// 	fmt.Printf("server add hyperedge %v\n", time.Now())
			// 	crdts[0].AddHyperedge(nil, op.Hyperedge)
			// case "RemoveHyperedge":
			// 	fmt.Printf("server remove hyperedge %v\n", time.Now())
			// 	crdts[0].RemoveHyperedge(nil, op.Hyperedge)
		}
	}

	txn, _ = clientHypergraphStore.NewTransaction(false)
	for _, op := range operations1[numOperations/2:] {
		switch op.Type {
		case "AddVertex":
			id := op.Vertex.GetID()
			clientHypergraphStore.SaveVertexTree(txn, id[:], dataTree)
			crdts[1].AddVertex(nil, op.Vertex)
		case "RemoveVertex":
			crdts[1].RemoveVertex(nil, op.Vertex)
			// case "AddHyperedge":
			// 	fmt.Printf("client add hyperedge %v\n", time.Now())
			// 	crdts[1].AddHyperedge(nil, op.Hyperedge)
			// case "RemoveHyperedge":
			// 	fmt.Printf("client remove hyperedge %v\n", time.Now())
			// 	crdts[1].RemoveHyperedge(nil, op.Hyperedge)
		}
	}
	txn.Commit()
	for _, op := range operations2[50:] {
		switch op.Type {
		case "AddVertex":
			crdts[1].AddVertex(nil, op.Vertex)
		case "RemoveVertex":
			crdts[1].RemoveVertex(nil, op.Vertex)
			// case "AddHyperedge":
			// 	fmt.Printf("client add hyperedge %v\n", time.Now())
			// 	crdts[1].AddHyperedge(nil, op.Hyperedge)
			// case "RemoveHyperedge":
			// 	fmt.Printf("client remove hyperedge %v\n", time.Now())
			// 	crdts[1].RemoveHyperedge(nil, op.Hyperedge)
		}
	}

	for _, op := range operations1 {
		switch op.Type {
		case "AddVertex":
			crdts[2].AddVertex(nil, op.Vertex)
		case "RemoveVertex":
			crdts[2].RemoveVertex(nil, op.Vertex)
			// case "AddHyperedge":
			// 	crdts[2].AddHyperedge(nil, op.Hyperedge)
			// case "RemoveHyperedge":
			// 	crdts[2].RemoveHyperedge(nil, op.Hyperedge)
		}
	}
	for _, op := range operations2 {
		switch op.Type {
		case "AddVertex":
			crdts[2].AddVertex(nil, op.Vertex)
		case "RemoveVertex":
			crdts[2].RemoveVertex(nil, op.Vertex)
			// case "AddHyperedge":
			// 	crdts[2].AddHyperedge(nil, op.Hyperedge)
			// case "RemoveHyperedge":
			// 	crdts[2].RemoveHyperedge(nil, op.Hyperedge)
		}
	}

	crdts[0].Commit()
	crdts[1].Commit()
	// crdts[2].Commit()
	// err := serverHypergraphStore.SaveHypergraph(crdts[0])
	// assert.NoError(t, err)
	// err = clientHypergraphStore.SaveHypergraph(crdts[1])
	// assert.NoError(t, err)
	serverHypergraphStore.MarkHypergraphAsComplete()
	clientHypergraphStore.MarkHypergraphAsComplete()
	serverLoad, err := serverHypergraphStore.LoadHypergraph()
	assert.NoError(t, err)
	clientLoad, err := clientHypergraphStore.LoadHypergraph()
	assert.NoError(t, err)
	fmt.Printf("%x\n", crdts[0].Commit()[0])
	fmt.Printf("%x\n", serverLoad.Commit()[0])
	assert.Len(t, crypto.CompareLeaves(
		crdts[0].GetVertexAdds()[shardKey].GetTree(),
		serverLoad.GetVertexAdds()[shardKey].GetTree(),
	), 0)
	assert.Len(t, crypto.CompareLeaves(
		crdts[1].GetVertexAdds()[shardKey].GetTree(),
		clientLoad.GetVertexAdds()[shardKey].GetTree(),
	), 0)
	crypto.DebugNode(string(application.VertexAtomType), string(application.AddsPhaseType), shardKey, serverLoad.GetVertexAdds()[shardKey].GetTree().Root, 0, "")
	log.Printf("Generated data")

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Server: failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer(
		grpc.ChainStreamInterceptor(func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
			_, priv, _ := ed448.GenerateKey(rand.Reader)
			privKey, err := pcrypto.UnmarshalEd448PrivateKey(priv)
			if err != nil {
				t.FailNow()
			}

			pub := privKey.GetPublic()
			peerId, err := peer.IDFromPublicKey(pub)
			if err != nil {
				t.FailNow()
			}

			return handler(srv, &serverStream{
				ServerStream: ss,
				ctx: internal_grpc.NewContextWithPeerID(
					ss.Context(),
					peerId,
				),
			})
		}),
	)
	protobufs.RegisterHypergraphComparisonServiceServer(
		grpcServer,
		rpc.NewHypergraphComparisonServer(logger, serverHypergraphStore, crdts[0], rpc.NewSyncController(), numOperations, false),
	)
	log.Println("Server listening on :50051")
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Server: failed to serve: %v", err)
		}
	}()

	conn, err := grpc.DialContext(context.TODO(), "localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Client: failed to listen: %v", err)
	}
	client := protobufs.NewHypergraphComparisonServiceClient(conn)
	str, err := client.HyperStream(context.TODO())
	if err != nil {
		log.Fatalf("Client: failed to stream: %v", err)
	}

	syncController := rpc.NewSyncController()

	err = rpc.SyncTreeBidirectionally(str, logger, append(append([]byte{}, shardKey.L1[:]...), shardKey.L2[:]...), protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS, clientHypergraphStore, crdts[1], crdts[1].GetVertexAdds()[shardKey], syncController, numOperations, false)
	if err != nil {
		log.Fatalf("Client: failed to sync 1: %v", err)
	}

	leaves := crypto.CompareLeaves(
		crdts[0].GetVertexAdds()[shardKey].GetTree(),
		crdts[1].GetVertexAdds()[shardKey].GetTree(),
	)
	fmt.Println("pass completed, orphans:", len(leaves))

	crdts[0].GetVertexAdds()[shardKey].GetTree().Commit(false)
	crdts[1].GetVertexAdds()[shardKey].GetTree().Commit(false)

	str, err = client.HyperStream(context.TODO())
	if err != nil {
		log.Fatalf("Client: failed to stream: %v", err)
	}

	err = rpc.SyncTreeBidirectionally(str, logger, append(append([]byte{}, shardKey.L1[:]...), shardKey.L2[:]...), protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS, clientHypergraphStore, crdts[1], crdts[1].GetVertexAdds()[shardKey], syncController, numOperations, false)
	if err != nil {
		log.Fatalf("Client: failed to sync 2: %v", err)
	}

	if !bytes.Equal(
		crdts[0].GetVertexAdds()[shardKey].GetTree().Commit(false),
		crdts[1].GetVertexAdds()[shardKey].GetTree().Commit(false),
	) {
		leaves := crypto.CompareLeaves(
			crdts[0].GetVertexAdds()[shardKey].GetTree(),
			crdts[1].GetVertexAdds()[shardKey].GetTree(),
		)
		fmt.Println(len(leaves))
		log.Fatalf(
			"trees mismatch: %v %v",
			crdts[0].GetVertexAdds()[shardKey].GetTree().Commit(false),
			crdts[1].GetVertexAdds()[shardKey].GetTree().Commit(false),
		)
	}

	if !bytes.Equal(
		crdts[0].GetVertexAdds()[shardKey].GetTree().Commit(false),
		crdts[2].GetVertexAdds()[shardKey].GetTree().Commit(false),
	) {
		log.Fatalf(
			"trees did not converge to correct state: %v %v",
			crdts[0].GetVertexAdds()[shardKey].GetTree().Commit(false),
			crdts[2].GetVertexAdds()[shardKey].GetTree().Commit(false),
		)
	}
	t.FailNow()
}
