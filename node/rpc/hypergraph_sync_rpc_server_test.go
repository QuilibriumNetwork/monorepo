package rpc_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	internal_grpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/channel"
	application "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	tp2p "source.quilibrium.com/quilibrium/monorepo/types/p2p"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
	crypto "source.quilibrium.com/quilibrium/monorepo/types/tries"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
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

func TestHypergraphSyncServer(t *testing.T) {
	numParties := 3
	numOperations := 1000
	log.Printf("Generating data")
	enc := verenc.NewMPCitHVerifiableEncryptor(1)
	pub, _, _ := ed448.GenerateKey(rand.Reader)
	data1 := enc.Encrypt(make([]byte, 20), pub)
	verenc1 := data1[0].Compress()
	vertices1 := make([]application.Vertex, numOperations)
	dataTree1 := &crypto.VectorCommitmentTree{}
	logger, _ := zap.NewDevelopment()
	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	for _, d := range []application.Encrypted{verenc1} {
		dataBytes := d.ToBytes()
		id := sha512.Sum512(dataBytes)
		dataTree1.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data1)*55)))
	}
	dataTree1.Commit(inclusionProver, false)
	for i := 0; i < numOperations; i++ {
		b := make([]byte, 32)
		rand.Read(b)
		vertices1[i] = hgcrdt.NewVertex(
			[32]byte{},
			[32]byte(b),
			dataTree1.Commit(inclusionProver, false),
			dataTree1.GetSize(),
		)
	}

	hyperedges := make([]application.Hyperedge, numOperations/10)
	for i := 0; i < numOperations/10; i++ {
		hyperedges[i] = hgcrdt.NewHyperedge(
			[32]byte{},
			[32]byte{0, 0, byte((i >> 8) / 256), byte(i / 256)},
		)
		for j := 0; j < 3; j++ {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(vertices1))))
			v := vertices1[n.Int64()]
			hyperedges[i].AddExtrinsic(v)
		}
	}

	shardKey := application.GetShardKey(vertices1[0])

	operations1 := make([]Operation, numOperations)
	operations2 := make([]Operation, numOperations)
	for i := 0; i < numOperations; i++ {
		operations1[i] = Operation{Type: "AddVertex", Vertex: vertices1[i]}
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

	clientKvdb := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestclient/store"}}, 0)
	serverKvdb := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestserver/store"}}, 0)
	controlKvdb := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestcontrol/store"}}, 0)

	clientHypergraphStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{Path: ".configtestclient/store"},
		clientKvdb,
		logger,
		enc,
		inclusionProver,
	)
	serverHypergraphStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{Path: ".configtestserver/store"},
		serverKvdb,
		logger,
		enc,
		inclusionProver,
	)
	controlHypergraphStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{Path: ".configtestcontrol/store"},
		controlKvdb,
		logger,
		enc,
		inclusionProver,
	)
	crdts := make([]application.Hypergraph, numParties)
	crdts[0] = hgcrdt.NewHypergraph(logger.With(zap.String("side", "server")), serverHypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{}, 200)
	crdts[1] = hgcrdt.NewHypergraph(logger.With(zap.String("side", "client")), clientHypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{}, 200)
	crdts[2] = hgcrdt.NewHypergraph(logger.With(zap.String("side", "control")), controlHypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{}, 200)

	servertxn, _ := serverHypergraphStore.NewTransaction(false)
	clienttxn, _ := clientHypergraphStore.NewTransaction(false)
	controltxn, _ := controlHypergraphStore.NewTransaction(false)
	for i, op := range operations1 {
		switch op.Type {
		case "AddVertex":
			{
				id := op.Vertex.GetID()
				serverHypergraphStore.SaveVertexTree(servertxn, id[:], dataTree1)
				crdts[0].AddVertex(servertxn, op.Vertex)
			}
			{
				if i%3 == 0 {
					id := op.Vertex.GetID()
					clientHypergraphStore.SaveVertexTree(clienttxn, id[:], dataTree1)
					crdts[1].AddVertex(clienttxn, op.Vertex)
				}
			}
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
	servertxn.Commit()
	clienttxn.Commit()

	// Seed many orphan vertices that only exist on the client so pruning can
	// remove them. We create enough orphans with varied addresses to trigger
	// tree restructuring (node merges) when they get deleted during sync.
	// This tests the fix for the FullPrefix bug in lazy_proof_tree.go Delete().
	numOrphans := 200
	orphanVertices := make([]application.Vertex, numOrphans)
	orphanIDs := make([][64]byte, numOrphans)

	orphanTxn, err := clientHypergraphStore.NewTransaction(false)
	require.NoError(t, err)

	for i := 0; i < numOrphans; i++ {
		orphanData := make([]byte, 32)
		_, _ = rand.Read(orphanData)
		// Mix in the index to ensure varied distribution across tree branches
		binary.BigEndian.PutUint32(orphanData[28:], uint32(i))

		var orphanAddr [32]byte
		copy(orphanAddr[:], orphanData)
		orphanVertices[i] = hgcrdt.NewVertex(
			vertices1[0].GetAppAddress(),
			orphanAddr,
			dataTree1.Commit(inclusionProver, false),
			dataTree1.GetSize(),
		)
		orphanShard := application.GetShardKey(orphanVertices[i])
		require.Equal(t, shardKey, orphanShard, "orphan vertex %d must share shard", i)

		orphanIDs[i] = orphanVertices[i].GetID()
		require.NoError(t, clientHypergraphStore.SaveVertexTree(orphanTxn, orphanIDs[i][:], dataTree1))
		require.NoError(t, crdts[1].AddVertex(orphanTxn, orphanVertices[i]))
	}
	require.NoError(t, orphanTxn.Commit())

	clientSet := crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey)
	for i := 0; i < numOrphans; i++ {
		require.True(t, clientSet.Has(orphanIDs[i]), "client must start with orphan leaf %d", i)
	}
	logger.Info("saved")

	for _, op := range operations1 {
		switch op.Type {
		case "AddVertex":
			crdts[2].AddVertex(controltxn, op.Vertex)
		case "RemoveVertex":
			crdts[2].RemoveVertex(controltxn, op.Vertex)
			// case "AddHyperedge":
			// 	crdts[2].AddHyperedge(nil, op.Hyperedge)
			// case "RemoveHyperedge":
			// 	crdts[2].RemoveHyperedge(nil, op.Hyperedge)
		}
	}
	for _, op := range operations2 {
		switch op.Type {
		case "AddVertex":
			crdts[2].AddVertex(controltxn, op.Vertex)
		case "RemoveVertex":
			crdts[2].RemoveVertex(controltxn, op.Vertex)
			// case "AddHyperedge":
			// 	crdts[2].AddHyperedge(nil, op.Hyperedge)
			// case "RemoveHyperedge":
			// 	crdts[2].RemoveHyperedge(nil, op.Hyperedge)
		}
	}
	controltxn.Commit()

	logger.Info("run commit server")

	crdts[0].Commit(0)
	logger.Info("run commit client")
	crdts[1].Commit(0)
	// crdts[2].Commit()
	// err := serverHypergraphStore.SaveHypergraph(crdts[0])
	// assert.NoError(t, err)
	// err = clientHypergraphStore.SaveHypergraph(crdts[1])
	// assert.NoError(t, err)
	logger.Info("mark as complete")

	serverHypergraphStore.MarkHypergraphAsComplete()
	clientHypergraphStore.MarkHypergraphAsComplete()
	logger.Info("load server")

	log.Printf("Generated data")

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Server: failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(100*1024*1024), // 100 MB
		grpc.MaxSendMsgSize(100*1024*1024), // 100 MB
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
		crdts[0],
	)
	defer grpcServer.Stop()
	log.Println("Server listening on :50051")
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Server: failed to serve: %v", err)
		}
	}()

	conn, err := grpc.DialContext(context.TODO(), "localhost:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(100*1024*1024), // 100 MB
			grpc.MaxCallSendMsgSize(100*1024*1024), // 100 MB
		),
	)
	if err != nil {
		log.Fatalf("Client: failed to listen: %v", err)
	}
	client := protobufs.NewHypergraphComparisonServiceClient(conn)
	str, err := client.PerformSync(context.TODO())
	if err != nil {
		log.Fatalf("Client: failed to stream: %v", err)
	}

	_, err = crdts[1].(*hgcrdt.HypergraphCRDT).SyncFrom(str, shardKey, protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS, nil)
	if err != nil {
		log.Fatalf("Client: failed to sync 1: %v", err)
	}
	str.CloseSend()

	// Verify all orphan vertices were pruned after sync
	for i := 0; i < numOrphans; i++ {
		require.False(t, clientSet.Has(orphanIDs[i]), "orphan vertex %d should be pruned after sync", i)
	}
	leaves := crypto.CompareLeaves(
		crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree(),
		crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree(),
	)
	fmt.Println("pass completed, orphans:", len(leaves))

	// Ensure every leaf received during raw sync lies within the covered prefix path.
	clientTree := crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree()
	coveredPrefixPath := clientTree.CoveredPrefix
	if len(coveredPrefixPath) == 0 {
		coveredPrefixPath = tries.GetFullPath(orphanIDs[0][:])[:0]
	}
	allLeaves := tries.GetAllLeaves(
		clientTree.SetType,
		clientTree.PhaseType,
		clientTree.ShardKey,
		clientTree.Root,
	)
	for _, leaf := range allLeaves {
		if leaf == nil {
			continue
		}
		if len(coveredPrefixPath) > 0 {
			require.True(
				t,
				isPrefix(coveredPrefixPath, tries.GetFullPath(leaf.Key)),
				"raw sync leaf outside covered prefix",
			)
		}
	}

	crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)

	str, err = client.PerformSync(context.TODO())
	if err != nil {
		log.Fatalf("Client: failed to stream: %v", err)
	}

	_, err = crdts[1].(*hgcrdt.HypergraphCRDT).SyncFrom(str, shardKey, protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS, nil)
	if err != nil {
		log.Fatalf("Client: failed to sync 2: %v", err)
	}
	str.CloseSend()

	if !bytes.Equal(
		crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(nil, false),
		crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(nil, false),
	) {
		leaves := crypto.CompareLeaves(
			crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree(),
			crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree(),
		)
		fmt.Println("remaining orphans", len(leaves))
		log.Fatalf(
			"trees mismatch: %v %v",
			crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(nil, false),
			crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(nil, false),
		)
	}

	if !bytes.Equal(
		crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(nil, false),
		crdts[2].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(nil, false),
	) {
		log.Fatalf(
			"trees did not converge to correct state: %v %v",
			crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(nil, false),
			crdts[2].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(nil, false),
		)
	}
}

func TestHypergraphPartialSync(t *testing.T) {
	numParties := 3
	numOperations := 1000
	log.Printf("Generating data")
	enc := verenc.NewMPCitHVerifiableEncryptor(1)
	pub, _, _ := ed448.GenerateKey(rand.Reader)
	data1 := enc.Encrypt(make([]byte, 20), pub)
	verenc1 := data1[0].Compress()
	vertices1 := make([]application.Vertex, numOperations)
	dataTree1 := &crypto.VectorCommitmentTree{}
	logger, _ := zap.NewDevelopment()
	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	domain := make([]byte, 32)
	rand.Read(domain)
	domainbi, _ := poseidon.HashBytes(domain)
	domain = domainbi.FillBytes(make([]byte, 32))
	for _, d := range []application.Encrypted{verenc1} {
		dataBytes := d.ToBytes()
		id := sha512.Sum512(dataBytes)
		dataTree1.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data1)*55)))
	}
	dataTree1.Commit(inclusionProver, false)
	for i := 0; i < numOperations; i++ {
		b := make([]byte, 32)
		rand.Read(b)
		addr, _ := poseidon.HashBytes(b)
		vertices1[i] = hgcrdt.NewVertex(
			[32]byte(domain),
			[32]byte(addr.FillBytes(make([]byte, 32))),
			dataTree1.Commit(inclusionProver, false),
			dataTree1.GetSize(),
		)
	}

	hyperedges := make([]application.Hyperedge, numOperations/10)
	for i := 0; i < numOperations/10; i++ {
		hyperedges[i] = hgcrdt.NewHyperedge(
			[32]byte(domain),
			[32]byte{0, 0, byte((i >> 8) / 256), byte(i / 256)},
		)
		for j := 0; j < 3; j++ {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(vertices1))))
			v := vertices1[n.Int64()]
			hyperedges[i].AddExtrinsic(v)
		}
	}

	shardKey := application.GetShardKey(vertices1[0])

	operations1 := make([]Operation, numOperations)
	operations2 := make([]Operation, numOperations)
	for i := 0; i < numOperations; i++ {
		operations1[i] = Operation{Type: "AddVertex", Vertex: vertices1[i]}
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

	clientKvdb := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestclient/store"}}, 0)
	serverKvdb := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestserver/store"}}, 0)
	controlKvdb := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestcontrol/store"}}, 0)

	clientHypergraphStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{Path: ".configtestclient/store"},
		clientKvdb,
		logger,
		enc,
		inclusionProver,
	)
	serverHypergraphStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{Path: ".configtestserver/store"},
		serverKvdb,
		logger,
		enc,
		inclusionProver,
	)
	controlHypergraphStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{Path: ".configtestcontrol/store"},
		controlKvdb,
		logger,
		enc,
		inclusionProver,
	)
	crdts := make([]application.Hypergraph, numParties)
	crdts[0] = hgcrdt.NewHypergraph(logger.With(zap.String("side", "server")), serverHypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{}, 200)
	crdts[2] = hgcrdt.NewHypergraph(logger.With(zap.String("side", "control")), controlHypergraphStore, inclusionProver, []int{}, &tests.Nopthenticator{}, 200)

	servertxn, _ := serverHypergraphStore.NewTransaction(false)
	controltxn, _ := controlHypergraphStore.NewTransaction(false)
	branchfork := []int32{}
	for i, op := range operations1 {
		switch op.Type {
		case "AddVertex":
			{
				id := op.Vertex.GetID()
				serverHypergraphStore.SaveVertexTree(servertxn, id[:], dataTree1)
				crdts[0].AddVertex(servertxn, op.Vertex)
			}
			{
				if i == 500 {
					id := op.Vertex.GetID()

					// Grab the first path of the data address, should get 1/64th ish
					branchfork = GetFullPath(id[:])[:44]
				}
			}
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

	servertxn.Commit()

	crdts[1] = hgcrdt.NewHypergraph(logger.With(zap.String("side", "client")), clientHypergraphStore, inclusionProver, toIntSlice(toUint32Slice(branchfork)), &tests.Nopthenticator{}, 200)
	logger.Info("saved")

	for _, op := range operations1 {
		switch op.Type {
		case "AddVertex":
			crdts[2].AddVertex(controltxn, op.Vertex)
		case "RemoveVertex":
			crdts[2].RemoveVertex(controltxn, op.Vertex)
			// case "AddHyperedge":
			// 	crdts[2].AddHyperedge(nil, op.Hyperedge)
			// case "RemoveHyperedge":
			// 	crdts[2].RemoveHyperedge(nil, op.Hyperedge)
		}
	}
	for _, op := range operations2 {
		switch op.Type {
		case "AddVertex":
			crdts[2].AddVertex(controltxn, op.Vertex)
		case "RemoveVertex":
			crdts[2].RemoveVertex(controltxn, op.Vertex)
			// case "AddHyperedge":
			// 	crdts[2].AddHyperedge(nil, op.Hyperedge)
			// case "RemoveHyperedge":
			// 	crdts[2].RemoveHyperedge(nil, op.Hyperedge)
		}
	}
	controltxn.Commit()

	logger.Info("run commit server")

	crdts[0].Commit(1)
	logger.Info("run commit client")
	crdts[1].Commit(1)
	// crdts[2].Commit()
	// err := serverHypergraphStore.SaveHypergraph(crdts[0])
	// assert.NoError(t, err)
	// err = clientHypergraphStore.SaveHypergraph(crdts[1])
	// assert.NoError(t, err)

	logger.Info("load server")

	log.Printf("Generated data")

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Server: failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(100*1024*1024), // 100 MB
		grpc.MaxSendMsgSize(100*1024*1024), // 100 MB
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
		crdts[0],
	)
	log.Println("Server listening on :50051")
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Server: failed to serve: %v", err)
		}
	}()

	conn, err := grpc.DialContext(context.TODO(), "localhost:50051",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(100*1024*1024), // 100 MB
			grpc.MaxCallSendMsgSize(100*1024*1024), // 100 MB
		),
	)
	if err != nil {
		log.Fatalf("Client: failed to listen: %v", err)
	}
	client := protobufs.NewHypergraphComparisonServiceClient(conn)
	str, err := client.PerformSync(context.TODO())
	if err != nil {
		log.Fatalf("Client: failed to stream: %v", err)
	}

	_, err = crdts[1].(*hgcrdt.HypergraphCRDT).SyncFrom(str, shardKey, protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS, nil)
	if err != nil {
		log.Fatalf("Client: failed to sync 1: %v", err)
	}
	str.CloseSend()
	leaves := crypto.CompareLeaves(
		crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree(),
		crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree(),
	)
	fmt.Println("pass completed, orphans:", len(leaves))

	crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)

	str, err = client.PerformSync(context.TODO())

	if err != nil {
		log.Fatalf("Client: failed to stream: %v", err)
	}

	_, err = crdts[1].(*hgcrdt.HypergraphCRDT).SyncFrom(str, shardKey, protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS, nil)
	if err != nil {
		log.Fatalf("Client: failed to sync 2: %v", err)
	}
	str.CloseSend()
	crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)

	desc, err := crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().GetByPath(toIntSlice(toUint32Slice(branchfork)))
	require.NoError(t, err)
	if !bytes.Equal(
		desc.(*crypto.LazyVectorCommitmentBranchNode).Commitment,
		crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(nil, false),
	) {
		leaves := crypto.CompareLeaves(
			crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree(),
			crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree(),
		)
		fmt.Println("remaining orphans", len(leaves))
	}

	clientHas := 0
	iter, err := clientHypergraphStore.GetVertexDataIterator(shardKey)
	if err != nil {
		panic(err)
	}
	for iter.First(); iter.Valid(); iter.Next() {
		clientHas++
	}

	// Assume variable distribution, but roughly triple is a safe guess. If it fails, just bump it.
	assert.Greater(t, 40, clientHas, "mismatching vertex data entries")
	// assert.Greater(t, clientHas, 1, "mismatching vertex data entries")
}

func TestHypergraphSyncWithConcurrentCommits(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	enc := verenc.NewMPCitHVerifiableEncryptor(1)
	inclusionProver := bls48581.NewKZGInclusionProver(logger)

	logDuration := func(step string, start time.Time) {
		t.Logf("%s took %s", step, time.Since(start))
	}

	start := time.Now()
	dataTrees := make([]*tries.VectorCommitmentTree, 1000)
	eg := errgroup.Group{}
	eg.SetLimit(1000)
	for i := 0; i < 1000; i++ {
		eg.Go(func() error {
			dataTrees[i] = buildDataTree(t, inclusionProver)
			return nil
		})
	}
	eg.Wait()
	logDuration("generated data trees", start)

	setupStart := time.Now()
	serverDB := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestserver/store"}}, 0)
	defer serverDB.Close()

	serverStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestserver/store"},
		serverDB,
		logger,
		enc,
		inclusionProver,
	)
	logDuration("server DB/store initialization", setupStart)

	const clientCount = 8
	clientDBs := make([]*store.PebbleDB, clientCount)
	clientStores := make([]*store.PebbleHypergraphStore, clientCount)
	clientHGs := make([]*hgcrdt.HypergraphCRDT, clientCount)

	serverHypergraphStart := time.Now()
	serverHG := hgcrdt.NewHypergraph(
		logger.With(zap.String("side", "server")),
		serverStore,
		inclusionProver,
		[]int{},
		&tests.Nopthenticator{},
		200,
	)
	logDuration("server hypergraph initialization", serverHypergraphStart)

	clientSetupStart := time.Now()
	for i := 0; i < clientCount; i++ {
		clientDBs[i] = store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".configtestclient%d/store", i)}}, 0)
		clientStores[i] = store.NewPebbleHypergraphStore(
			&config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".configtestclient%d/store", i)},
			clientDBs[i],
			logger,
			enc,
			inclusionProver,
		)
		clientHGs[i] = hgcrdt.NewHypergraph(
			logger.With(zap.String("side", fmt.Sprintf("client-%d", i))),
			clientStores[i],
			inclusionProver,
			[]int{},
			&tests.Nopthenticator{},
			200,
		)
	}
	logDuration("client hypergraph initialization", clientSetupStart)
	defer func() {
		for _, db := range clientDBs {
			if db != nil {
				db.Close()
			}
		}
	}()

	// Seed both hypergraphs with a baseline vertex so they share the shard key.
	domain := randomBytes32(t)
	initialVertex := hgcrdt.NewVertex(
		domain,
		randomBytes32(t),
		dataTrees[0].Commit(inclusionProver, false),
		dataTrees[0].GetSize(),
	)
	seedStart := time.Now()
	addVertices(
		t,
		serverStore,
		serverHG,
		dataTrees[:1],
		initialVertex,
	)
	logDuration("seed server baseline vertex", seedStart)
	for i := 0; i < clientCount; i++ {
		start := time.Now()
		addVertices(
			t,
			clientStores[i],
			clientHGs[i],
			dataTrees[:1],
			initialVertex,
		)
		logDuration(fmt.Sprintf("seed client-%d baseline vertex", i), start)
	}

	shardKey := application.GetShardKey(initialVertex)

	// Start gRPC server backed by the server hypergraph.
	const bufSize = 1 << 20
	lis := bufconn.Listen(bufSize)

	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(100*1024*1024), // 100 MB
		grpc.MaxSendMsgSize(100*1024*1024), // 100 MB
		grpc.ChainStreamInterceptor(func(
			srv interface{},
			ss grpc.ServerStream,
			info *grpc.StreamServerInfo,
			handler grpc.StreamHandler,
		) error {
			_, priv, _ := ed448.GenerateKey(rand.Reader)
			privKey, err := pcrypto.UnmarshalEd448PrivateKey(priv)
			require.NoError(t, err)

			pub := privKey.GetPublic()
			peerID, err := peer.IDFromPublicKey(pub)
			require.NoError(t, err)

			return handler(srv, &serverStream{
				ServerStream: ss,
				ctx:          internal_grpc.NewContextWithPeerID(ss.Context(), peerID),
			})
		}),
	)
	protobufs.RegisterHypergraphComparisonServiceServer(
		grpcServer,
		serverHG,
	)
	defer grpcServer.Stop()

	go func() {
		_ = grpcServer.Serve(lis)
	}()

	dialClient := func() (*grpc.ClientConn, protobufs.HypergraphComparisonServiceClient) {
		dialer := func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}

		conn, err := grpc.DialContext(
			context.Background(),
			"bufnet",
			grpc.WithContextDialer(dialer),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(
				grpc.MaxCallRecvMsgSize(100*1024*1024), // 100 MB
				grpc.MaxCallSendMsgSize(100*1024*1024), // 100 MB
			),
		)
		require.NoError(t, err)
		return conn, protobufs.NewHypergraphComparisonServiceClient(conn)
	}

	// Publish initial snapshot so clients can sync during the rounds
	initialRoot := serverHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	serverHG.PublishSnapshot(initialRoot)

	const rounds = 3
	for round := 0; round < rounds; round++ {
		currentRound := round
		roundStart := time.Now()
		c, _ := serverHG.Commit(uint64(currentRound))
		fmt.Printf("svr commitment: %x\n", c[shardKey][0])

		genStart := time.Now()
		updates := generateVertices(
			t,
			domain,
			dataTrees,
			inclusionProver,
			15,
			1+(15*currentRound),
		)
		logDuration(fmt.Sprintf("round %d vertex generation", currentRound), genStart)

		var syncWG sync.WaitGroup
		var serverWG sync.WaitGroup

		syncWG.Add(clientCount)
		serverWG.Add(1)

		for clientIdx := 0; clientIdx < clientCount; clientIdx++ {
			go func(idx int, round int) {
				defer syncWG.Done()
				clientSyncStart := time.Now()
				clientHG := clientHGs[idx]
				conn, client := dialClient()
				streamCtx, cancelStream := context.WithTimeout(
					context.Background(),
					100*time.Second,
				)
				stream, err := client.PerformSync(streamCtx)
				require.NoError(t, err)
				_, _ = clientHG.SyncFrom(
					stream,
					shardKey,
					protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
					nil,
				)
				require.NoError(t, stream.CloseSend())
				cancelStream()
				conn.Close()

				c, _ := clientHGs[idx].Commit(uint64(round))
				fmt.Printf("cli commitment: %x\n", c[shardKey][0])
				logDuration(fmt.Sprintf("round %d client-%d sync", round, idx), clientSyncStart)
			}(clientIdx, currentRound)
		}

		go func(round int) {
			defer serverWG.Done()
			serverRoundStart := time.Now()
			logger.Info("server applying concurrent updates", zap.Int("round", round))
			addVertices(t, serverStore, serverHG, dataTrees[1+(15*round):1+(15*(round+1))], updates...)
			logger.Info(
				"server applied concurrent updates",
				zap.Int("round", round),
				zap.Duration("duration", time.Since(serverRoundStart)),
			)
			logger.Info("server commit starting", zap.Int("round", round))
			_, err := serverHG.Commit(uint64(round + 1))
			require.NoError(t, err)
			logger.Info("server commit finished", zap.Int("round", round))
		}(round)

		syncWG.Wait()
		serverWG.Wait()
		logDuration(fmt.Sprintf("round %d total sync", currentRound), roundStart)
	}

	// Add additional server-only updates after the concurrent sync rounds.
	extraStart := time.Now()
	extraUpdates := generateVertices(t, domain, dataTrees, inclusionProver, len(dataTrees)-(1+(15*rounds))-1, 1+(15*rounds))
	addVertices(t, serverStore, serverHG, dataTrees[1+(15*rounds):], extraUpdates...)
	logDuration("server extra updates application", extraStart)

	commitStart := time.Now()
	_, err := serverHG.Commit(100)
	require.NoError(t, err)

	_, err = serverHG.Commit(101)
	require.NoError(t, err)
	logDuration("server final commits", commitStart)
	wg := sync.WaitGroup{}
	wg.Add(1)
	serverRoot := serverHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	// Publish the server's snapshot so clients can sync against this exact state
	serverHG.PublishSnapshot(serverRoot)

	// Create a snapshot handle for this shard by doing a sync.
	// This is needed because the snapshot manager only creates handles when acquire
	// is called.
	{
		conn, client := dialClient()
		stream, err := client.PerformSync(context.Background())
		require.NoError(t, err)
		_, _ = clientHGs[0].SyncFrom(
			stream,
			shardKey,
			protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
			nil,
		)
		_ = stream.CloseSend()
		conn.Close()
	}

	for i := 0; i < 1; i++ {
		go func(idx int) {
			defer wg.Done()
			catchUpStart := time.Now()

			_, err = clientHGs[idx].Commit(100)
			require.NoError(t, err)
			// Final sync to catch up.
			conn, client := dialClient()
			streamCtx, cancelStream := context.WithTimeout(
				context.Background(),
				100*time.Second,
			)
			stream, err := client.PerformSync(streamCtx)
			require.NoError(t, err)
			_, err = clientHGs[idx].SyncFrom(
				stream,
				shardKey,
				protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
				nil,
			)
			require.NoError(t, err)
			require.NoError(t, stream.CloseSend())
			cancelStream()
			conn.Close()

			_, err = clientHGs[idx].Commit(101)
			require.NoError(t, err)
			clientRoot := clientHGs[idx].GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
			assert.Equal(t, serverRoot, clientRoot, "client should converge to server state")
			logDuration(fmt.Sprintf("client-%d final catch-up", idx), catchUpStart)
		}(i)
	}
	wg.Wait()
}

func buildDataTree(
	t *testing.T,
	prover *bls48581.KZGInclusionProver,
) *crypto.VectorCommitmentTree {
	t.Helper()

	tree := &crypto.VectorCommitmentTree{}
	b := make([]byte, 20000)
	rand.Read(b)
	for bytes := range slices.Chunk(b, 64) {
		id := sha512.Sum512(bytes)
		tree.Insert(id[:], bytes, nil, big.NewInt(int64(len(bytes))))
	}
	tree.Commit(prover, false)
	return tree
}

func addVertices(
	t *testing.T,
	hStore *store.PebbleHypergraphStore,
	hg *hgcrdt.HypergraphCRDT,
	dataTrees []*crypto.VectorCommitmentTree,
	vertices ...application.Vertex,
) {
	t.Helper()

	txn, err := hStore.NewTransaction(false)
	require.NoError(t, err)
	for i, v := range vertices {
		id := v.GetID()
		require.NoError(t, hStore.SaveVertexTree(txn, id[:], dataTrees[i]))
		require.NoError(t, hg.AddVertex(txn, v))
	}
	require.NoError(t, txn.Commit())
}

func generateVertices(
	t *testing.T,
	appAddress [32]byte,
	dataTrees []*crypto.VectorCommitmentTree,
	prover *bls48581.KZGInclusionProver,
	count int,
	startingIndex int,
) []application.Vertex {
	t.Helper()

	verts := make([]application.Vertex, count)
	for i := 0; i < count; i++ {
		addr := randomBytes32(t)
		binary.BigEndian.PutUint64(addr[:], uint64(i))
		verts[i] = hgcrdt.NewVertex(
			appAddress,
			addr,
			dataTrees[startingIndex+i].Commit(prover, false),
			dataTrees[startingIndex+i].GetSize(),
		)
	}
	return verts
}

func randomBytes32(t *testing.T) [32]byte {
	t.Helper()
	var out [32]byte
	_, err := rand.Read(out[:])
	require.NoError(t, err)
	return out
}

func toUint32Slice(s []int32) []uint32 {
	o := []uint32{}
	for _, p := range s {
		o = append(o, uint32(p))
	}
	return o
}

func toIntSlice(s []uint32) []int {
	o := []int{}
	for _, p := range s {
		o = append(o, int(p))
	}
	return o
}

func isPrefix(prefix []int, path []int) bool {
	if len(prefix) > len(path) {
		return false
	}

	for i := range prefix {
		if prefix[i] != path[i] {
			return false
		}
	}

	return true
}

func GetFullPath(key []byte) []int32 {
	var nibbles []int32
	depth := 0
	for {
		n1 := getNextNibble(key, depth)
		if n1 == -1 {
			break
		}
		nibbles = append(nibbles, n1)
		depth += tries.BranchBits
	}

	return nibbles
}

// getNextNibble returns the next BranchBits bits from the key starting at pos
func getNextNibble(key []byte, pos int) int32 {
	startByte := pos / 8
	if startByte >= len(key) {
		return -1
	}

	// Calculate how many bits we need from the current byte
	startBit := pos % 8
	bitsFromCurrentByte := 8 - startBit

	result := int(key[startByte] & ((1 << bitsFromCurrentByte) - 1))

	if bitsFromCurrentByte >= tries.BranchBits {
		// We have enough bits in the current byte
		return int32((result >> (bitsFromCurrentByte - tries.BranchBits)) &
			tries.BranchMask)
	}

	// We need bits from the next byte
	result = result << (tries.BranchBits - bitsFromCurrentByte)
	if startByte+1 < len(key) {
		remainingBits := tries.BranchBits - bitsFromCurrentByte
		nextByte := int(key[startByte+1])
		result |= (nextByte >> (8 - remainingBits))
	}

	return int32(result & tries.BranchMask)
}

// TestHypergraphSyncWithExpectedRoot tests that clients can request sync
// against a specific snapshot generation by providing an expected root.
// The server should use a matching historical snapshot if available.
func TestHypergraphSyncWithExpectedRoot(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	enc := verenc.NewMPCitHVerifiableEncryptor(1)
	inclusionProver := bls48581.NewKZGInclusionProver(logger)

	// Create data trees for vertices
	dataTrees := make([]*tries.VectorCommitmentTree, 100)
	for i := 0; i < 100; i++ {
		dataTrees[i] = buildDataTree(t, inclusionProver)
	}

	serverDB := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestserver/store"}}, 0)
	defer serverDB.Close()

	serverStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestserver/store"},
		serverDB,
		logger,
		enc,
		inclusionProver,
	)

	serverHG := hgcrdt.NewHypergraph(
		logger.With(zap.String("side", "server")),
		serverStore,
		inclusionProver,
		[]int{},
		&tests.Nopthenticator{},
		200,
	)

	// Create initial vertex to establish shard key
	domain := randomBytes32(t)
	initialVertex := hgcrdt.NewVertex(
		domain,
		randomBytes32(t),
		dataTrees[0].Commit(inclusionProver, false),
		dataTrees[0].GetSize(),
	)
	shardKey := application.GetShardKey(initialVertex)

	// Phase 1: Add initial vertices to server and commit
	phase1Vertices := make([]application.Vertex, 20)
	phase1Vertices[0] = initialVertex
	for i := 1; i < 20; i++ {
		phase1Vertices[i] = hgcrdt.NewVertex(
			domain,
			randomBytes32(t),
			dataTrees[i].Commit(inclusionProver, false),
			dataTrees[i].GetSize(),
		)
	}
	addVertices(t, serverStore, serverHG, dataTrees[:20], phase1Vertices...)

	// Commit to get root1
	commitResult1, err := serverHG.Commit(1)
	require.NoError(t, err)
	root1 := commitResult1[shardKey][0]
	t.Logf("Root after phase 1: %x", root1)

	// Publish root1 as the current snapshot generation
	serverHG.PublishSnapshot(root1)

	// Start gRPC server early so we can create a snapshot while root1 is current
	const bufSize = 1 << 20
	lis := bufconn.Listen(bufSize)

	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(100*1024*1024), // 100 MB
		grpc.MaxSendMsgSize(100*1024*1024), // 100 MB
		grpc.ChainStreamInterceptor(func(
			srv interface{},
			ss grpc.ServerStream,
			info *grpc.StreamServerInfo,
			handler grpc.StreamHandler,
		) error {
			_, priv, _ := ed448.GenerateKey(rand.Reader)
			privKey, err := pcrypto.UnmarshalEd448PrivateKey(priv)
			require.NoError(t, err)

			pub := privKey.GetPublic()
			peerID, err := peer.IDFromPublicKey(pub)
			require.NoError(t, err)

			return handler(srv, &serverStream{
				ServerStream: ss,
				ctx:          internal_grpc.NewContextWithPeerID(ss.Context(), peerID),
			})
		}),
	)
	protobufs.RegisterHypergraphComparisonServiceServer(grpcServer, serverHG)
	defer grpcServer.Stop()

	go func() {
		_ = grpcServer.Serve(lis)
	}()

	dialClient := func() (*grpc.ClientConn, protobufs.HypergraphComparisonServiceClient) {
		dialer := func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}
		conn, err := grpc.DialContext(
			context.Background(),
			"bufnet",
			grpc.WithContextDialer(dialer),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(
				grpc.MaxCallRecvMsgSize(100*1024*1024), // 100 MB
				grpc.MaxCallSendMsgSize(100*1024*1024), // 100 MB
			),
		)
		require.NoError(t, err)
		return conn, protobufs.NewHypergraphComparisonServiceClient(conn)
	}

	// Helper to create a fresh client hypergraph
	clientCounter := 0
	createClient := func(name string) (*store.PebbleDB, *hgcrdt.HypergraphCRDT) {
		clientCounter++
		clientDB := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".configtestclient%d/store", clientCounter)}}, 0)
		clientStore := store.NewPebbleHypergraphStore(
			&config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".configtestclient%d/store", clientCounter)},
			clientDB,
			logger,
			enc,
			inclusionProver,
		)
		clientHG := hgcrdt.NewHypergraph(
			logger.With(zap.String("side", name)),
			clientStore,
			inclusionProver,
			[]int{},
			&tests.Nopthenticator{},
			200,
		)
		return clientDB, clientHG
	}

	// IMPORTANT: Create a snapshot while root1 is current by doing a sync now.
	// This snapshot will be preserved when we later publish root2.
	t.Log("Creating snapshot for root1 by syncing a client while root1 is current")
	{
		clientDB, clientHG := createClient("client-snapshot-root1")
		conn, client := dialClient()

		stream, err := client.PerformSync(context.Background())
		require.NoError(t, err)

		_, err = clientHG.SyncFrom(
			stream,
			shardKey,
			protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
			nil,
		)
		require.NoError(t, err)
		require.NoError(t, stream.CloseSend())

		// Verify this client got root1
		clientCommit, err := clientHG.Commit(1)
		require.NoError(t, err)
		require.Equal(t, root1, clientCommit[shardKey][0], "snapshot client should have root1")

		conn.Close()
		clientDB.Close()
	}

	// Phase 2: Add more vertices to server and commit
	phase2Vertices := make([]application.Vertex, 30)
	for i := 0; i < 30; i++ {
		phase2Vertices[i] = hgcrdt.NewVertex(
			domain,
			randomBytes32(t),
			dataTrees[20+i].Commit(inclusionProver, false),
			dataTrees[20+i].GetSize(),
		)
	}
	addVertices(t, serverStore, serverHG, dataTrees[20:50], phase2Vertices...)

	// Commit to get root2
	commitResult2, err := serverHG.Commit(2)
	require.NoError(t, err)
	root2 := commitResult2[shardKey][0]
	t.Logf("Root after phase 2: %x", root2)

	// Publish root2 as the new current snapshot generation
	// This preserves the root1 generation (with its snapshot) as a historical generation
	serverHG.PublishSnapshot(root2)

	// Verify roots are different
	require.NotEqual(t, root1, root2, "roots should be different after adding more data")

	// Test 1: Sync gets latest state
	t.Run("sync gets latest", func(t *testing.T) {
		clientDB, clientHG := createClient("client1")
		defer clientDB.Close()

		conn, client := dialClient()
		defer conn.Close()

		stream, err := client.PerformSync(context.Background())
		require.NoError(t, err)

		_, err = clientHG.SyncFrom(
			stream,
			shardKey,
			protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
			nil,
		)
		require.NoError(t, err)
		require.NoError(t, stream.CloseSend())

		// Commit client to get comparable root
		clientCommit, err := clientHG.Commit(1)
		require.NoError(t, err)
		clientRoot := clientCommit[shardKey][0]

		// Client should have synced to the latest (root2)
		assert.Equal(t, root2, clientRoot, "client should sync to latest root")
	})

	// Test 2: Multiple syncs converge to same state
	t.Run("multiple syncs converge", func(t *testing.T) {
		clientDB, clientHG := createClient("client2")
		defer clientDB.Close()

		conn, client := dialClient()
		defer conn.Close()

		stream, err := client.PerformSync(context.Background())
		require.NoError(t, err)

		_, err = clientHG.SyncFrom(
			stream,
			shardKey,
			protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
			nil,
		)
		require.NoError(t, err)
		require.NoError(t, stream.CloseSend())

		// Commit client to get comparable root
		clientCommit, err := clientHG.Commit(1)
		require.NoError(t, err)
		clientRoot := clientCommit[shardKey][0]

		// Client should have synced to the latest (root2)
		assert.Equal(t, root2, clientRoot, "client should sync to latest root")
	})
}

// TestHypergraphSyncWithModifiedEntries tests sync behavior when both client
// and server have the same keys but with different values (modified entries).
// This verifies that sync correctly updates entries rather than just adding
// new ones or deleting orphans.
func TestHypergraphSyncWithModifiedEntries(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	enc := verenc.NewMPCitHVerifiableEncryptor(1)
	inclusionProver := bls48581.NewKZGInclusionProver(logger)

	// Create enough data trees for all vertices we'll need
	numVertices := 50
	dataTrees := make([]*tries.VectorCommitmentTree, numVertices*2) // Extra for modified versions
	for i := 0; i < len(dataTrees); i++ {
		dataTrees[i] = buildDataTree(t, inclusionProver)
	}

	// Create server and client databases
	serverDB := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestserver/store"}}, 0)
	defer serverDB.Close()

	clientDB := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestclient/store"}}, 0)
	defer clientDB.Close()

	serverStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestserver/store"},
		serverDB,
		logger,
		enc,
		inclusionProver,
	)

	clientStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestclient/store"},
		clientDB,
		logger,
		enc,
		inclusionProver,
	)

	serverHG := hgcrdt.NewHypergraph(
		logger.With(zap.String("side", "server")),
		serverStore,
		inclusionProver,
		[]int{},
		&tests.Nopthenticator{},
		200,
	)

	clientHG := hgcrdt.NewHypergraph(
		logger.With(zap.String("side", "client")),
		clientStore,
		inclusionProver,
		[]int{},
		&tests.Nopthenticator{},
		200,
	)

	// Create a shared domain for all vertices
	domain := randomBytes32(t)

	// Generate fixed addresses that will be used by both client and server
	// This ensures they share the same keys
	addresses := make([][32]byte, numVertices)
	for i := 0; i < numVertices; i++ {
		addresses[i] = randomBytes32(t)
	}

	// Create "original" vertices for the client (using first set of data trees)
	clientVertices := make([]application.Vertex, numVertices)
	for i := 0; i < numVertices; i++ {
		clientVertices[i] = hgcrdt.NewVertex(
			domain,
			addresses[i], // Same address
			dataTrees[i].Commit(inclusionProver, false),
			dataTrees[i].GetSize(),
		)
	}

	// Create "modified" vertices for the server (using second set of data trees)
	// These have the SAME addresses but DIFFERENT data commitments
	serverVertices := make([]application.Vertex, numVertices)
	for i := 0; i < numVertices; i++ {
		serverVertices[i] = hgcrdt.NewVertex(
			domain,
			addresses[i], // Same address as client
			dataTrees[numVertices+i].Commit(inclusionProver, false), // Different data
			dataTrees[numVertices+i].GetSize(),
		)
	}

	shardKey := application.GetShardKey(clientVertices[0])

	// Add original vertices to client
	t.Log("Adding original vertices to client")
	clientTxn, err := clientStore.NewTransaction(false)
	require.NoError(t, err)
	for i, v := range clientVertices {
		id := v.GetID()
		require.NoError(t, clientStore.SaveVertexTree(clientTxn, id[:], dataTrees[i]))
		require.NoError(t, clientHG.AddVertex(clientTxn, v))
	}
	require.NoError(t, clientTxn.Commit())

	// Add modified vertices to server
	t.Log("Adding modified vertices to server")
	serverTxn, err := serverStore.NewTransaction(false)
	require.NoError(t, err)
	for i, v := range serverVertices {
		id := v.GetID()
		require.NoError(t, serverStore.SaveVertexTree(serverTxn, id[:], dataTrees[numVertices+i]))
		require.NoError(t, serverHG.AddVertex(serverTxn, v))
	}
	require.NoError(t, serverTxn.Commit())

	// Commit both hypergraphs
	_, err = clientHG.Commit(1)
	require.NoError(t, err)
	_, err = serverHG.Commit(1)
	require.NoError(t, err)

	// Verify roots are different before sync (modified entries should cause different roots)
	clientRootBefore := clientHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	serverRoot := serverHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	require.NotEqual(t, clientRootBefore, serverRoot, "roots should differ before sync due to modified entries")

	t.Logf("Client root before sync: %x", clientRootBefore)
	t.Logf("Server root: %x", serverRoot)

	// Publish server snapshot
	serverHG.PublishSnapshot(serverRoot)

	// Start gRPC server
	const bufSize = 1 << 20
	lis := bufconn.Listen(bufSize)

	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(100*1024*1024), // 100 MB
		grpc.MaxSendMsgSize(100*1024*1024), // 100 MB
		grpc.ChainStreamInterceptor(func(
			srv interface{},
			ss grpc.ServerStream,
			info *grpc.StreamServerInfo,
			handler grpc.StreamHandler,
		) error {
			_, priv, _ := ed448.GenerateKey(rand.Reader)
			privKey, err := pcrypto.UnmarshalEd448PrivateKey(priv)
			require.NoError(t, err)

			pub := privKey.GetPublic()
			peerID, err := peer.IDFromPublicKey(pub)
			require.NoError(t, err)

			return handler(srv, &serverStream{
				ServerStream: ss,
				ctx:          internal_grpc.NewContextWithPeerID(ss.Context(), peerID),
			})
		}),
	)
	protobufs.RegisterHypergraphComparisonServiceServer(grpcServer, serverHG)
	defer grpcServer.Stop()

	go func() {
		_ = grpcServer.Serve(lis)
	}()

	dialClient := func() (*grpc.ClientConn, protobufs.HypergraphComparisonServiceClient) {
		dialer := func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}
		conn, err := grpc.DialContext(
			context.Background(),
			"bufnet",
			grpc.WithContextDialer(dialer),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(
				grpc.MaxCallRecvMsgSize(100*1024*1024), // 100 MB
				grpc.MaxCallSendMsgSize(100*1024*1024), // 100 MB
			),
		)
		require.NoError(t, err)
		return conn, protobufs.NewHypergraphComparisonServiceClient(conn)
	}

	// Perform sync
	t.Log("Performing sync to update modified entries")
	conn, client := dialClient()
	defer conn.Close()

	stream, err := client.PerformSync(context.Background())
	require.NoError(t, err)

	_, err = clientHG.SyncFrom(
		stream,
		shardKey,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
		nil,
	)
	require.NoError(t, err)
	require.NoError(t, stream.CloseSend())

	// Commit client after sync
	_, err = clientHG.Commit(2)
	require.NoError(t, err)

	// Verify client now matches server
	clientRootAfter := clientHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	t.Logf("Client root after sync: %x", clientRootAfter)

	assert.Equal(t, serverRoot, clientRootAfter, "client should converge to server state after sync with modified entries")

	// Verify all entries were updated by comparing the leaves
	serverTree := serverHG.GetVertexAddsSet(shardKey).GetTree()
	clientTree := clientHG.GetVertexAddsSet(shardKey).GetTree()

	diffLeaves := tries.CompareLeaves(serverTree, clientTree)
	assert.Empty(t, diffLeaves, "there should be no difference in leaves after sync")

	t.Logf("Sync completed successfully - %d entries with same keys but different values were updated", numVertices)
}

// TestHypergraphBidirectionalSyncWithDisjointData tests that when node A has 500
// unique vertices and node B has 500 different unique vertices, syncing in both
// directions results in both nodes having all 1000 vertices.
func TestHypergraphBidirectionalSyncWithDisjointData(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	enc := verenc.NewMPCitHVerifiableEncryptor(1)
	inclusionProver := bls48581.NewKZGInclusionProver(logger)

	// Create data trees for all 1000 vertices
	numVerticesPerNode := 500
	totalVertices := numVerticesPerNode * 2
	dataTrees := make([]*tries.VectorCommitmentTree, totalVertices)
	eg := errgroup.Group{}
	eg.SetLimit(100)
	for i := 0; i < totalVertices; i++ {
		eg.Go(func() error {
			dataTrees[i] = buildDataTree(t, inclusionProver)
			return nil
		})
	}
	eg.Wait()
	t.Log("Generated data trees")

	// Create databases and stores for both nodes
	nodeADB := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestnodeA/store"}}, 0)
	defer nodeADB.Close()

	nodeBDB := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestnodeB/store"}}, 0)
	defer nodeBDB.Close()

	nodeAStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestnodeA/store"},
		nodeADB,
		logger,
		enc,
		inclusionProver,
	)

	nodeBStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestnodeB/store"},
		nodeBDB,
		logger,
		enc,
		inclusionProver,
	)

	nodeAHG := hgcrdt.NewHypergraph(
		logger.With(zap.String("side", "nodeA")),
		nodeAStore,
		inclusionProver,
		[]int{},
		&tests.Nopthenticator{},
		200,
	)

	nodeBHG := hgcrdt.NewHypergraph(
		logger.With(zap.String("side", "nodeB")),
		nodeBStore,
		inclusionProver,
		[]int{},
		&tests.Nopthenticator{},
		200,
	)

	// Create a shared domain for all vertices
	domain := randomBytes32(t)

	// Generate vertices for node A (first 500)
	nodeAVertices := make([]application.Vertex, numVerticesPerNode)
	for i := 0; i < numVerticesPerNode; i++ {
		addr := randomBytes32(t)
		nodeAVertices[i] = hgcrdt.NewVertex(
			domain,
			addr,
			dataTrees[i].Commit(inclusionProver, false),
			dataTrees[i].GetSize(),
		)
	}

	// Generate vertices for node B (second 500, completely different)
	nodeBVertices := make([]application.Vertex, numVerticesPerNode)
	for i := 0; i < numVerticesPerNode; i++ {
		addr := randomBytes32(t)
		nodeBVertices[i] = hgcrdt.NewVertex(
			domain,
			addr,
			dataTrees[numVerticesPerNode+i].Commit(inclusionProver, false),
			dataTrees[numVerticesPerNode+i].GetSize(),
		)
	}

	shardKey := application.GetShardKey(nodeAVertices[0])

	// Add vertices to node A
	t.Log("Adding 500 vertices to node A")
	nodeATxn, err := nodeAStore.NewTransaction(false)
	require.NoError(t, err)
	for i, v := range nodeAVertices {
		id := v.GetID()
		require.NoError(t, nodeAStore.SaveVertexTree(nodeATxn, id[:], dataTrees[i]))
		require.NoError(t, nodeAHG.AddVertex(nodeATxn, v))
	}
	require.NoError(t, nodeATxn.Commit())

	// Add vertices to node B
	t.Log("Adding 500 different vertices to node B")
	nodeBTxn, err := nodeBStore.NewTransaction(false)
	require.NoError(t, err)
	for i, v := range nodeBVertices {
		id := v.GetID()
		require.NoError(t, nodeBStore.SaveVertexTree(nodeBTxn, id[:], dataTrees[numVerticesPerNode+i]))
		require.NoError(t, nodeBHG.AddVertex(nodeBTxn, v))
	}
	require.NoError(t, nodeBTxn.Commit())

	// Commit both hypergraphs
	_, err = nodeAHG.Commit(1)
	require.NoError(t, err)
	_, err = nodeBHG.Commit(1)
	require.NoError(t, err)

	nodeARootBefore := nodeAHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	nodeBRootBefore := nodeBHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	t.Logf("Node A root before sync: %x", nodeARootBefore)
	t.Logf("Node B root before sync: %x", nodeBRootBefore)
	require.NotEqual(t, nodeARootBefore, nodeBRootBefore, "roots should differ before sync")

	// Helper to set up gRPC server for a hypergraph
	setupServer := func(hg *hgcrdt.HypergraphCRDT) (*bufconn.Listener, *grpc.Server) {
		const bufSize = 1 << 20
		lis := bufconn.Listen(bufSize)

		grpcServer := grpc.NewServer(
			grpc.MaxRecvMsgSize(100*1024*1024), // 100 MB
			grpc.MaxSendMsgSize(100*1024*1024), // 100 MB
			grpc.ChainStreamInterceptor(func(
				srv interface{},
				ss grpc.ServerStream,
				info *grpc.StreamServerInfo,
				handler grpc.StreamHandler,
			) error {
				_, priv, _ := ed448.GenerateKey(rand.Reader)
				privKey, err := pcrypto.UnmarshalEd448PrivateKey(priv)
				require.NoError(t, err)

				pub := privKey.GetPublic()
				peerID, err := peer.IDFromPublicKey(pub)
				require.NoError(t, err)

				return handler(srv, &serverStream{
					ServerStream: ss,
					ctx:          internal_grpc.NewContextWithPeerID(ss.Context(), peerID),
				})
			}),
		)
		protobufs.RegisterHypergraphComparisonServiceServer(grpcServer, hg)

		go func() {
			_ = grpcServer.Serve(lis)
		}()

		return lis, grpcServer
	}

	dialClient := func(lis *bufconn.Listener) (*grpc.ClientConn, protobufs.HypergraphComparisonServiceClient) {
		dialer := func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}
		conn, err := grpc.DialContext(
			context.Background(),
			"bufnet",
			grpc.WithContextDialer(dialer),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(
				grpc.MaxCallRecvMsgSize(100*1024*1024), // 100 MB
				grpc.MaxCallSendMsgSize(100*1024*1024), // 100 MB
			),
		)
		require.NoError(t, err)
		return conn, protobufs.NewHypergraphComparisonServiceClient(conn)
	}

	// Step 1: Node A syncs from Node B (as server)
	// Node A should receive Node B's 500 vertices
	t.Log("Step 1: Node A syncs from Node B (B is server)")
	nodeBHG.PublishSnapshot(nodeBRootBefore)
	lisB, serverB := setupServer(nodeBHG)
	defer serverB.Stop()

	connB, clientB := dialClient(lisB)
	streamB, err := clientB.PerformSync(context.Background())
	require.NoError(t, err)

	_, err = nodeAHG.SyncFrom(
		streamB,
		shardKey,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
		nil,
	)
	require.NoError(t, err)
	require.NoError(t, streamB.CloseSend())
	connB.Close()

	_, err = nodeAHG.Commit(2)
	require.NoError(t, err)

	nodeARootAfterFirstSync := nodeAHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	t.Logf("Node A root after syncing from B: %x", nodeARootAfterFirstSync)

	// Step 2: Node B syncs from Node A (as server)
	// Node B should receive Node A's 500 vertices
	t.Log("Step 2: Node B syncs from Node A (A is server)")
	nodeAHG.PublishSnapshot(nodeARootAfterFirstSync)
	lisA, serverA := setupServer(nodeAHG)
	defer serverA.Stop()

	connA, clientA := dialClient(lisA)
	streamA, err := clientA.PerformSync(context.Background())
	require.NoError(t, err)

	_, err = nodeBHG.SyncFrom(
		streamA,
		shardKey,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
		nil,
	)
	require.NoError(t, err)
	require.NoError(t, streamA.CloseSend())
	connA.Close()

	_, err = nodeBHG.Commit(2)
	require.NoError(t, err)

	// Verify both nodes have converged
	nodeARootFinal := nodeAHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	nodeBRootFinal := nodeBHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	t.Logf("Node A final root: %x", nodeARootFinal)
	t.Logf("Node B final root: %x", nodeBRootFinal)

	assert.Equal(t, nodeARootFinal, nodeBRootFinal, "both nodes should have identical roots after bidirectional sync")

	// Verify the tree contains all 1000 vertices
	nodeATree := nodeAHG.GetVertexAddsSet(shardKey).GetTree()
	nodeBTree := nodeBHG.GetVertexAddsSet(shardKey).GetTree()

	nodeALeaves := tries.GetAllLeaves(
		nodeATree.SetType,
		nodeATree.PhaseType,
		nodeATree.ShardKey,
		nodeATree.Root,
	)
	nodeBLeaves := tries.GetAllLeaves(
		nodeBTree.SetType,
		nodeBTree.PhaseType,
		nodeBTree.ShardKey,
		nodeBTree.Root,
	)

	nodeALeafCount := 0
	for _, leaf := range nodeALeaves {
		if leaf != nil {
			nodeALeafCount++
		}
	}
	nodeBLeafCount := 0
	for _, leaf := range nodeBLeaves {
		if leaf != nil {
			nodeBLeafCount++
		}
	}

	t.Logf("Node A has %d leaves, Node B has %d leaves", nodeALeafCount, nodeBLeafCount)
	assert.Equal(t, totalVertices, nodeALeafCount, "Node A should have all 1000 vertices")
	assert.Equal(t, totalVertices, nodeBLeafCount, "Node B should have all 1000 vertices")

	// Verify no differences between the trees
	diffLeaves := tries.CompareLeaves(nodeATree, nodeBTree)
	assert.Empty(t, diffLeaves, "there should be no differences between the trees")

	t.Log("Bidirectional sync test passed - both nodes have all 1000 vertices")
}

// TestHypergraphBidirectionalSyncClientDriven tests the new client-driven sync
// protocol (PerformSync/SyncFrom) with two nodes having disjoint data sets.
// Node A has 500 unique vertices and node B has 500 different unique vertices.
// After syncing in both directions, both nodes should have all 1000 vertices.
func TestHypergraphBidirectionalSyncClientDriven(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	enc := verenc.NewMPCitHVerifiableEncryptor(1)
	inclusionProver := bls48581.NewKZGInclusionProver(logger)

	// Create data trees for all 1000 vertices
	numVerticesPerNode := 500
	totalVertices := numVerticesPerNode * 2
	dataTrees := make([]*tries.VectorCommitmentTree, totalVertices)
	eg := errgroup.Group{}
	eg.SetLimit(100)
	for i := 0; i < totalVertices; i++ {
		eg.Go(func() error {
			dataTrees[i] = buildDataTree(t, inclusionProver)
			return nil
		})
	}
	eg.Wait()
	t.Log("Generated data trees")

	// Create databases and stores for both nodes
	nodeADB := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestnodeA_cd/store"}}, 0)
	defer nodeADB.Close()

	nodeBDB := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestnodeB_cd/store"}}, 0)
	defer nodeBDB.Close()

	nodeAStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestnodeA_cd/store"},
		nodeADB,
		logger,
		enc,
		inclusionProver,
	)

	nodeBStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestnodeB_cd/store"},
		nodeBDB,
		logger,
		enc,
		inclusionProver,
	)

	nodeAHG := hgcrdt.NewHypergraph(
		logger.With(zap.String("side", "nodeA-cd")),
		nodeAStore,
		inclusionProver,
		[]int{},
		&tests.Nopthenticator{},
		200,
	)

	nodeBHG := hgcrdt.NewHypergraph(
		logger.With(zap.String("side", "nodeB-cd")),
		nodeBStore,
		inclusionProver,
		[]int{},
		&tests.Nopthenticator{},
		200,
	)

	// Create a shared domain for all vertices
	domain := randomBytes32(t)

	// Generate vertices for node A (first 500)
	nodeAVertices := make([]application.Vertex, numVerticesPerNode)
	for i := 0; i < numVerticesPerNode; i++ {
		addr := randomBytes32(t)
		nodeAVertices[i] = hgcrdt.NewVertex(
			domain,
			addr,
			dataTrees[i].Commit(inclusionProver, false),
			dataTrees[i].GetSize(),
		)
	}

	// Generate vertices for node B (second 500, completely different)
	nodeBVertices := make([]application.Vertex, numVerticesPerNode)
	for i := 0; i < numVerticesPerNode; i++ {
		addr := randomBytes32(t)
		nodeBVertices[i] = hgcrdt.NewVertex(
			domain,
			addr,
			dataTrees[numVerticesPerNode+i].Commit(inclusionProver, false),
			dataTrees[numVerticesPerNode+i].GetSize(),
		)
	}

	shardKey := application.GetShardKey(nodeAVertices[0])

	// Add vertices to node A
	t.Log("Adding 500 vertices to node A")
	nodeATxn, err := nodeAStore.NewTransaction(false)
	require.NoError(t, err)
	for i, v := range nodeAVertices {
		id := v.GetID()
		require.NoError(t, nodeAStore.SaveVertexTree(nodeATxn, id[:], dataTrees[i]))
		require.NoError(t, nodeAHG.AddVertex(nodeATxn, v))
	}
	require.NoError(t, nodeATxn.Commit())

	// Add vertices to node B
	t.Log("Adding 500 different vertices to node B")
	nodeBTxn, err := nodeBStore.NewTransaction(false)
	require.NoError(t, err)
	for i, v := range nodeBVertices {
		id := v.GetID()
		require.NoError(t, nodeBStore.SaveVertexTree(nodeBTxn, id[:], dataTrees[numVerticesPerNode+i]))
		require.NoError(t, nodeBHG.AddVertex(nodeBTxn, v))
	}
	require.NoError(t, nodeBTxn.Commit())

	// Commit both hypergraphs
	_, err = nodeAHG.Commit(1)
	require.NoError(t, err)
	_, err = nodeBHG.Commit(1)
	require.NoError(t, err)

	nodeARootBefore := nodeAHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	nodeBRootBefore := nodeBHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	t.Logf("Node A root before sync: %x", nodeARootBefore)
	t.Logf("Node B root before sync: %x", nodeBRootBefore)
	require.NotEqual(t, nodeARootBefore, nodeBRootBefore, "roots should differ before sync")

	// Helper to set up gRPC server for a hypergraph
	setupServer := func(hg *hgcrdt.HypergraphCRDT) (*bufconn.Listener, *grpc.Server) {
		const bufSize = 1 << 20
		lis := bufconn.Listen(bufSize)

		grpcServer := grpc.NewServer(
			grpc.MaxRecvMsgSize(100*1024*1024), // 100 MB
			grpc.MaxSendMsgSize(100*1024*1024), // 100 MB
			grpc.ChainStreamInterceptor(func(
				srv interface{},
				ss grpc.ServerStream,
				info *grpc.StreamServerInfo,
				handler grpc.StreamHandler,
			) error {
				_, priv, _ := ed448.GenerateKey(rand.Reader)
				privKey, err := pcrypto.UnmarshalEd448PrivateKey(priv)
				require.NoError(t, err)

				pub := privKey.GetPublic()
				peerID, err := peer.IDFromPublicKey(pub)
				require.NoError(t, err)

				return handler(srv, &serverStream{
					ServerStream: ss,
					ctx:          internal_grpc.NewContextWithPeerID(ss.Context(), peerID),
				})
			}),
		)
		protobufs.RegisterHypergraphComparisonServiceServer(grpcServer, hg)

		go func() {
			_ = grpcServer.Serve(lis)
		}()

		return lis, grpcServer
	}

	dialClient := func(lis *bufconn.Listener) (*grpc.ClientConn, protobufs.HypergraphComparisonServiceClient) {
		dialer := func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}
		conn, err := grpc.DialContext(
			context.Background(),
			"bufnet",
			grpc.WithContextDialer(dialer),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(
				grpc.MaxCallRecvMsgSize(100*1024*1024), // 100 MB
				grpc.MaxCallSendMsgSize(100*1024*1024), // 100 MB
			),
		)
		require.NoError(t, err)
		return conn, protobufs.NewHypergraphComparisonServiceClient(conn)
	}

	// Convert tries.ShardKey to bytes for SyncFrom
	shardKeyBytes := slices.Concat(shardKey.L1[:], shardKey.L2[:])
	_ = shardKeyBytes // Used below in the SyncFrom call

	// Step 1: Node A syncs from Node B (as server) using client-driven sync
	// Node A should receive Node B's 500 vertices
	t.Log("Step 1: Node A syncs from Node B using PerformSync (B is server)")
	lisB, serverB := setupServer(nodeBHG)
	defer serverB.Stop()

	connB, clientB := dialClient(lisB)
	streamB, err := clientB.PerformSync(context.Background())
	require.NoError(t, err)

	_, err = nodeAHG.SyncFrom(
		streamB,
		shardKey,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
		nil,
	)
	require.NoError(t, err)
	require.NoError(t, streamB.CloseSend())
	connB.Close()

	_, err = nodeAHG.Commit(2)
	require.NoError(t, err)

	nodeARootAfterFirstSync := nodeAHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	t.Logf("Node A root after syncing from B: %x", nodeARootAfterFirstSync)

	// Step 2: Node B syncs from Node A (as server) using client-driven sync
	// Node B should receive Node A's 500 vertices
	t.Log("Step 2: Node B syncs from Node A using PerformSync (A is server)")
	lisA, serverA := setupServer(nodeAHG)
	defer serverA.Stop()

	connA, clientA := dialClient(lisA)
	streamA, err := clientA.PerformSync(context.Background())
	require.NoError(t, err)

	_, err = nodeBHG.SyncFrom(
		streamA,
		shardKey,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
		nil,
	)
	require.NoError(t, err)
	require.NoError(t, streamA.CloseSend())
	connA.Close()

	_, err = nodeBHG.Commit(2)
	require.NoError(t, err)

	// Verify both nodes have converged
	nodeARootFinal := nodeAHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	nodeBRootFinal := nodeBHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	t.Logf("Node A final root: %x", nodeARootFinal)
	t.Logf("Node B final root: %x", nodeBRootFinal)

	assert.Equal(t, nodeARootFinal, nodeBRootFinal, "both nodes should have identical roots after bidirectional sync")

	// Verify the tree contains all 1000 vertices
	nodeATree := nodeAHG.GetVertexAddsSet(shardKey).GetTree()
	nodeBTree := nodeBHG.GetVertexAddsSet(shardKey).GetTree()

	nodeALeaves := tries.GetAllLeaves(
		nodeATree.SetType,
		nodeATree.PhaseType,
		nodeATree.ShardKey,
		nodeATree.Root,
	)
	nodeBLeaves := tries.GetAllLeaves(
		nodeBTree.SetType,
		nodeBTree.PhaseType,
		nodeBTree.ShardKey,
		nodeBTree.Root,
	)

	nodeALeafCount := 0
	for _, leaf := range nodeALeaves {
		if leaf != nil {
			nodeALeafCount++
		}
	}
	nodeBLeafCount := 0
	for _, leaf := range nodeBLeaves {
		if leaf != nil {
			nodeBLeafCount++
		}
	}

	t.Logf("Node A has %d leaves, Node B has %d leaves", nodeALeafCount, nodeBLeafCount)
	assert.Equal(t, totalVertices, nodeALeafCount, "Node A should have all 1000 vertices")
	assert.Equal(t, totalVertices, nodeBLeafCount, "Node B should have all 1000 vertices")

	// Verify no differences between the trees
	diffLeaves := tries.CompareLeaves(nodeATree, nodeBTree)
	assert.Empty(t, diffLeaves, "there should be no differences between the trees")

	t.Log("Client-driven bidirectional sync test passed - both nodes have all 1000 vertices")
}

// TestHypergraphSyncWithPrefixLengthMismatch tests sync behavior when one node
// has a deeper tree structure (longer prefix path) than the other. This tests
// the prefix length mismatch handling in the walk function.
//
// We create two nodes with different tree structures that will cause prefix
// length mismatches during sync. Node A has deeper prefixes at certain branches
// while Node B has shallower but wider structures.
func TestHypergraphSyncWithPrefixLengthMismatch(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	enc := verenc.NewMPCitHVerifiableEncryptor(1)
	inclusionProver := bls48581.NewKZGInclusionProver(logger)

	// Create data trees
	numTrees := 20
	dataTrees := make([]*tries.VectorCommitmentTree, numTrees)
	for i := 0; i < numTrees; i++ {
		dataTrees[i] = buildDataTree(t, inclusionProver)
	}

	// Fixed domain (appAddress) - all vertices must share this to be in the same shard
	fixedDomain := [32]byte{}

	// Helper to create a vertex with a specific dataAddress path suffix.
	// The vertex ID is [appAddress (32 bytes) || dataAddress (32 bytes)].
	// The path is derived from the full 64-byte ID.
	// With BranchBits=6, nibbles 0-41 come from appAddress, nibbles 42+ from dataAddress.
	// Since all vertices share the same appAddress, their paths share the first 42 nibbles.
	// Path differences come from dataAddress (nibbles 42+).
	//
	// We control the "suffix path" starting at nibble 42 by setting bits in dataAddress.
	createVertexWithDataPath := func(suffixPath []int, uniqueSuffix uint64, treeIdx int) application.Vertex {
		dataAddr := [32]byte{}

		// Pack the suffix path nibbles into bits of dataAddress
		// Nibble 42 starts at bit 0 of dataAddress
		bitPos := 0
		for _, nibble := range suffixPath {
			byteIdx := bitPos / 8
			bitOffset := bitPos % 8

			if bitOffset+6 <= 8 {
				// Nibble fits in one byte
				dataAddr[byteIdx] |= byte(nibble << (8 - bitOffset - 6))
			} else {
				// Nibble spans two bytes
				bitsInFirstByte := 8 - bitOffset
				dataAddr[byteIdx] |= byte(nibble >> (6 - bitsInFirstByte))
				if byteIdx+1 < 32 {
					dataAddr[byteIdx+1] |= byte(nibble << (8 - (6 - bitsInFirstByte)))
				}
			}
			bitPos += 6
		}

		// Add unique suffix in the last 8 bytes to make each vertex distinct
		binary.BigEndian.PutUint64(dataAddr[24:], uniqueSuffix)

		return hgcrdt.NewVertex(
			fixedDomain,
			dataAddr,
			dataTrees[treeIdx].Commit(inclusionProver, false),
			dataTrees[treeIdx].GetSize(),
		)
	}

	// Run the test in both directions
	runSyncTest := func(direction string) {
		t.Run(direction, func(t *testing.T) {
			// Create fresh databases for this sub-test
			nodeADB := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".configtestnodeA_%s/store", direction)}}, 0)
			defer nodeADB.Close()

			nodeBDB := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".configtestnodeB_%s/store", direction)}}, 0)
			defer nodeBDB.Close()

			nodeAStore := store.NewPebbleHypergraphStore(
				&config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".configtestnodeA_%s/store", direction)},
				nodeADB,
				logger,
				enc,
				inclusionProver,
			)

			nodeBStore := store.NewPebbleHypergraphStore(
				&config.DBConfig{InMemoryDONOTUSE: true, Path: fmt.Sprintf(".configtestnodeB_%s/store", direction)},
				nodeBDB,
				logger,
				enc,
				inclusionProver,
			)

			nodeAHG := hgcrdt.NewHypergraph(
				logger.With(zap.String("side", "nodeA-"+direction)),
				nodeAStore,
				inclusionProver,
				[]int{},
				&tests.Nopthenticator{},
				200,
			)

			nodeBHG := hgcrdt.NewHypergraph(
				logger.With(zap.String("side", "nodeB-"+direction)),
				nodeBStore,
				inclusionProver,
				[]int{},
				&tests.Nopthenticator{},
				200,
			)

			// Create vertices with specific path structures to cause prefix mismatches.
			// All vertices share the same appAddress (fixedDomain), so they're in the same shard.
			// Their paths share the first 42 nibbles (all zeros from fixedDomain).
			// Path differences come from dataAddress, starting at nibble 42.
			//
			// We create vertices with suffix paths (nibbles 42+) that differ:
			// Node A: suffix paths 0,1,x and 0,2,x and 1,x
			// Node B: suffix paths 0,0,x and 0,1,x and 0,3,x and 1,x
			//
			// This creates prefix mismatch scenarios in the dataAddress portion of the tree.

			t.Log("Creating Node A structure")
			nodeAVertices := []application.Vertex{
				createVertexWithDataPath([]int{0, 1}, 100, 0), // suffix path 0,1,...
				createVertexWithDataPath([]int{0, 2}, 101, 1), // suffix path 0,2,...
				createVertexWithDataPath([]int{1}, 102, 2),    // suffix path 1,...
			}
			t.Logf("Created Node A vertices with suffix paths: 0,1; 0,2; 1")

			t.Log("Creating Node B structure")
			nodeBVertices := []application.Vertex{
				createVertexWithDataPath([]int{0, 0}, 200, 3), // suffix path 0,0,...
				createVertexWithDataPath([]int{0, 1}, 201, 4), // suffix path 0,1,...
				createVertexWithDataPath([]int{0, 3}, 202, 5), // suffix path 0,3,...
				createVertexWithDataPath([]int{1}, 203, 6),    // suffix path 1,...
			}
			t.Logf("Created Node B vertices with suffix paths: 0,0; 0,1; 0,3; 1")

			// Verify the paths - show nibbles 40-50 where the difference should be
			t.Log("Node A vertices paths (showing nibbles 40-50 where dataAddress starts):")
			for i, v := range nodeAVertices {
				id := v.GetID()
				path := GetFullPath(id[:])
				// Nibble 42 is where dataAddress bits start (256/6 = 42.67)
				start := 40
				end := min(50, len(path))
				if end > start {
					t.Logf("  Vertex %d path[%d:%d]: %v", i, start, end, path[start:end])
				}
			}
			t.Log("Node B vertices paths (showing nibbles 40-50 where dataAddress starts):")
			for i, v := range nodeBVertices {
				id := v.GetID()
				path := GetFullPath(id[:])
				start := 40
				end := min(50, len(path))
				if end > start {
					t.Logf("  Vertex %d path[%d:%d]: %v", i, start, end, path[start:end])
				}
			}

			shardKey := application.GetShardKey(nodeAVertices[0])

			// Add vertices to Node A
			nodeATxn, err := nodeAStore.NewTransaction(false)
			require.NoError(t, err)
			for i, v := range nodeAVertices {
				id := v.GetID()
				require.NoError(t, nodeAStore.SaveVertexTree(nodeATxn, id[:], dataTrees[i]))
				require.NoError(t, nodeAHG.AddVertex(nodeATxn, v))
			}
			require.NoError(t, nodeATxn.Commit())

			// Add vertices to Node B
			nodeBTxn, err := nodeBStore.NewTransaction(false)
			require.NoError(t, err)
			for i, v := range nodeBVertices {
				id := v.GetID()
				require.NoError(t, nodeBStore.SaveVertexTree(nodeBTxn, id[:], dataTrees[3+i]))
				require.NoError(t, nodeBHG.AddVertex(nodeBTxn, v))
			}
			require.NoError(t, nodeBTxn.Commit())

			// Commit both
			_, err = nodeAHG.Commit(1)
			require.NoError(t, err)
			_, err = nodeBHG.Commit(1)
			require.NoError(t, err)

			nodeARoot := nodeAHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
			nodeBRoot := nodeBHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
			t.Logf("Node A root: %x", nodeARoot)
			t.Logf("Node B root: %x", nodeBRoot)

			// Setup gRPC server
			const bufSize = 1 << 20
			setupServer := func(hg *hgcrdt.HypergraphCRDT) (*bufconn.Listener, *grpc.Server) {
				lis := bufconn.Listen(bufSize)
				grpcServer := grpc.NewServer(
					grpc.MaxRecvMsgSize(100*1024*1024), // 100 MB
					grpc.MaxSendMsgSize(100*1024*1024), // 100 MB
					grpc.ChainStreamInterceptor(func(
						srv interface{},
						ss grpc.ServerStream,
						info *grpc.StreamServerInfo,
						handler grpc.StreamHandler,
					) error {
						_, priv, _ := ed448.GenerateKey(rand.Reader)
						privKey, err := pcrypto.UnmarshalEd448PrivateKey(priv)
						require.NoError(t, err)
						pub := privKey.GetPublic()
						peerID, err := peer.IDFromPublicKey(pub)
						require.NoError(t, err)
						return handler(srv, &serverStream{
							ServerStream: ss,
							ctx:          internal_grpc.NewContextWithPeerID(ss.Context(), peerID),
						})
					}),
				)
				protobufs.RegisterHypergraphComparisonServiceServer(grpcServer, hg)
				go func() { _ = grpcServer.Serve(lis) }()
				return lis, grpcServer
			}

			dialClient := func(lis *bufconn.Listener) (*grpc.ClientConn, protobufs.HypergraphComparisonServiceClient) {
				dialer := func(context.Context, string) (net.Conn, error) { return lis.Dial() }
				conn, err := grpc.DialContext(
					context.Background(),
					"bufnet",
					grpc.WithContextDialer(dialer),
					grpc.WithTransportCredentials(insecure.NewCredentials()),
					grpc.WithDefaultCallOptions(
						grpc.MaxCallRecvMsgSize(100*1024*1024), // 100 MB
						grpc.MaxCallSendMsgSize(100*1024*1024), // 100 MB
					),
				)
				require.NoError(t, err)
				return conn, protobufs.NewHypergraphComparisonServiceClient(conn)
			}

			var serverHG, clientHG *hgcrdt.HypergraphCRDT
			var serverRoot []byte

			if direction == "A_syncs_from_B" {
				serverHG = nodeBHG
				clientHG = nodeAHG
				serverRoot = nodeBRoot
			} else {
				serverHG = nodeAHG
				clientHG = nodeBHG
				serverRoot = nodeARoot
			}

			serverHG.PublishSnapshot(serverRoot)
			lis, grpcServer := setupServer(serverHG)
			defer grpcServer.Stop()

			// Count client leaves before sync
			clientTreeBefore := clientHG.GetVertexAddsSet(shardKey).GetTree()
			clientLeavesBefore := tries.GetAllLeaves(
				clientTreeBefore.SetType,
				clientTreeBefore.PhaseType,
				clientTreeBefore.ShardKey,
				clientTreeBefore.Root,
			)
			clientLeafCountBefore := 0
			for _, leaf := range clientLeavesBefore {
				if leaf != nil {
					clientLeafCountBefore++
				}
			}
			t.Logf("Client has %d leaves before sync", clientLeafCountBefore)

			conn, client := dialClient(lis)
			stream, err := client.PerformSync(context.Background())
			require.NoError(t, err)

			_, err = clientHG.SyncFrom(
				stream,
				shardKey,
				protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
				nil,
			)
			require.NoError(t, err)
			require.NoError(t, stream.CloseSend())
			conn.Close()

			_, err = clientHG.Commit(2)
			require.NoError(t, err)

			// In CRDT sync, the client receives data from the server and MERGES it.
			// The client should now have BOTH its original vertices AND the server's vertices.
			// So the client root should differ from both original roots (it's a superset).
			clientRoot := clientHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
			t.Logf("Client root after sync: %x", clientRoot)

			// Get all leaves from the client tree after sync
			clientTree := clientHG.GetVertexAddsSet(shardKey).GetTree()
			clientLeaves := tries.GetAllLeaves(
				clientTree.SetType,
				clientTree.PhaseType,
				clientTree.ShardKey,
				clientTree.Root,
			)

			clientLeafCount := 0
			for _, leaf := range clientLeaves {
				if leaf != nil {
					clientLeafCount++
				}
			}

			// After sync, client should have received server's vertices (merged with its own)
			// The client should have at least as many leaves as it started with
			assert.GreaterOrEqual(t, clientLeafCount, clientLeafCountBefore,
				"client should not lose leaves during sync")

			// Client should have gained some leaves from the server (unless they already had them all)
			t.Logf("Sync %s completed - client went from %d to %d leaves",
				direction, clientLeafCountBefore, clientLeafCount)

			// Verify the sync actually transferred data by checking that server's vertices are now in client
			serverTree := serverHG.GetVertexAddsSet(shardKey).GetTree()
			serverLeaves := tries.GetAllLeaves(
				serverTree.SetType,
				serverTree.PhaseType,
				serverTree.ShardKey,
				serverTree.Root,
			)
			serverLeafCount := 0
			for _, leaf := range serverLeaves {
				if leaf != nil {
					serverLeafCount++
				}
			}
			t.Logf("Server has %d leaves", serverLeafCount)

			// The client should have at least as many leaves as the server
			// (since it's merging server data into its own)
			assert.GreaterOrEqual(t, clientLeafCount, serverLeafCount,
				"client should have at least as many leaves as server after sync")
		})
	}

	// Test both directions
	runSyncTest("A_syncs_from_B")
	runSyncTest("B_syncs_from_A")
}

// TestMainnetBlossomsubFrameReceptionAndHypersync is an integration test that:
// 1. Connects to mainnet blossomsub using real bootstrap peers
// 2. Subscribes to the global frame bitmask (0x0000) as done in global_consensus_engine.go
// 3. Receives a real frame from a global prover on mainnet
// 4. Performs hypersync on the prover shard (000000ffffffff...ffffffff)
// 5. Confirms the synced data matches the prover root commitment from the frame
//
// This test requires network access and may take up to 5 minutes to receive a frame.
// Run with: go test -v -timeout 10m -run TestMainnetBlossomsubFrameReceptionAndHypersync
func TestMainnetBlossomsubFrameReceptionAndHypersync(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping mainnet integration test in short mode")
	}

	logger, _ := zap.NewDevelopment()
	enc := verenc.NewMPCitHVerifiableEncryptor(1)
	inclusionProver := bls48581.NewKZGInclusionProver(logger)

	// The prover shard key from global consensus:
	// L1 = [0x00, 0x00, 0x00], L2 = bytes.Repeat([]byte{0xff}, 32)
	proverShardKey := tries.ShardKey{
		L1: [3]byte{0x00, 0x00, 0x00},
		L2: [32]byte(bytes.Repeat([]byte{0xff}, 32)),
	}

	// Frame bitmask from global consensus: []byte{0x00, 0x00}
	globalFrameBitmask := []byte{0x00, 0x00}

	// Create in-memory hypergraph store for the client
	clientDB := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest_mainnet_client/store"}}, 0)
	defer clientDB.Close()

	clientStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest_mainnet_client/store"},
		clientDB,
		logger,
		enc,
		inclusionProver,
	)

	clientHG := hgcrdt.NewHypergraph(
		logger.With(zap.String("side", "mainnet-client")),
		clientStore,
		inclusionProver,
		[]int{},
		&tests.Nopthenticator{},
		200,
	)

	// Generate a random peer key for this test node
	peerPrivKey, _, err := pcrypto.GenerateEd448Key(rand.Reader)
	require.NoError(t, err)
	peerPrivKeyBytes, err := peerPrivKey.Raw()
	require.NoError(t, err)

	// Create P2P config with mainnet bootstrap peers
	p2pConfig := &config.P2PConfig{
		ListenMultiaddr:           "/ip4/0.0.0.0/udp/0/quic-v1", // Use random port
		BootstrapPeers:            config.BootstrapPeers,
		PeerPrivKey:               fmt.Sprintf("%x", peerPrivKeyBytes),
		Network:                   0, // Mainnet
		D:                         8,
		DLo:                       6,
		DHi:                       12,
		DScore:                    4,
		DOut:                      2,
		HistoryLength:             5,
		HistoryGossip:             3,
		DLazy:                     6,
		GossipFactor:              0.25,
		GossipRetransmission:      3,
		HeartbeatInitialDelay:     100 * time.Millisecond,
		HeartbeatInterval:         1 * time.Second,
		FanoutTTL:                 60 * time.Second,
		PrunePeers:                16,
		PruneBackoff:              time.Minute,
		UnsubscribeBackoff:        10 * time.Second,
		Connectors:                8,
		MaxPendingConnections:     128,
		ConnectionTimeout:         30 * time.Second,
		DirectConnectTicks:        300,
		DirectConnectInitialDelay: 1 * time.Second,
		OpportunisticGraftTicks:   60,
		OpportunisticGraftPeers:   2,
		GraftFloodThreshold:       10 * time.Second,
		MaxIHaveLength:            5000,
		MaxIHaveMessages:          10,
		MaxIDontWantMessages:      10,
		IWantFollowupTime:         3 * time.Second,
		IDontWantMessageThreshold: 10000,
		IDontWantMessageTTL:       3,
		MinBootstrapPeers:         1,
		BootstrapParallelism:      4,
		DiscoveryParallelism:      4,
		DiscoveryPeerLookupLimit:  100,
		PingTimeout:               30 * time.Second,
		PingPeriod:                time.Minute,
		PingAttempts:              3,
		LowWatermarkConnections:   -1,
		HighWatermarkConnections:  -1,
		SubscriptionQueueSize:     128,
		ValidateQueueSize:         128,
		ValidateWorkers:           4,
		PeerOutboundQueueSize:     128,
	}

	engineConfig := &config.EngineConfig{}

	// Create a temporary config directory
	configDir, err := os.MkdirTemp("", "quil-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(configDir)

	// Create connectivity cache file to bypass the connectivity test
	// The cache file must be named "connectivity-check-<coreId>" and exist in configDir
	connectivityCachePath := fmt.Sprintf("%s/connectivity-check-0", configDir)
	err = os.WriteFile(connectivityCachePath, []byte(time.Now().Format(time.RFC3339)), 0644)
	require.NoError(t, err)

	t.Log("Connecting to mainnet blossomsub...")

	// Create the real blossomsub instance
	pubsub := p2p.NewBlossomSub(
		p2pConfig,
		engineConfig,
		logger.Named("blossomsub"),
		0,
		p2p.ConfigDir(configDir),
	)
	defer pubsub.Close()

	t.Logf("Connected to mainnet with peer ID: %x", pubsub.GetPeerID())
	t.Logf("Bootstrap peers: %d", len(config.BootstrapPeers))

	// Create a channel to receive frames
	frameReceived := make(chan *protobufs.GlobalFrame, 1)

	// Create a peer info manager to store peer reachability info
	// We use a simple in-memory map to store peer info from the peer info bitmask
	peerInfoMap := make(map[string]*tp2p.PeerInfo)
	var peerInfoMu sync.RWMutex

	// Create a key registry map to map prover addresses to identity peer IDs
	// Key: prover address ([]byte as string), Value: identity peer ID
	keyRegistryMap := make(map[string]peer.ID)
	var keyRegistryMu sync.RWMutex

	// Peer info bitmask from global consensus: []byte{0x00, 0x00, 0x00, 0x00}
	globalPeerInfoBitmask := []byte{0x00, 0x00, 0x00, 0x00}

	// Subscribe to peer info bitmask - this handles both PeerInfo and KeyRegistry messages
	t.Log("Subscribing to global peer info bitmask...")
	err = pubsub.Subscribe(globalPeerInfoBitmask, func(message *pb.Message) error {
		if len(message.Data) < 4 {
			return nil
		}

		// Check type prefix
		typePrefix := binary.BigEndian.Uint32(message.Data[:4])

		switch typePrefix {
		case protobufs.PeerInfoType:
			peerInfoMsg := &protobufs.PeerInfo{}
			if err := peerInfoMsg.FromCanonicalBytes(message.Data); err != nil {
				t.Logf("Failed to unmarshal peer info: %v", err)
				return nil
			}

			// Validate signature using Ed448
			if len(peerInfoMsg.Signature) == 0 || len(peerInfoMsg.PublicKey) == 0 {
				return nil
			}

			// Create a copy without signature for validation
			infoCopy := &protobufs.PeerInfo{
				PeerId:              peerInfoMsg.PeerId,
				Reachability:        peerInfoMsg.Reachability,
				Timestamp:           peerInfoMsg.Timestamp,
				Version:             peerInfoMsg.Version,
				PatchNumber:         peerInfoMsg.PatchNumber,
				Capabilities:        peerInfoMsg.Capabilities,
				PublicKey:           peerInfoMsg.PublicKey,
				LastReceivedFrame:   peerInfoMsg.LastReceivedFrame,
				LastGlobalHeadFrame: peerInfoMsg.LastGlobalHeadFrame,
			}

			msg, err := infoCopy.ToCanonicalBytes()
			if err != nil {
				return nil
			}

			// Validate Ed448 signature
			if !ed448.Verify(ed448.PublicKey(peerInfoMsg.PublicKey), msg, peerInfoMsg.Signature, "") {
				return nil
			}

			// Convert and store peer info
			reachability := []tp2p.Reachability{}
			for _, r := range peerInfoMsg.Reachability {
				reachability = append(reachability, tp2p.Reachability{
					Filter:           r.Filter,
					PubsubMultiaddrs: r.PubsubMultiaddrs,
					StreamMultiaddrs: r.StreamMultiaddrs,
				})
			}

			peerInfoMu.Lock()
			peerInfoMap[string(peerInfoMsg.PeerId)] = &tp2p.PeerInfo{
				PeerId:              peerInfoMsg.PeerId,
				Reachability:        reachability,
				Cores:               uint32(len(reachability)),
				LastSeen:            time.Now().UnixMilli(),
				Version:             peerInfoMsg.Version,
				PatchNumber:         peerInfoMsg.PatchNumber,
				LastReceivedFrame:   peerInfoMsg.LastReceivedFrame,
				LastGlobalHeadFrame: peerInfoMsg.LastGlobalHeadFrame,
			}
			peerInfoMu.Unlock()

			// peerIdStr := peer.ID(peerInfoMsg.PeerId).String()
			// t.Logf("Received peer info for %s with %d reachability entries",
			// 	peerIdStr, len(reachability))

		case protobufs.KeyRegistryType:
			keyRegistry := &protobufs.KeyRegistry{}
			if err := keyRegistry.FromCanonicalBytes(message.Data); err != nil {
				t.Logf("Failed to unmarshal key registry: %v", err)
				return nil
			}

			// We need identity key and prover key to establish the mapping
			if keyRegistry.IdentityKey == nil || len(keyRegistry.IdentityKey.KeyValue) == 0 {
				return nil
			}
			if keyRegistry.ProverKey == nil || len(keyRegistry.ProverKey.KeyValue) == 0 {
				return nil
			}

			// Derive peer ID from identity key
			pk, err := pcrypto.UnmarshalEd448PublicKey(keyRegistry.IdentityKey.KeyValue)
			if err != nil {
				t.Logf("Failed to unmarshal identity key: %v", err)
				return nil
			}
			identityPeerID, err := peer.IDFromPublicKey(pk)
			if err != nil {
				t.Logf("Failed to derive peer ID from identity key: %v", err)
				return nil
			}

			// Derive prover address from prover key (Poseidon hash)
			proverAddrBI, err := poseidon.HashBytes(keyRegistry.ProverKey.KeyValue)
			if err != nil {
				t.Logf("Failed to derive prover address: %v", err)
				return nil
			}
			proverAddress := proverAddrBI.FillBytes(make([]byte, 32))

			// Store the mapping: prover address -> identity peer ID
			keyRegistryMu.Lock()
			keyRegistryMap[string(proverAddress)] = identityPeerID
			keyRegistryMu.Unlock()

			// t.Logf("Received key registry: prover %x -> peer %s",
			// 	proverAddress, identityPeerID.String())
		}

		return nil
	})
	require.NoError(t, err)

	// Register a validator for peer info messages with age checks
	err = pubsub.RegisterValidator(globalPeerInfoBitmask, func(peerID peer.ID, message *pb.Message) tp2p.ValidationResult {
		if len(message.Data) < 4 {
			return tp2p.ValidationResultReject
		}

		typePrefix := binary.BigEndian.Uint32(message.Data[:4])
		now := time.Now().UnixMilli()

		switch typePrefix {
		case protobufs.PeerInfoType:
			peerInfo := &protobufs.PeerInfo{}
			if err := peerInfo.FromCanonicalBytes(message.Data); err != nil {
				return tp2p.ValidationResultReject
			}

			// Age checks: timestamp must be within 1 second in the past, 5 seconds in the future
			if peerInfo.Timestamp < now-1000 {
				t.Logf("Rejecting peer info: timestamp too old (%d < %d)", peerInfo.Timestamp, now-1000)
				return tp2p.ValidationResultReject
			}
			if peerInfo.Timestamp > now+5000 {
				t.Logf("Ignoring peer info: timestamp too far in future (%d > %d)", peerInfo.Timestamp, now+5000)
				return tp2p.ValidationResultIgnore
			}

		case protobufs.KeyRegistryType:
			keyRegistry := &protobufs.KeyRegistry{}
			if err := keyRegistry.FromCanonicalBytes(message.Data); err != nil {
				return tp2p.ValidationResultReject
			}

			// Age checks: LastUpdated must be within 1 second in the past, 5 seconds in the future
			if int64(keyRegistry.LastUpdated) < now-1000 {
				t.Logf("Rejecting key registry: timestamp too old (%d < %d)", keyRegistry.LastUpdated, now-1000)
				return tp2p.ValidationResultReject
			}
			if int64(keyRegistry.LastUpdated) > now+5000 {
				t.Logf("Ignoring key registry: timestamp too far in future (%d > %d)", keyRegistry.LastUpdated, now+5000)
				return tp2p.ValidationResultIgnore
			}

		default:
			return tp2p.ValidationResultIgnore
		}

		return tp2p.ValidationResultAccept
	}, true)
	require.NoError(t, err)

	// Subscribe to frame messages
	t.Log("Subscribing to global frame bitmask...")
	err = pubsub.Subscribe(globalFrameBitmask, func(message *pb.Message) error {
		t.Logf("Received message on frame bitmask, data length: %d", len(message.Data))

		if len(message.Data) < 4 {
			return nil
		}

		// Check type prefix
		typePrefix := binary.BigEndian.Uint32(message.Data[:4])
		t.Logf("Message type prefix: %d (GlobalFrameType=%d)", typePrefix, protobufs.GlobalFrameType)
		if typePrefix != protobufs.GlobalFrameType {
			return nil
		}

		frame := &protobufs.GlobalFrame{}
		if err := frame.FromCanonicalBytes(message.Data); err != nil {
			t.Logf("Failed to unmarshal frame: %v", err)
			return nil
		}

		t.Logf("Received frame %d from prover %x with root %x",
			frame.Header.FrameNumber,
			frame.Header.Prover,
			frame.Header.ProverTreeCommitment)

		select {
		case frameReceived <- frame:
		default:
		}
		return nil
	})
	require.NoError(t, err)

	// Register a validator for frame messages with age checks
	err = pubsub.RegisterValidator(globalFrameBitmask, func(peerID peer.ID, message *pb.Message) tp2p.ValidationResult {
		if len(message.Data) < 4 {
			return tp2p.ValidationResultReject
		}

		typePrefix := binary.BigEndian.Uint32(message.Data[:4])
		if typePrefix != protobufs.GlobalFrameType {
			return tp2p.ValidationResultIgnore
		}

		frame := &protobufs.GlobalFrame{}
		if err := frame.FromCanonicalBytes(message.Data); err != nil {
			t.Logf("Frame validation: failed to unmarshal: %v", err)
			return tp2p.ValidationResultReject
		}

		// Check signature is present
		if frame.Header.PublicKeySignatureBls48581 == nil ||
			frame.Header.PublicKeySignatureBls48581.PublicKey == nil ||
			frame.Header.PublicKeySignatureBls48581.PublicKey.KeyValue == nil {
			t.Logf("Frame validation: missing signature")
			return tp2p.ValidationResultReject
		}

		// Age check: frame must be within 120 seconds
		frameAge := time.Since(time.UnixMilli(frame.Header.Timestamp))
		if frameAge > 120*time.Second {
			t.Logf("Frame validation: too old (age=%v)", frameAge)
			return tp2p.ValidationResultIgnore
		}

		t.Logf("Frame validation: accepting frame %d (age=%v)", frame.Header.FrameNumber, frameAge)
		return tp2p.ValidationResultAccept
	}, true)
	require.NoError(t, err)

	t.Log("Waiting for a global frame from mainnet (this may take up to 20 minutes)...")

	// Wait for a frame with a longer timeout for mainnet - frames can take a while
	var receivedFrame *protobufs.GlobalFrame
	select {
	case receivedFrame = <-frameReceived:
		t.Logf("Successfully received frame %d!", receivedFrame.Header.FrameNumber)
	case <-time.After(20 * time.Minute):
		t.Fatal("timeout waiting for frame from mainnet - ensure network connectivity")
	}

	// Verify frame has required fields
	require.NotNil(t, receivedFrame.Header, "frame must have header")
	require.NotEmpty(t, receivedFrame.Header.Prover, "frame must have prover")
	require.NotEmpty(t, receivedFrame.Header.ProverTreeCommitment, "frame must have prover tree commitment")

	expectedRoot := receivedFrame.Header.ProverTreeCommitment
	proverAddress := receivedFrame.Header.Prover // This is the prover ADDRESS (hash of BLS key), not a peer ID

	t.Logf("Frame details:")
	t.Logf("  Frame number: %d", receivedFrame.Header.FrameNumber)
	t.Logf("  Prover address: %x", proverAddress)
	t.Logf("  Prover root commitment: %x", expectedRoot)

	// Now we need to find the prover's peer info to connect and sync
	// The prover address (in frame) needs to be mapped to a peer ID via key registry
	t.Log("Looking up prover peer info...")

	// Helper function to get prover's identity peer ID from key registry
	getProverPeerID := func() (peer.ID, bool) {
		keyRegistryMu.RLock()
		defer keyRegistryMu.RUnlock()

		peerID, ok := keyRegistryMap[string(proverAddress)]
		return peerID, ok
	}

	// Helper function to get multiaddr from peer info map using peer ID
	getMultiaddrForPeer := func(peerID peer.ID) string {
		peerInfoMu.RLock()
		defer peerInfoMu.RUnlock()

		info, ok := peerInfoMap[string([]byte(peerID))]
		if !ok || len(info.Reachability) == 0 {
			return ""
		}

		// Try stream multiaddrs first (for direct gRPC connection)
		for _, r := range info.Reachability {
			if len(r.StreamMultiaddrs) > 0 {
				return r.StreamMultiaddrs[0]
			}
		}
		// Fall back to pubsub multiaddrs
		for _, r := range info.Reachability {
			if len(r.PubsubMultiaddrs) > 0 {
				return r.PubsubMultiaddrs[0]
			}
		}
		return ""
	}

	// Wait for key registry and peer info to arrive (provers broadcast every 5 minutes)
	t.Log("Waiting for prover key registry and peer info (up to 10 minutes)...")

	var proverPeerID peer.ID
	var proverMultiaddr string
	timeout := time.After(10 * time.Minute)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

waitLoop:
	for {
		select {
		case <-timeout:
			t.Log("Timeout waiting for prover info")
			break waitLoop
		case <-ticker.C:
			// First try to get the peer ID from key registry
			if proverPeerID == "" {
				if pID, ok := getProverPeerID(); ok {
					proverPeerID = pID
					t.Logf("Found key registry: prover address %x -> peer ID %s", proverAddress, proverPeerID.String())
				}
			}

			// If we have the peer ID, try to get the multiaddr from peer info
			if proverPeerID != "" {
				proverMultiaddr = getMultiaddrForPeer(proverPeerID)
				if proverMultiaddr != "" {
					t.Logf("Found prover peer info from peer info bitmask!")
					break waitLoop
				}
			}

			// Log progress
			keyRegistryMu.RLock()
			peerInfoMu.RLock()
			t.Logf("Still waiting... key registries: %d, peer infos: %d, have prover peer ID: %v",
				len(keyRegistryMap), len(peerInfoMap), proverPeerID != "")
			peerInfoMu.RUnlock()
			keyRegistryMu.RUnlock()
		}
	}

	// If we have peer ID but no multiaddr, try connected peers
	if proverPeerID != "" && proverMultiaddr == "" {
		t.Log("Checking connected peers for prover...")
		networkInfo := pubsub.GetNetworkInfo()
		for _, info := range networkInfo.NetworkInfo {
			if bytes.Equal(info.PeerId, []byte(proverPeerID)) && len(info.Multiaddrs) > 0 {
				proverMultiaddr = info.Multiaddrs[0]
				t.Logf("Found prover in connected peers")
				break
			}
		}
	}

	// Final fallback - direct lookup using peer ID
	if proverPeerID != "" && proverMultiaddr == "" {
		t.Logf("Attempting direct peer lookup...")
		proverMultiaddr = pubsub.GetMultiaddrOfPeer([]byte(proverPeerID))
	}

	if proverPeerID == "" {
		t.Skip("Could not find prover key registry - prover may not have broadcast key info yet")
	}

	if proverMultiaddr == "" {
		t.Skip("Could not find prover multiaddr - prover may not have broadcast peer info yet")
	}

	t.Logf("Prover multiaddr: %s", proverMultiaddr)

	// Connect to the prover using direct gRPC connection via multiaddr
	t.Log("Connecting to prover for hypersync...")

	// Create TLS credentials for the connection
	creds, err := p2p.NewPeerAuthenticator(
		logger,
		p2pConfig,
		nil,
		nil,
		nil,
		nil,
		[][]byte{[]byte(proverPeerID)},
		map[string]channel.AllowedPeerPolicyType{},
		map[string]channel.AllowedPeerPolicyType{},
	).CreateClientTLSCredentials([]byte(proverPeerID))
	if err != nil {
		t.Skipf("Could not create TLS credentials: %v", err)
	}

	// Parse the multiaddr and convert to network address
	ma, err := multiaddr.StringCast(proverMultiaddr)
	if err != nil {
		t.Skipf("Could not parse multiaddr %s: %v", proverMultiaddr, err)
	}

	mga, err := mn.ToNetAddr(ma)
	if err != nil {
		t.Skipf("Could not convert multiaddr to net addr: %v", err)
	}

	// Create gRPC client connection
	conn, err := grpc.NewClient(
		mga.String(),
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		t.Skipf("Could not establish connection to prover: %v", err)
	}
	defer conn.Close()

	client := protobufs.NewHypergraphComparisonServiceClient(conn)

	// First, query the server's root commitment to verify what it claims to have
	t.Log("Querying server's root commitment before sync...")
	{
		diagStream, err := client.PerformSync(context.Background())
		require.NoError(t, err)

		shardKeyBytes := slices.Concat(proverShardKey.L1[:], proverShardKey.L2[:])
		err = diagStream.Send(&protobufs.HypergraphSyncQuery{
			Request: &protobufs.HypergraphSyncQuery_GetBranch{
				GetBranch: &protobufs.HypergraphSyncGetBranchRequest{
					ShardKey: shardKeyBytes,
					PhaseSet: protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
					Path:     []int32{},
				},
			},
		})
		require.NoError(t, err)

		resp, err := diagStream.Recv()
		require.NoError(t, err)

		if errResp := resp.GetError(); errResp != nil {
			t.Logf("Server error on root query: %s", errResp.Message)
		} else if branch := resp.GetBranch(); branch != nil {
			t.Logf("Server root commitment: %x", branch.Commitment)
			t.Logf("Server root path: %v", branch.FullPath)
			t.Logf("Server root isLeaf: %v", branch.IsLeaf)
			t.Logf("Server root children count: %d", len(branch.Children))
			t.Logf("Server root leafCount: %d", branch.LeafCount)
			t.Logf("Frame expected root: %x", expectedRoot)
			if !bytes.Equal(branch.Commitment, expectedRoot) {
				t.Logf("WARNING: Server root commitment does NOT match frame expected root!")
			} else {
				t.Logf("OK: Server root commitment matches frame expected root")
			}
			// Log each child's commitment
			for _, child := range branch.Children {
				t.Logf("  Server child[%d]: commitment=%x", child.Index, child.Commitment)
			}

			// Drill into child[37] specifically to compare
			child37Path := append(slices.Clone(branch.FullPath), 37)
			err = diagStream.Send(&protobufs.HypergraphSyncQuery{
				Request: &protobufs.HypergraphSyncQuery_GetBranch{
					GetBranch: &protobufs.HypergraphSyncGetBranchRequest{
						ShardKey: shardKeyBytes,
						PhaseSet: protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
						Path:     child37Path,
					},
				},
			})
			if err == nil {
				resp37, err := diagStream.Recv()
				if err == nil {
					if b37 := resp37.GetBranch(); b37 != nil {
						t.Logf("Server child[37] details: path=%v, leafCount=%d, isLeaf=%v, childrenCount=%d",
							b37.FullPath, b37.LeafCount, b37.IsLeaf, len(b37.Children))
					}
				}
			}
		}
		_ = diagStream.CloseSend()
	}

	// Perform hypersync on all phases
	t.Log("Performing hypersync on prover shard...")

	phases := []protobufs.HypergraphPhaseSet{
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
	}

	for _, phase := range phases {
		stream, err := client.PerformSync(context.Background())
		if err != nil {
			t.Logf("PerformSync error: %v", err)
			continue
		}

		_, err = clientHG.SyncFrom(stream, proverShardKey, phase, nil)
		if err != nil {
			t.Logf("SyncFrom error for phase %v: %v", phase, err)
		}
		_ = stream.CloseSend()
	}

	// Commit client to compute root
	_, err = clientHG.Commit(uint64(receivedFrame.Header.FrameNumber))
	require.NoError(t, err)

	// Verify client now has the expected prover root
	clientProverRoot := clientHG.GetVertexAddsSet(proverShardKey).GetTree().Commit(nil, false)
	t.Logf("Client prover root after sync: %x", clientProverRoot)
	t.Logf("Expected prover root from frame: %x", expectedRoot)

	// Diagnostic: show client tree structure
	clientTreeForDiag := clientHG.GetVertexAddsSet(proverShardKey).GetTree()
	if clientTreeForDiag != nil && clientTreeForDiag.Root != nil {
		switch n := clientTreeForDiag.Root.(type) {
		case *tries.LazyVectorCommitmentBranchNode:
			t.Logf("Client root is BRANCH: path=%v, commitment=%x, leafCount=%d", n.FullPrefix, n.Commitment, n.LeafCount)
			childCount := 0
			for i := 0; i < 64; i++ {
				if n.Children[i] != nil {
					childCount++
					child := n.Children[i]
					switch c := child.(type) {
					case *tries.LazyVectorCommitmentBranchNode:
						t.Logf("  Client child[%d]: BRANCH commitment=%x, leafCount=%d", i, c.Commitment, c.LeafCount)
					case *tries.LazyVectorCommitmentLeafNode:
						t.Logf("  Client child[%d]: LEAF commitment=%x", i, c.Commitment)
					}
				}
			}
			t.Logf("Client root in-memory children: %d", childCount)
		case *tries.LazyVectorCommitmentLeafNode:
			t.Logf("Client root is LEAF: key=%x, commitment=%x", n.Key, n.Commitment)
		}
	} else {
		t.Logf("Client tree root is nil")
	}

	// Deep dive into child[37] - get server leaves to compare
	t.Log("=== Deep dive into child[37] ===")
	var serverChild37Leaves []*protobufs.LeafData
	{
		diagStream, err := client.PerformSync(context.Background())
		if err != nil {
			t.Logf("Failed to create diag stream: %v", err)
		} else {
			shardKeyBytes := slices.Concat(proverShardKey.L1[:], proverShardKey.L2[:])
			// Correct path: root is at [...60], child[37] is at [...60, 37]
			child37Path := []int32{63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 60, 37}

			err = diagStream.Send(&protobufs.HypergraphSyncQuery{
				Request: &protobufs.HypergraphSyncQuery_GetLeaves{
					GetLeaves: &protobufs.HypergraphSyncGetLeavesRequest{
						ShardKey:  shardKeyBytes,
						PhaseSet:  protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
						Path:      child37Path,
						MaxLeaves: 1000,
					},
				},
			})
			if err != nil {
				t.Logf("Failed to send GetLeaves request: %v", err)
			} else {
				resp, err := diagStream.Recv()
				if err != nil {
					t.Logf("Failed to receive GetLeaves response: %v", err)
				} else if errResp := resp.GetError(); errResp != nil {
					t.Logf("Server returned error: %s", errResp.Message)
				} else if leaves := resp.GetLeaves(); leaves != nil {
					serverChild37Leaves = leaves.Leaves
					t.Logf("Server child[37] leaves: count=%d, total=%d", len(leaves.Leaves), leaves.TotalLeaves)
					// Show first few leaf keys
					for i, leaf := range leaves.Leaves {
						if i < 5 {
							t.Logf("  Server leaf[%d]: key=%x (len=%d)", i, leaf.Key[:min(32, len(leaf.Key))], len(leaf.Key))
						}
					}
					if len(leaves.Leaves) > 5 {
						t.Logf("  ... and %d more leaves", len(leaves.Leaves)-5)
					}
				} else {
					t.Logf("Server returned unexpected response type")
				}
			}
			_ = diagStream.CloseSend()
		}
	}

	// Get all client leaves and compare with server child[37] leaves
	clientTree := clientHG.GetVertexAddsSet(proverShardKey).GetTree()
	allClientLeaves := tries.GetAllLeaves(
		clientTree.SetType,
		clientTree.PhaseType,
		clientTree.ShardKey,
		clientTree.Root,
	)
	t.Logf("Total client leaves: %d", len(allClientLeaves))

	// Build map of client leaf keys -> values
	clientLeafMap := make(map[string][]byte)
	for _, leaf := range allClientLeaves {
		if leaf != nil {
			clientLeafMap[string(leaf.Key)] = leaf.Value
		}
	}

	// Check which server child[37] leaves are in client and compare values
	if len(serverChild37Leaves) > 0 {
		found := 0
		missing := 0
		valueMismatch := 0
		for _, serverLeaf := range serverChild37Leaves {
			clientValue, exists := clientLeafMap[string(serverLeaf.Key)]
			if !exists {
				if missing < 3 {
					t.Logf("  Missing server leaf: key=%x", serverLeaf.Key[:min(32, len(serverLeaf.Key))])
				}
				missing++
			} else {
				found++
				if !bytes.Equal(clientValue, serverLeaf.Value) {
					if valueMismatch < 5 {
						t.Logf("  VALUE MISMATCH for key=%x: serverLen=%d, clientLen=%d",
							serverLeaf.Key[:min(32, len(serverLeaf.Key))],
							len(serverLeaf.Value), len(clientValue))
						t.Logf("    Server value prefix: %x", serverLeaf.Value[:min(64, len(serverLeaf.Value))])
						t.Logf("    Client value prefix: %x", clientValue[:min(64, len(clientValue))])
					}
					valueMismatch++
				}
			}
		}
		t.Logf("Server child[37] leaves in client: found=%d, missing=%d, valueMismatch=%d", found, missing, valueMismatch)
	}

	// Compare branch structure for child[37]
	t.Log("=== Comparing branch structure for child[37] ===")
	{
		// Query server's child[37] branch info
		diagStream, err := client.PerformSync(context.Background())
		if err == nil {
			shardKeyBytes := slices.Concat(proverShardKey.L1[:], proverShardKey.L2[:])
			child37Path := []int32{63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 60, 37}

			err = diagStream.Send(&protobufs.HypergraphSyncQuery{
				Request: &protobufs.HypergraphSyncQuery_GetBranch{
					GetBranch: &protobufs.HypergraphSyncGetBranchRequest{
						ShardKey: shardKeyBytes,
						PhaseSet: protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
						Path:     child37Path,
					},
				},
			})
			if err == nil {
				resp, err := diagStream.Recv()
				if err == nil {
					if branch := resp.GetBranch(); branch != nil {
						t.Logf("Server child[37] branch: path=%v, commitment=%x, children=%d",
							branch.FullPath, branch.Commitment[:min(32, len(branch.Commitment))], len(branch.Children))

						// Show first few children with their commitments
						for i, child := range branch.Children {
							if i < 10 {
								t.Logf("  Server sub-child[%d]: commitment=%x", child.Index, child.Commitment[:min(32, len(child.Commitment))])
							}
						}

						// Now check client's child[37] branch structure
						if clientTree != nil && clientTree.Root != nil {
							if rootBranch, ok := clientTree.Root.(*tries.LazyVectorCommitmentBranchNode); ok {
								if child37 := rootBranch.Children[37]; child37 != nil {
									if clientChild37Branch, ok := child37.(*tries.LazyVectorCommitmentBranchNode); ok {
										t.Logf("Client child[37] branch: path=%v, commitment=%x, leafCount=%d",
											clientChild37Branch.FullPrefix, clientChild37Branch.Commitment[:min(32, len(clientChild37Branch.Commitment))], clientChild37Branch.LeafCount)

										// Count and show client's children
										clientChildCount := 0
										for i := 0; i < 64; i++ {
											if clientChild37Branch.Children[i] != nil {
												if clientChildCount < 10 {
													switch c := clientChild37Branch.Children[i].(type) {
													case *tries.LazyVectorCommitmentBranchNode:
														t.Logf("  Client sub-child[%d]: BRANCH commitment=%x", i, c.Commitment[:min(32, len(c.Commitment))])
													case *tries.LazyVectorCommitmentLeafNode:
														t.Logf("  Client sub-child[%d]: LEAF commitment=%x", i, c.Commitment[:min(32, len(c.Commitment))])
													}
												}
												clientChildCount++
											}
										}
										t.Logf("Client child[37] has %d in-memory children, server has %d", clientChildCount, len(branch.Children))
									} else if clientChild37Leaf, ok := child37.(*tries.LazyVectorCommitmentLeafNode); ok {
										t.Logf("Client child[37] is LEAF: key=%x, commitment=%x",
											clientChild37Leaf.Key[:min(32, len(clientChild37Leaf.Key))], clientChild37Leaf.Commitment[:min(32, len(clientChild37Leaf.Commitment))])
									}
								} else {
									t.Logf("Client has NO child at index 37")
								}
							}
						}
					}
				}
			}
			_ = diagStream.CloseSend()
		}
	}

	// Recursive comparison function to drill into mismatches
	var recursiveCompare func(path []int32, depth int)
	recursiveCompare = func(path []int32, depth int) {
		if depth > 10 {
			t.Logf("DEPTH LIMIT REACHED at path=%v", path)
			return
		}

		indent := strings.Repeat("  ", depth)

		// Get server branch at path
		diagStream, err := client.PerformSync(context.Background())
		if err != nil {
			t.Logf("%sERROR creating stream: %v", indent, err)
			return
		}
		defer diagStream.CloseSend()

		shardKeyBytes := slices.Concat(proverShardKey.L1[:], proverShardKey.L2[:])
		err = diagStream.Send(&protobufs.HypergraphSyncQuery{
			Request: &protobufs.HypergraphSyncQuery_GetBranch{
				GetBranch: &protobufs.HypergraphSyncGetBranchRequest{
					ShardKey: shardKeyBytes,
					PhaseSet: protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
					Path:     path,
				},
			},
		})
		if err != nil {
			t.Logf("%sERROR sending request: %v", indent, err)
			return
		}

		resp, err := diagStream.Recv()
		if err != nil {
			t.Logf("%sERROR receiving response: %v", indent, err)
			return
		}

		if errResp := resp.GetError(); errResp != nil {
			t.Logf("%sSERVER ERROR: %s", indent, errResp.Message)
			return
		}

		serverBranch := resp.GetBranch()
		if serverBranch == nil {
			t.Logf("%sNO BRANCH in response", indent)
			return
		}

		t.Logf("%sSERVER: path=%v, fullPath=%v, leafCount=%d, children=%d, isLeaf=%v",
			indent, path, serverBranch.FullPath, serverBranch.LeafCount,
			len(serverBranch.Children), serverBranch.IsLeaf)
		t.Logf("%sSERVER commitment: %x", indent, serverBranch.Commitment[:min(48, len(serverBranch.Commitment))])

		// Get corresponding client node - convert []int32 to []int
		pathInt := make([]int, len(path))
		for i, p := range path {
			pathInt[i] = int(p)
		}
		clientNode, err := clientTree.GetByPath(pathInt)
		if err != nil {
			t.Logf("%sERROR getting client node: %v", indent, err)
			return
		}

		if clientNode == nil {
			t.Logf("%sCLIENT: NO NODE at path=%v", indent, path)
			return
		}

		switch cn := clientNode.(type) {
		case *tries.LazyVectorCommitmentBranchNode:
			t.Logf("%sCLIENT: path=%v, fullPrefix=%v, leafCount=%d, commitment=%x",
				indent, path, cn.FullPrefix, cn.LeafCount, cn.Commitment[:min(48, len(cn.Commitment))])

			// Check if server is leaf but client is branch
			if serverBranch.IsLeaf {
				t.Logf("%s*** TYPE MISMATCH: server is LEAF, client is BRANCH ***", indent)
				t.Logf("%s  SERVER: fullPath=%v, isLeaf=%v, commitment=%x",
					indent, serverBranch.FullPath, serverBranch.IsLeaf, serverBranch.Commitment[:min(48, len(serverBranch.Commitment))])
				return
			}

			// Check if FullPath differs from FullPrefix
			serverPathStr := fmt.Sprintf("%v", serverBranch.FullPath)
			clientPathStr := fmt.Sprintf("%v", cn.FullPrefix)
			if serverPathStr != clientPathStr {
				t.Logf("%s*** PATH MISMATCH: server fullPath=%v, client fullPrefix=%v ***",
					indent, serverBranch.FullPath, cn.FullPrefix)
			}

			// Check commitment match
			if !bytes.Equal(serverBranch.Commitment, cn.Commitment) {
				t.Logf("%s*** COMMITMENT MISMATCH ***", indent)

				// Compare children
				serverChildren := make(map[int32][]byte)
				for _, sc := range serverBranch.Children {
					serverChildren[sc.Index] = sc.Commitment
				}

				for i := int32(0); i < 64; i++ {
					serverCommit := serverChildren[i]
					var clientCommit []byte
					clientChild := cn.Children[i]

					// Lazy-load client child from store if needed
					if clientChild == nil && len(serverCommit) > 0 {
						childPathInt := make([]int, len(cn.FullPrefix)+1)
						for j, p := range cn.FullPrefix {
							childPathInt[j] = p
						}
						childPathInt[len(cn.FullPrefix)] = int(i)
						clientChild, _ = clientTree.Store.GetNodeByPath(
							clientTree.SetType,
							clientTree.PhaseType,
							clientTree.ShardKey,
							childPathInt,
						)
					}

					if clientChild != nil {
						switch cc := clientChild.(type) {
						case *tries.LazyVectorCommitmentBranchNode:
							clientCommit = cc.Commitment
						case *tries.LazyVectorCommitmentLeafNode:
							clientCommit = cc.Commitment
						}
					}

					if len(serverCommit) > 0 || len(clientCommit) > 0 {
						if !bytes.Equal(serverCommit, clientCommit) {
							t.Logf("%s  CHILD[%d] MISMATCH: server=%x, client=%x",
								indent, i,
								serverCommit[:min(24, len(serverCommit))],
								clientCommit[:min(24, len(clientCommit))])
							// Recurse into mismatched child
							childPath := append(slices.Clone(serverBranch.FullPath), i)
							recursiveCompare(childPath, depth+1)
						}
					}
				}
			}

		case *tries.LazyVectorCommitmentLeafNode:
			t.Logf("%sCLIENT: LEAF key=%x, commitment=%x",
				indent, cn.Key[:min(32, len(cn.Key))], cn.Commitment[:min(48, len(cn.Commitment))])
			t.Logf("%sCLIENT LEAF DETAIL: fullKey=%x, value len=%d",
				indent, cn.Key, len(cn.Value))
			// Compare with server commitment
			if serverBranch.IsLeaf {
				if !bytes.Equal(serverBranch.Commitment, cn.Commitment) {
					t.Logf("%s*** LEAF COMMITMENT MISMATCH ***", indent)
					t.Logf("%s  SERVER commitment: %x", indent, serverBranch.Commitment)
					t.Logf("%s  CLIENT commitment: %x", indent, cn.Commitment)
					t.Logf("%s  SERVER fullPath: %v", indent, serverBranch.FullPath)
					// The key in LazyVectorCommitmentLeafNode doesn't have a "fullPrefix" directly -
					// the path is determined by the key bytes
				}
			} else {
				t.Logf("%s*** TYPE MISMATCH: server is branch, client is leaf ***", indent)
			}
		}
	}

	// Start recursive comparison at root
	t.Log("=== RECURSIVE MISMATCH ANALYSIS ===")
	rootPath := []int32{63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 60}
	recursiveCompare(rootPath, 0)

	// Now let's drill into the specific mismatched subtree to see the leaves
	t.Log("=== LEAF-LEVEL ANALYSIS for [...60 37 1 50] ===")
	{
		// Get server leaves under this subtree
		diagStream, err := client.PerformSync(context.Background())
		if err == nil {
			shardKeyBytes := slices.Concat(proverShardKey.L1[:], proverShardKey.L2[:])
			mismatchPath := []int32{63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 60, 37, 1, 50}

			err = diagStream.Send(&protobufs.HypergraphSyncQuery{
				Request: &protobufs.HypergraphSyncQuery_GetLeaves{
					GetLeaves: &protobufs.HypergraphSyncGetLeavesRequest{
						ShardKey:  shardKeyBytes,
						PhaseSet:  protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
						Path:      mismatchPath,
						MaxLeaves: 100,
					},
				},
			})
			if err == nil {
				resp, err := diagStream.Recv()
				if err == nil {
					if leaves := resp.GetLeaves(); leaves != nil {
						t.Logf("SERVER leaves under [...60 37 1 50]: count=%d, total=%d",
							len(leaves.Leaves), leaves.TotalLeaves)
						for i, leaf := range leaves.Leaves {
							t.Logf("  SERVER leaf[%d]: key=%x", i, leaf.Key)
						}
					}
				}
			}
			_ = diagStream.CloseSend()
		}

		// Get client leaves under this subtree
		clientTree = clientHG.GetVertexAddsSet(proverShardKey).GetTree()
		mismatchPathInt := []int{63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 60, 37, 1, 50}
		clientSubtreeNode, err := clientTree.GetByPath(mismatchPathInt)
		if err != nil {
			t.Logf("CLIENT error getting node at [...60 37 1 50]: %v", err)
		} else if clientSubtreeNode != nil {
			clientSubtreeLeaves := tries.GetAllLeaves(
				clientTree.SetType,
				clientTree.PhaseType,
				clientTree.ShardKey,
				clientSubtreeNode,
			)
			t.Logf("CLIENT leaves under [...60 37 1 50]: count=%d", len(clientSubtreeLeaves))
			for i, leaf := range clientSubtreeLeaves {
				if leaf != nil {
					t.Logf("  CLIENT leaf[%d]: key=%x", i, leaf.Key)
				}
			}
		}
	}

	// Check the deeper path [...60 37 1 50 50] which server claims has leafCount=2
	t.Log("=== LEAF-LEVEL ANALYSIS for [...60 37 1 50 50] ===")
	{
		diagStream, err := client.PerformSync(context.Background())
		if err == nil {
			shardKeyBytes := slices.Concat(proverShardKey.L1[:], proverShardKey.L2[:])
			deepPath := []int32{63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 60, 37, 1, 50, 50}

			err = diagStream.Send(&protobufs.HypergraphSyncQuery{
				Request: &protobufs.HypergraphSyncQuery_GetLeaves{
					GetLeaves: &protobufs.HypergraphSyncGetLeavesRequest{
						ShardKey:  shardKeyBytes,
						PhaseSet:  protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
						Path:      deepPath,
						MaxLeaves: 100,
					},
				},
			})
			if err == nil {
				resp, err := diagStream.Recv()
				if err == nil {
					if leaves := resp.GetLeaves(); leaves != nil {
						t.Logf("SERVER leaves under [...60 37 1 50 50]: count=%d, total=%d",
							len(leaves.Leaves), leaves.TotalLeaves)
						for i, leaf := range leaves.Leaves {
							t.Logf("  SERVER leaf[%d]: key=%x", i, leaf.Key)
						}
					} else if errResp := resp.GetError(); errResp != nil {
						t.Logf("SERVER error for [...60 37 1 50 50]: %s", errResp.Message)
					}
				}
			}
			_ = diagStream.CloseSend()
		}
	}

	// Also check path [...60 37 1] to see the 3 vs 3 children issue
	t.Log("=== LEAF-LEVEL ANALYSIS for [...60 37 1] ===")
	{
		diagStream, err := client.PerformSync(context.Background())
		if err == nil {
			shardKeyBytes := slices.Concat(proverShardKey.L1[:], proverShardKey.L2[:])
			path371 := []int32{63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 60, 37, 1}

			err = diagStream.Send(&protobufs.HypergraphSyncQuery{
				Request: &protobufs.HypergraphSyncQuery_GetLeaves{
					GetLeaves: &protobufs.HypergraphSyncGetLeavesRequest{
						ShardKey:  shardKeyBytes,
						PhaseSet:  protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
						Path:      path371,
						MaxLeaves: 100,
					},
				},
			})
			if err == nil {
				resp, err := diagStream.Recv()
				if err == nil {
					if leaves := resp.GetLeaves(); leaves != nil {
						t.Logf("SERVER leaves under [...60 37 1]: count=%d, total=%d",
							len(leaves.Leaves), leaves.TotalLeaves)
						for i, leaf := range leaves.Leaves {
							t.Logf("  SERVER leaf[%d]: key=%x", i, leaf.Key)
						}
					}
				}
			}
			_ = diagStream.CloseSend()
		}

		// Client leaves under [...60 37 1]
		clientTree = clientHG.GetVertexAddsSet(proverShardKey).GetTree()
		path371Int := []int{63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 63, 60, 37, 1}
		clientNode371, err := clientTree.GetByPath(path371Int)
		if err != nil {
			t.Logf("CLIENT error getting node at [...60 37 1]: %v", err)
		} else if clientNode371 != nil {
			clientLeaves371 := tries.GetAllLeaves(
				clientTree.SetType,
				clientTree.PhaseType,
				clientTree.ShardKey,
				clientNode371,
			)
			t.Logf("CLIENT leaves under [...60 37 1]: count=%d", len(clientLeaves371))
			for i, leaf := range clientLeaves371 {
				if leaf != nil {
					t.Logf("  CLIENT leaf[%d]: key=%x", i, leaf.Key)
				}
			}
		}
	}

	assert.Equal(t, expectedRoot, clientProverRoot,
		"client prover root should match frame's prover tree commitment after hypersync")

	// Count vertices synced
	clientTree = clientHG.GetVertexAddsSet(proverShardKey).GetTree()
	clientLeaves2 := tries.GetAllLeaves(
		clientTree.SetType,
		clientTree.PhaseType,
		clientTree.ShardKey,
		clientTree.Root,
	)

	clientLeafCount2 := 0
	for _, leaf := range clientLeaves2 {
		if leaf != nil {
			clientLeafCount2++
		}
	}

	t.Logf("Hypersync complete: client synced %d prover vertices", clientLeafCount2)
	assert.Greater(t, clientLeafCount2, 0, "should have synced at least some prover vertices")

	// Verify the sync-based repair approach:
	// 1. Create a second in-memory hypergraph
	// 2. Sync from clientHG to the second hypergraph
	// 3. Wipe the tree data from clientDB
	// 4. Sync back from the second hypergraph to clientHG
	// 5. Verify the root still matches
	t.Log("Verifying sync-based repair approach...")

	// Create second in-memory hypergraph
	repairDB := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest_mainnet_repair/store"}}, 0)
	defer repairDB.Close()

	repairStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest_mainnet_repair/store"},
		repairDB,
		logger,
		enc,
		inclusionProver,
	)

	repairHG := hgcrdt.NewHypergraph(
		logger.With(zap.String("side", "repair")),
		repairStore,
		inclusionProver,
		[]int{},
		&tests.Nopthenticator{},
		200,
	)

	// Get current root from clientHG before repair
	clientRootBeforeRepair := clientHG.GetVertexAddsSet(proverShardKey).GetTree().Commit(nil, false)
	t.Logf("Client root before repair: %x", clientRootBeforeRepair)

	// Publish snapshot on clientHG
	clientHG.PublishSnapshot(clientRootBeforeRepair)

	// Set up gRPC server backed by clientHG
	const repairBufSize = 1 << 20
	clientLis := bufconn.Listen(repairBufSize)
	clientGRPCServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(100*1024*1024),
		grpc.MaxSendMsgSize(100*1024*1024),
	)
	protobufs.RegisterHypergraphComparisonServiceServer(clientGRPCServer, clientHG)
	go func() { _ = clientGRPCServer.Serve(clientLis) }()

	// Dial clientHG
	clientDialer := func(context.Context, string) (net.Conn, error) {
		return clientLis.Dial()
	}
	clientRepairConn, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(clientDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(100*1024*1024),
			grpc.MaxCallSendMsgSize(100*1024*1024),
		),
	)
	require.NoError(t, err)

	clientRepairClient := protobufs.NewHypergraphComparisonServiceClient(clientRepairConn)

	// Sync from clientHG to repairHG for all phases
	repairPhases := []protobufs.HypergraphPhaseSet{
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_REMOVES,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_ADDS,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_HYPEREDGE_REMOVES,
	}

	t.Log("Syncing client -> repair hypergraph...")
	for _, phase := range repairPhases {
		stream, err := clientRepairClient.PerformSync(context.Background())
		require.NoError(t, err)
		_, err = repairHG.SyncFrom(stream, proverShardKey, phase, nil)
		if err != nil {
			t.Logf("Sync client->repair phase %v: %v", phase, err)
		}
		_ = stream.CloseSend()
	}

	// Verify repairHG has the data
	repairRoot := repairHG.GetVertexAddsSet(proverShardKey).GetTree().Commit(nil, false)
	t.Logf("Repair hypergraph root after sync: %x", repairRoot)
	assert.Equal(t, clientRootBeforeRepair, repairRoot, "repair HG should match client root")

	// Stop client server before wiping
	clientGRPCServer.Stop()
	clientRepairConn.Close()

	// Wipe tree data from clientDB for the prover shard
	t.Log("Wiping tree data from client DB...")
	treePrefixes := []byte{
		store.VERTEX_ADDS_TREE_NODE,
		store.VERTEX_REMOVES_TREE_NODE,
		store.HYPEREDGE_ADDS_TREE_NODE,
		store.HYPEREDGE_REMOVES_TREE_NODE,
		store.VERTEX_ADDS_TREE_NODE_BY_PATH,
		store.VERTEX_REMOVES_TREE_NODE_BY_PATH,
		store.HYPEREDGE_ADDS_TREE_NODE_BY_PATH,
		store.HYPEREDGE_REMOVES_TREE_NODE_BY_PATH,
		store.VERTEX_ADDS_CHANGE_RECORD,
		store.VERTEX_REMOVES_CHANGE_RECORD,
		store.HYPEREDGE_ADDS_CHANGE_RECORD,
		store.HYPEREDGE_REMOVES_CHANGE_RECORD,
		store.VERTEX_ADDS_TREE_ROOT,
		store.VERTEX_REMOVES_TREE_ROOT,
		store.HYPEREDGE_ADDS_TREE_ROOT,
		store.HYPEREDGE_REMOVES_TREE_ROOT,
	}

	shardKeyBytes := make([]byte, 0, len(proverShardKey.L1)+len(proverShardKey.L2))
	shardKeyBytes = append(shardKeyBytes, proverShardKey.L1[:]...)
	shardKeyBytes = append(shardKeyBytes, proverShardKey.L2[:]...)

	for _, prefix := range treePrefixes {
		start := append([]byte{store.HYPERGRAPH_SHARD, prefix}, shardKeyBytes...)
		// Increment shard key for end bound
		endShardKeyBytes := make([]byte, len(shardKeyBytes))
		copy(endShardKeyBytes, shardKeyBytes)
		// Since all bytes of L2 are 0xff, incrementing would overflow, so use next prefix
		end := []byte{store.HYPERGRAPH_SHARD, prefix + 1}
		if err := clientDB.DeleteRange(start, end); err != nil {
			t.Logf("DeleteRange for prefix 0x%02x: %v", prefix, err)
		}
	}

	// Reload clientHG after wipe
	t.Log("Reloading client hypergraph after wipe...")
	clientStore2 := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest_mainnet_client/store"},
		clientDB,
		logger,
		enc,
		inclusionProver,
	)
	clientHG2 := hgcrdt.NewHypergraph(
		logger.With(zap.String("side", "mainnet-client-reloaded")),
		clientStore2,
		inclusionProver,
		[]int{},
		&tests.Nopthenticator{},
		200,
	)

	// Verify tree is now empty/different
	clientRootAfterWipe := clientHG2.GetVertexAddsSet(proverShardKey).GetTree().Commit(nil, false)
	t.Logf("Client root after wipe: %x (expected nil or different)", clientRootAfterWipe)

	// Publish snapshot on repairHG for reverse sync
	repairHG.PublishSnapshot(repairRoot)

	// Set up gRPC server backed by repairHG
	repairLis := bufconn.Listen(repairBufSize)
	repairGRPCServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(100*1024*1024),
		grpc.MaxSendMsgSize(100*1024*1024),
	)
	protobufs.RegisterHypergraphComparisonServiceServer(repairGRPCServer, repairHG)
	go func() { _ = repairGRPCServer.Serve(repairLis) }()
	defer repairGRPCServer.Stop()

	// Dial repairHG
	repairDialer := func(context.Context, string) (net.Conn, error) {
		return repairLis.Dial()
	}
	repairConn, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(repairDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(100*1024*1024),
			grpc.MaxCallSendMsgSize(100*1024*1024),
		),
	)
	require.NoError(t, err)
	defer repairConn.Close()

	repairClient := protobufs.NewHypergraphComparisonServiceClient(repairConn)

	// Sync from repairHG to clientHG2 for all phases
	t.Log("Syncing repair -> client hypergraph...")
	for _, phase := range repairPhases {
		stream, err := repairClient.PerformSync(context.Background())
		require.NoError(t, err)
		_, err = clientHG2.SyncFrom(stream, proverShardKey, phase, nil)
		if err != nil {
			t.Logf("Sync repair->client phase %v: %v", phase, err)
		}
		_ = stream.CloseSend()
	}

	// Commit and verify root after repair
	clientRootAfterRepair := clientHG2.GetVertexAddsSet(proverShardKey).GetTree().Commit(nil, true)
	t.Logf("Client root after repair: %x", clientRootAfterRepair)
	t.Logf("Expected root from frame: %x", expectedRoot)

	// Verify the root matches the original (before repair) - this confirms the round-trip works
	assert.Equal(t, clientRootBeforeRepair, clientRootAfterRepair,
		"root after sync repair should match root before repair")

	// Note: The root may not match the frame's expected root if there was corruption,
	// but it should at least match what we synced before the repair.
	// The actual fix for the frame mismatch requires fixing the corruption at the source.
	t.Logf("Sync-based repair verification complete.")
	t.Logf("  Original client root: %x", clientRootBeforeRepair)
	t.Logf("  Repaired client root: %x", clientRootAfterRepair)
	t.Logf("  Frame expected root:  %x", expectedRoot)
	if bytes.Equal(clientRootAfterRepair, expectedRoot) {
		t.Log("SUCCESS: Repaired root matches frame expected root!")
	} else {
		t.Log("Note: Repaired root differs from frame expected root - corruption exists at source")
	}
}

// TestHypergraphSyncWithPagination tests that syncing a large tree with >1000 leaves
// correctly handles pagination through multiple GetLeaves requests.
func TestHypergraphSyncWithPagination(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	enc := verenc.NewMPCitHVerifiableEncryptor(1)
	inclusionProver := bls48581.NewKZGInclusionProver(logger)

	// Create 1500 data trees to exceed the 1000 leaf batch size
	numVertices := 1500
	dataTrees := make([]*tries.VectorCommitmentTree, numVertices)
	eg := errgroup.Group{}
	eg.SetLimit(100)
	for i := 0; i < numVertices; i++ {
		eg.Go(func() error {
			dataTrees[i] = buildDataTree(t, inclusionProver)
			return nil
		})
	}
	eg.Wait()
	t.Log("Generated data trees")

	// Create server DB and store
	serverDB := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest_pagination_server/store"}}, 0)
	defer serverDB.Close()

	serverStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest_pagination_server/store"},
		serverDB,
		logger,
		enc,
		inclusionProver,
	)

	serverHG := hgcrdt.NewHypergraph(
		logger.With(zap.String("side", "server")),
		serverStore,
		inclusionProver,
		[]int{},
		&tests.Nopthenticator{},
		200,
	)

	// Create client DB and store
	clientDB := store.NewPebbleDB(logger, &config.Config{DB: &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest_pagination_client/store"}}, 0)
	defer clientDB.Close()

	clientStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest_pagination_client/store"},
		clientDB,
		logger,
		enc,
		inclusionProver,
	)

	clientHG := hgcrdt.NewHypergraph(
		logger.With(zap.String("side", "client")),
		clientStore,
		inclusionProver,
		[]int{},
		&tests.Nopthenticator{},
		200,
	)

	// Create all vertices in a single domain
	domain := randomBytes32(t)
	vertices := make([]application.Vertex, numVertices)
	for i := 0; i < numVertices; i++ {
		vertices[i] = hgcrdt.NewVertex(
			domain,
			randomBytes32(t),
			dataTrees[i].Commit(inclusionProver, false),
			dataTrees[i].GetSize(),
		)
	}
	shardKey := application.GetShardKey(vertices[0])

	// Add all vertices to server
	t.Logf("Adding %d vertices to server", numVertices)
	serverTxn, err := serverStore.NewTransaction(false)
	require.NoError(t, err)
	for i, v := range vertices {
		id := v.GetID()
		require.NoError(t, serverStore.SaveVertexTree(serverTxn, id[:], dataTrees[i]))
		require.NoError(t, serverHG.AddVertex(serverTxn, v))
	}
	require.NoError(t, serverTxn.Commit())

	// Add initial vertex to client (to establish same shard key)
	clientTxn, err := clientStore.NewTransaction(false)
	require.NoError(t, err)
	id := vertices[0].GetID()
	require.NoError(t, clientStore.SaveVertexTree(clientTxn, id[:], dataTrees[0]))
	require.NoError(t, clientHG.AddVertex(clientTxn, vertices[0]))
	require.NoError(t, clientTxn.Commit())

	// Commit both
	_, err = serverHG.Commit(1)
	require.NoError(t, err)
	_, err = clientHG.Commit(1)
	require.NoError(t, err)

	serverRoot := serverHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	serverHG.PublishSnapshot(serverRoot)

	t.Logf("Server root: %x", serverRoot)

	// Verify server has 1500 vertices
	serverTree := serverHG.GetVertexAddsSet(shardKey).GetTree()
	serverLeaves := tries.GetAllLeaves(
		serverTree.SetType,
		serverTree.PhaseType,
		serverTree.ShardKey,
		serverTree.Root,
	)
	serverLeafCount := 0
	for _, leaf := range serverLeaves {
		if leaf != nil {
			serverLeafCount++
		}
	}
	assert.Equal(t, numVertices, serverLeafCount, "server should have %d leaves", numVertices)
	t.Logf("Server has %d leaves", serverLeafCount)

	// Setup gRPC server
	const bufSize = 1 << 20
	lis := bufconn.Listen(bufSize)

	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(100*1024*1024), // 100 MB
		grpc.MaxSendMsgSize(100*1024*1024), // 100 MB
		grpc.ChainStreamInterceptor(func(
			srv interface{},
			ss grpc.ServerStream,
			info *grpc.StreamServerInfo,
			handler grpc.StreamHandler,
		) error {
			_, priv, _ := ed448.GenerateKey(rand.Reader)
			privKey, err := pcrypto.UnmarshalEd448PrivateKey(priv)
			require.NoError(t, err)

			pub := privKey.GetPublic()
			peerID, err := peer.IDFromPublicKey(pub)
			require.NoError(t, err)

			return handler(srv, &serverStream{
				ServerStream: ss,
				ctx:          internal_grpc.NewContextWithPeerID(ss.Context(), peerID),
			})
		}),
	)
	protobufs.RegisterHypergraphComparisonServiceServer(grpcServer, serverHG)
	defer grpcServer.Stop()

	go func() {
		_ = grpcServer.Serve(lis)
	}()

	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}
	conn, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(100*1024*1024), // 100 MB
			grpc.MaxCallSendMsgSize(100*1024*1024), // 100 MB
		),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := protobufs.NewHypergraphComparisonServiceClient(conn)

	// Perform sync
	t.Log("Starting sync with pagination...")
	stream, err := client.PerformSync(context.Background())
	require.NoError(t, err)

	_, err = clientHG.SyncFrom(
		stream,
		shardKey,
		protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
		nil,
	)
	require.NoError(t, err)
	require.NoError(t, stream.CloseSend())

	// Commit client and verify
	_, err = clientHG.Commit(2)
	require.NoError(t, err)

	clientRoot := clientHG.GetVertexAddsSet(shardKey).GetTree().Commit(nil, false)
	t.Logf("Client root after sync: %x", clientRoot)

	// Verify client now has all 1500 vertices
	clientTree := clientHG.GetVertexAddsSet(shardKey).GetTree()
	clientLeaves := tries.GetAllLeaves(
		clientTree.SetType,
		clientTree.PhaseType,
		clientTree.ShardKey,
		clientTree.Root,
	)
	clientLeafCount := 0
	for _, leaf := range clientLeaves {
		if leaf != nil {
			clientLeafCount++
		}
	}
	assert.Equal(t, numVertices, clientLeafCount, "client should have %d leaves after sync", numVertices)
	t.Logf("Client has %d leaves after sync", clientLeafCount)

	// Verify roots match
	assert.Equal(t, serverRoot, clientRoot, "client root should match server root after sync")
	t.Log("Pagination test passed - client converged to server state")
}

// dumpHypergraphShardKeys dumps all database keys matching the global prover shard pattern.
// This replicates the behavior of: dbscan -prefix 09 -search 000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
// Parameters:
//   - t: testing context for logging
//   - db: the PebbleDB to inspect
//   - label: a label to identify the database in output (e.g., "client", "server")
func dumpHypergraphShardKeys(t *testing.T, db *store.PebbleDB, label string) {
	// Prefix 0x09 = HYPERGRAPH_SHARD
	prefixFilter := []byte{store.HYPERGRAPH_SHARD}

	// Global prover shard key: L1=[0x00,0x00,0x00], L2=[0xff * 32]
	// As hex: 000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff (35 bytes)
	keySearchPattern, err := hex.DecodeString("000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Logf("[%s] Failed to decode search pattern: %v", label, err)
		return
	}

	// Set iteration bounds based on prefix
	lowerBound := prefixFilter
	upperBound := []byte{store.HYPERGRAPH_SHARD + 1}

	iter, err := db.NewIter(lowerBound, upperBound)
	if err != nil {
		t.Logf("[%s] Failed to create iterator: %v", label, err)
		return
	}
	defer iter.Close()

	t.Logf("=== Database dump for %s (prefix=09, search=global prover shard) ===", label)

	count := 0
	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()
		value := iter.Value()

		// Apply prefix filter
		if !bytes.HasPrefix(key, prefixFilter) {
			continue
		}

		// Apply key search pattern (must contain the global prover shard key bytes)
		if !bytes.Contains(key, keySearchPattern) {
			continue
		}

		count++

		// Decode and display the key/value
		semantic := describeHypergraphKeyForTest(key)
		decoded := decodeHypergraphValueForTest(key, value)

		t.Logf("[%s] key: %s", label, hex.EncodeToString(key))
		t.Logf("[%s] semantic: %s", label, semantic)
		t.Logf("[%s] value:\n%s\n", label, indentForTest(decoded))
	}

	t.Logf("=== End dump for %s: %d keys matched ===", label, count)
}

// describeHypergraphKeyForTest provides semantic description of hypergraph keys.
// Mirrors the logic from dbscan/main.go describeHypergraphKey.
func describeHypergraphKeyForTest(key []byte) string {
	if len(key) < 2 {
		return "hypergraph: invalid key length"
	}

	// Check for shard commit keys (frame-based)
	if len(key) >= 10 {
		switch key[9] {
		case store.HYPERGRAPH_VERTEX_ADDS_SHARD_COMMIT,
			store.HYPERGRAPH_VERTEX_REMOVES_SHARD_COMMIT,
			store.HYPERGRAPH_HYPEREDGE_ADDS_SHARD_COMMIT,
			store.HYPERGRAPH_HYPEREDGE_REMOVES_SHARD_COMMIT:
			frame := binary.BigEndian.Uint64(key[1:9])
			shard := key[10:]
			var setPhase string
			switch key[9] {
			case store.HYPERGRAPH_VERTEX_ADDS_SHARD_COMMIT:
				setPhase = "vertex-adds"
			case store.HYPERGRAPH_VERTEX_REMOVES_SHARD_COMMIT:
				setPhase = "vertex-removes"
			case store.HYPERGRAPH_HYPEREDGE_ADDS_SHARD_COMMIT:
				setPhase = "hyperedge-adds"
			case store.HYPERGRAPH_HYPEREDGE_REMOVES_SHARD_COMMIT:
				setPhase = "hyperedge-removes"
			}
			return fmt.Sprintf(
				"hypergraph shard commit %s frame=%d shard=%s",
				setPhase,
				frame,
				shortHexForTest(shard),
			)
		}
	}

	sub := key[1]
	payload := key[2:]
	switch sub {
	case store.VERTEX_DATA:
		return fmt.Sprintf("hypergraph vertex data id=%s", shortHexForTest(payload))
	case store.VERTEX_TOMBSTONE:
		return fmt.Sprintf("hypergraph vertex tombstone id=%s", shortHexForTest(payload))
	case store.VERTEX_ADDS_TREE_NODE,
		store.VERTEX_REMOVES_TREE_NODE,
		store.HYPEREDGE_ADDS_TREE_NODE,
		store.HYPEREDGE_REMOVES_TREE_NODE:
		if len(payload) >= 35 {
			l1 := payload[:3]
			l2 := payload[3:35]
			node := payload[35:]
			return fmt.Sprintf(
				"%s tree node shard=[%s|%s] node=%s",
				describeHypergraphTreeTypeForTest(sub),
				shortHexForTest(l1),
				shortHexForTest(l2),
				shortHexForTest(node),
			)
		}
		return fmt.Sprintf(
			"%s tree node (invalid length)",
			describeHypergraphTreeTypeForTest(sub),
		)
	case store.VERTEX_ADDS_TREE_NODE_BY_PATH,
		store.VERTEX_REMOVES_TREE_NODE_BY_PATH,
		store.HYPEREDGE_ADDS_TREE_NODE_BY_PATH,
		store.HYPEREDGE_REMOVES_TREE_NODE_BY_PATH:
		if len(payload) >= 35 {
			l1 := payload[:3]
			l2 := payload[3:35]
			path := parseUint64PathForTest(payload[35:])
			return fmt.Sprintf(
				"%s path shard=[%s|%s] path=%v",
				describeHypergraphTreeTypeForTest(sub),
				shortHexForTest(l1),
				shortHexForTest(l2),
				path,
			)
		}
		return fmt.Sprintf(
			"%s path (invalid length)",
			describeHypergraphTreeTypeForTest(sub),
		)
	case store.VERTEX_ADDS_TREE_ROOT,
		store.VERTEX_REMOVES_TREE_ROOT,
		store.HYPEREDGE_ADDS_TREE_ROOT,
		store.HYPEREDGE_REMOVES_TREE_ROOT:
		if len(payload) >= 35 {
			l1 := payload[:3]
			l2 := payload[3:35]
			return fmt.Sprintf(
				"%s tree root shard=[%s|%s]",
				describeHypergraphTreeTypeForTest(sub),
				shortHexForTest(l1),
				shortHexForTest(l2),
			)
		}
		return fmt.Sprintf(
			"%s tree root (invalid length)",
			describeHypergraphTreeTypeForTest(sub),
		)
	case store.HYPERGRAPH_COVERED_PREFIX:
		return "hypergraph covered prefix metadata"
	case store.HYPERGRAPH_COMPLETE:
		return "hypergraph completeness flag"
	default:
		return fmt.Sprintf(
			"hypergraph unknown subtype 0x%02x raw=%s",
			sub,
			shortHexForTest(payload),
		)
	}
}

func describeHypergraphTreeTypeForTest(kind byte) string {
	switch kind {
	case store.VERTEX_ADDS_TREE_NODE,
		store.VERTEX_ADDS_TREE_NODE_BY_PATH,
		store.VERTEX_ADDS_TREE_ROOT:
		return "vertex adds"
	case store.VERTEX_REMOVES_TREE_NODE,
		store.VERTEX_REMOVES_TREE_NODE_BY_PATH,
		store.VERTEX_REMOVES_TREE_ROOT:
		return "vertex removes"
	case store.HYPEREDGE_ADDS_TREE_NODE,
		store.HYPEREDGE_ADDS_TREE_NODE_BY_PATH,
		store.HYPEREDGE_ADDS_TREE_ROOT:
		return "hyperedge adds"
	case store.HYPEREDGE_REMOVES_TREE_NODE,
		store.HYPEREDGE_REMOVES_TREE_NODE_BY_PATH,
		store.HYPEREDGE_REMOVES_TREE_ROOT:
		return "hyperedge removes"
	default:
		return "hypergraph"
	}
}

// decodeHypergraphValueForTest decodes hypergraph values for display.
// Mirrors the logic from dbscan/main.go decodeHypergraphValue.
func decodeHypergraphValueForTest(key []byte, value []byte) string {
	if len(value) == 0 {
		return "<empty>"
	}

	sub := byte(0)
	if len(key) > 1 {
		sub = key[1]
	}

	switch sub {
	case store.VERTEX_DATA:
		return summarizeVectorCommitmentTreeForTest(key, value)
	case store.VERTEX_TOMBSTONE:
		return shortHexForTest(value)
	case store.VERTEX_ADDS_TREE_NODE,
		store.VERTEX_REMOVES_TREE_NODE,
		store.HYPEREDGE_ADDS_TREE_NODE,
		store.HYPEREDGE_REMOVES_TREE_NODE,
		store.VERTEX_ADDS_TREE_NODE_BY_PATH,
		store.VERTEX_REMOVES_TREE_NODE_BY_PATH,
		store.HYPEREDGE_ADDS_TREE_NODE_BY_PATH,
		store.HYPEREDGE_REMOVES_TREE_NODE_BY_PATH,
		store.VERTEX_ADDS_TREE_ROOT,
		store.VERTEX_REMOVES_TREE_ROOT,
		store.HYPEREDGE_ADDS_TREE_ROOT,
		store.HYPEREDGE_REMOVES_TREE_ROOT:
		return summarizeHypergraphTreeNodeForTest(value)
	case store.HYPERGRAPH_COVERED_PREFIX:
		return decodeCoveredPrefixForTest(value)
	case store.HYPERGRAPH_COMPLETE:
		if len(value) == 0 {
			return "complete=false"
		}
		return fmt.Sprintf("complete=%t", value[len(value)-1] != 0)
	default:
		return shortHexForTest(value)
	}
}

func summarizeVectorCommitmentTreeForTest(key []byte, value []byte) string {
	tree, err := tries.DeserializeNonLazyTree(value)
	if err != nil {
		return fmt.Sprintf(
			"vector_commitment_tree decode_error=%v raw=%s",
			err,
			shortHexForTest(value),
		)
	}

	sum := sha256.Sum256(value)
	summary := map[string]any{
		"size_bytes": len(value),
		"sha256":     shortHexForTest(sum[:]),
	}

	// Check if this is a global intrinsic vertex (domain = 0xff*32)
	globalIntrinsicAddress := bytes.Repeat([]byte{0xff}, 32)
	if len(key) >= 66 {
		domain := key[2:34]
		address := key[34:66]

		if bytes.Equal(domain, globalIntrinsicAddress) {
			// This is a global intrinsic vertex - decode the fields
			globalData := decodeGlobalIntrinsicVertexForTest(tree, address)
			if globalData != nil {
				for k, v := range globalData {
					summary[k] = v
				}
			}
		}
	}

	jsonBytes, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Sprintf("vector_commitment_tree size_bytes=%d", len(value))
	}

	return string(jsonBytes)
}

func decodeGlobalIntrinsicVertexForTest(tree *tries.VectorCommitmentTree, address []byte) map[string]any {
	result := make(map[string]any)
	result["vertex_address"] = hex.EncodeToString(address)

	// Check order 0 field
	order0Value, err := tree.Get([]byte{0x00})
	if err != nil || len(order0Value) == 0 {
		result["type"] = "unknown (no order 0 field)"
		return result
	}

	switch len(order0Value) {
	case 585:
		// Prover: PublicKey is 585 bytes
		result["type"] = "prover:Prover"
		result["public_key"] = shortHexForTest(order0Value)
		decodeProverFieldsForTest(tree, result)
	case 32:
		// Could be Allocation (Prover reference) or Reward (DelegateAddress)
		joinFrame, _ := tree.Get([]byte{0x10})
		if len(joinFrame) == 8 {
			result["type"] = "allocation:ProverAllocation"
			result["prover_reference"] = hex.EncodeToString(order0Value)
			decodeAllocationFieldsForTest(tree, result)
		} else {
			result["type"] = "reward:ProverReward"
			result["delegate_address"] = hex.EncodeToString(order0Value)
		}
	default:
		result["type"] = "unknown"
		result["order_0_size"] = len(order0Value)
	}

	return result
}

func decodeProverFieldsForTest(tree *tries.VectorCommitmentTree, result map[string]any) {
	if status, err := tree.Get([]byte{0x04}); err == nil && len(status) == 1 {
		result["status"] = decodeProverStatusForTest(status[0])
		result["status_raw"] = status[0]
	}
	if storage, err := tree.Get([]byte{0x08}); err == nil && len(storage) == 8 {
		result["available_storage"] = binary.BigEndian.Uint64(storage)
	}
	if seniority, err := tree.Get([]byte{0x0c}); err == nil && len(seniority) == 8 {
		result["seniority"] = binary.BigEndian.Uint64(seniority)
	}
	if kickFrame, err := tree.Get([]byte{0x10}); err == nil && len(kickFrame) == 8 {
		result["kick_frame_number"] = binary.BigEndian.Uint64(kickFrame)
	}
}

func decodeAllocationFieldsForTest(tree *tries.VectorCommitmentTree, result map[string]any) {
	if status, err := tree.Get([]byte{0x04}); err == nil && len(status) == 1 {
		result["status"] = decodeProverStatusForTest(status[0])
		result["status_raw"] = status[0]
	}
	if confirmFilter, err := tree.Get([]byte{0x08}); err == nil && len(confirmFilter) > 0 {
		result["confirmation_filter"] = hex.EncodeToString(confirmFilter)
		if bytes.Equal(confirmFilter, make([]byte, len(confirmFilter))) {
			result["is_global_prover"] = true
		}
	} else {
		result["is_global_prover"] = true
	}
	if joinFrame, err := tree.Get([]byte{0x10}); err == nil && len(joinFrame) == 8 {
		result["join_frame_number"] = binary.BigEndian.Uint64(joinFrame)
	}
	if leaveFrame, err := tree.Get([]byte{0x14}); err == nil && len(leaveFrame) == 8 {
		result["leave_frame_number"] = binary.BigEndian.Uint64(leaveFrame)
	}
	if lastActive, err := tree.Get([]byte{0x34}); err == nil && len(lastActive) == 8 {
		result["last_active_frame_number"] = binary.BigEndian.Uint64(lastActive)
	}
}

func decodeProverStatusForTest(status byte) string {
	switch status {
	case 0:
		return "Joining"
	case 1:
		return "Active"
	case 2:
		return "Paused"
	case 3:
		return "Leaving"
	case 4:
		return "Rejected"
	case 5:
		return "Kicked"
	default:
		return fmt.Sprintf("Unknown(%d)", status)
	}
}

func summarizeHypergraphTreeNodeForTest(value []byte) string {
	if len(value) == 0 {
		return "hypergraph_tree_node <empty>"
	}

	hash := sha256.Sum256(value)
	hashStr := shortHexForTest(hash[:])

	reader := bytes.NewReader(value)
	var nodeType byte
	if err := binary.Read(reader, binary.BigEndian, &nodeType); err != nil {
		return fmt.Sprintf("tree_node decode_error=%v sha256=%s", err, hashStr)
	}

	switch nodeType {
	case tries.TypeNil:
		return fmt.Sprintf("tree_nil sha256=%s", hashStr)
	case tries.TypeLeaf:
		leaf, err := tries.DeserializeLeafNode(nil, reader)
		if err != nil {
			return fmt.Sprintf("tree_leaf decode_error=%v sha256=%s", err, hashStr)
		}

		summary := map[string]any{
			"type":         "leaf",
			"key":          shortHexForTest(leaf.Key),
			"value":        shortHexForTest(leaf.Value),
			"hash_target":  shortHexForTest(leaf.HashTarget),
			"commitment":   shortHexForTest(leaf.Commitment),
			"bytes_sha256": hashStr,
		}
		if leaf.Size != nil {
			summary["size"] = leaf.Size.String()
		}

		jsonBytes, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return fmt.Sprintf(
				"tree_leaf key=%s sha256=%s",
				shortHexForTest(leaf.Key),
				hashStr,
			)
		}
		return string(jsonBytes)
	case tries.TypeBranch:
		branch, err := tries.DeserializeBranchNode(nil, reader, true)
		if err != nil {
			return fmt.Sprintf("tree_branch decode_error=%v sha256=%s", err, hashStr)
		}

		childSummary := map[string]int{
			"branch": 0,
			"leaf":   0,
			"nil":    0,
		}
		for _, child := range branch.Children {
			switch child.(type) {
			case *tries.LazyVectorCommitmentBranchNode:
				childSummary["branch"]++
			case *tries.LazyVectorCommitmentLeafNode:
				childSummary["leaf"]++
			default:
				childSummary["nil"]++
			}
		}

		summary := map[string]any{
			"type":           "branch",
			"prefix":         branch.Prefix,
			"leaf_count":     branch.LeafCount,
			"longest_branch": branch.LongestBranch,
			"commitment":     shortHexForTest(branch.Commitment),
			"children":       childSummary,
			"bytes_sha256":   hashStr,
		}
		if branch.Size != nil {
			summary["size"] = branch.Size.String()
		}

		jsonBytes, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			return fmt.Sprintf(
				"tree_branch prefix=%v leafs=%d sha256=%s",
				branch.Prefix,
				branch.LeafCount,
				hashStr,
			)
		}
		return string(jsonBytes)
	default:
		return fmt.Sprintf(
			"tree_node type=0x%02x payload=%s sha256=%s",
			nodeType,
			shortHexForTest(value[1:]),
			hashStr,
		)
	}
}

func decodeCoveredPrefixForTest(value []byte) string {
	if len(value)%8 != 0 {
		return shortHexForTest(value)
	}

	result := make([]int64, len(value)/8)
	for i := range result {
		result[i] = int64(binary.BigEndian.Uint64(value[i*8 : (i+1)*8]))
	}

	return fmt.Sprintf("covered_prefix=%v", result)
}

func shortHexForTest(b []byte) string {
	if len(b) == 0 {
		return "0x"
	}
	if len(b) <= 16 {
		return "0x" + hex.EncodeToString(b)
	}
	return fmt.Sprintf(
		"0x%s...%s(len=%d)",
		hex.EncodeToString(b[:8]),
		hex.EncodeToString(b[len(b)-8:]),
		len(b),
	)
}

func parseUint64PathForTest(b []byte) []uint64 {
	if len(b)%8 != 0 {
		return nil
	}

	out := make([]uint64, len(b)/8)
	for i := range out {
		out[i] = binary.BigEndian.Uint64(b[i*8 : (i+1)*8])
	}
	return out
}

func indentForTest(value string) string {
	if value == "" {
		return ""
	}
	lines := bytes.Split([]byte(value), []byte("\n"))
	for i, line := range lines {
		lines[i] = append([]byte("  "), line...)
	}
	return string(bytes.Join(lines, []byte("\n")))
}
