package rpc_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"net"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/config"
	hgcrdt "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	internal_grpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tests"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	application "source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
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

	clientKvdb := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestclient/store"}, 0)
	serverKvdb := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestserver/store"}, 0)
	controlKvdb := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestcontrol/store"}, 0)

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

	conn, err := grpc.DialContext(context.TODO(), "localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Client: failed to listen: %v", err)
	}
	client := protobufs.NewHypergraphComparisonServiceClient(conn)
	str, err := client.HyperStream(context.TODO())
	if err != nil {
		log.Fatalf("Client: failed to stream: %v", err)
	}

	err = crdts[1].Sync(str, shardKey, protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS)
	if err != nil {
		log.Fatalf("Client: failed to sync 1: %v", err)
	}
	time.Sleep(10 * time.Second)
	str.CloseSend()
	leaves := crypto.CompareLeaves(
		crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree(),
		crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree(),
	)
	fmt.Println("pass completed, orphans:", len(leaves))

	crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(false)
	crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(false)

	str, err = client.HyperStream(context.TODO())
	if err != nil {
		log.Fatalf("Client: failed to stream: %v", err)
	}

	err = crdts[1].Sync(str, shardKey, protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS)
	if err != nil {
		log.Fatalf("Client: failed to sync 2: %v", err)
	}
	time.Sleep(10 * time.Second)
	str.CloseSend()

	if !bytes.Equal(
		crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(false),
		crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(false),
	) {
		leaves := crypto.CompareLeaves(
			crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree(),
			crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree(),
		)
		fmt.Println("remaining orphans", len(leaves))
		log.Fatalf(
			"trees mismatch: %v %v",
			crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(false),
			crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(false),
		)
	}

	if !bytes.Equal(
		crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(false),
		crdts[2].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(false),
	) {
		log.Fatalf(
			"trees did not converge to correct state: %v %v",
			crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(false),
			crdts[2].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(false),
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

	clientKvdb := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestclient/store"}, 0)
	serverKvdb := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestserver/store"}, 0)
	controlKvdb := store.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtestcontrol/store"}, 0)

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

	conn, err := grpc.DialContext(context.TODO(), "localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Client: failed to listen: %v", err)
	}
	client := protobufs.NewHypergraphComparisonServiceClient(conn)
	str, err := client.HyperStream(context.TODO())
	if err != nil {
		log.Fatalf("Client: failed to stream: %v", err)
	}

	now := time.Now()
	response, err := client.GetChildrenForPath(context.TODO(), &protobufs.GetChildrenForPathRequest{
		ShardKey: append(append([]byte{}, shardKey.L1[:]...), shardKey.L2[:]...),
		Path:     toUint32Slice(branchfork),
		PhaseSet: protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
	})
	fmt.Println(time.Since(now))

	require.NoError(t, err)

	slices.Reverse(response.PathSegments)
	sum := uint64(0)
	size := big.NewInt(0)
	longestBranch := uint32(0)

	for _, ps := range response.PathSegments {
		for _, s := range ps.Segments {
			switch seg := s.Segment.(type) {
			case *protobufs.TreePathSegment_Branch:
				if isPrefix(toIntSlice(seg.Branch.FullPrefix), toIntSlice(toUint32Slice(branchfork))) {
					seg.Branch.Commitment = nil
					branchSize := new(big.Int).SetBytes(seg.Branch.Size)
					if sum == 0 {
						sum = seg.Branch.LeafCount
						size.Add(size, branchSize)
						longestBranch = seg.Branch.LongestBranch
					}
					seg.Branch.LeafCount -= sum
					seg.Branch.Size = branchSize.Sub(branchSize, size).Bytes()
					seg.Branch.LongestBranch -= longestBranch
				}
			}
		}
	}
	slices.Reverse(response.PathSegments)
	for i, ps := range response.PathSegments {
		for _, s := range ps.Segments {
			switch seg := s.Segment.(type) {
			case *protobufs.TreePathSegment_Leaf:
				err := crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().InsertLeafSkeleton(
					nil,
					&tries.LazyVectorCommitmentLeafNode{
						Key:        seg.Leaf.Key,
						Value:      seg.Leaf.Value,
						HashTarget: seg.Leaf.HashTarget,
						Commitment: seg.Leaf.Commitment,
						Size:       new(big.Int).SetBytes(seg.Leaf.Size),
						Store:      crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Store,
					},
					i == 0,
				)
				if err != nil {
					panic(err)
				}
			case *protobufs.TreePathSegment_Branch:
				if isPrefix(toIntSlice(seg.Branch.FullPrefix), toIntSlice(toUint32Slice(branchfork))) {
					seg.Branch.Commitment = nil
				}
				if !slices.Equal(toIntSlice(seg.Branch.FullPrefix), toIntSlice(toUint32Slice(branchfork))) {
					err := crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().InsertBranchSkeleton(
						nil,
						&tries.LazyVectorCommitmentBranchNode{
							Prefix:        toIntSlice(seg.Branch.Prefix),
							Commitment:    seg.Branch.Commitment,
							Size:          new(big.Int).SetBytes(seg.Branch.Size),
							LeafCount:     int(seg.Branch.LeafCount),
							LongestBranch: int(seg.Branch.LongestBranch),
							FullPrefix:    toIntSlice(seg.Branch.FullPrefix),
							Store:         crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Store,
						},
						i == 0,
					)
					if err != nil {
						panic(err)
					}
				}
				// }
			}
		}
	}

	err = crdts[1].Sync(str, shardKey, protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS)
	if err != nil {
		log.Fatalf("Client: failed to sync 1: %v", err)
	}
	str.CloseSend()
	leaves := crypto.CompareLeaves(
		crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree(),
		crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree(),
	)
	fmt.Println("pass completed, orphans:", len(leaves))

	crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(false)
	crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(false)

	require.Equal(t, crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Root.GetSize().Int64(), crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Root.GetSize().Int64())
	require.Equal(t, crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Root.(*tries.LazyVectorCommitmentBranchNode).LeafCount, crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Root.(*tries.LazyVectorCommitmentBranchNode).LeafCount)
	require.NoError(t, crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().PruneUncoveredBranches())

	now = time.Now()
	response, err = client.GetChildrenForPath(context.TODO(), &protobufs.GetChildrenForPathRequest{
		ShardKey: append(append([]byte{}, shardKey.L1[:]...), shardKey.L2[:]...),
		Path:     toUint32Slice(branchfork),
		PhaseSet: protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
	})
	fmt.Println(time.Since(now))

	require.NoError(t, err)

	slices.Reverse(response.PathSegments)
	sum = uint64(0xffffffffffffffff)
	size = big.NewInt(0)
	longest := uint32(0)
	ourNode, err := clientHypergraphStore.GetNodeByPath(
		crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().SetType,
		crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().PhaseType,
		crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().ShardKey,
		toIntSlice(toUint32Slice(branchfork)),
	)
	require.NoError(t, err)
	for _, ps := range response.PathSegments {
		for _, s := range ps.Segments {
			switch seg := s.Segment.(type) {
			case *protobufs.TreePathSegment_Branch:
				if isPrefix(toIntSlice(seg.Branch.FullPrefix), toIntSlice(toUint32Slice(branchfork))) {
					seg.Branch.Commitment = nil
					branchSize := new(big.Int).SetBytes(seg.Branch.Size)
					if sum == 0xffffffffffffffff {
						sum = seg.Branch.LeafCount - uint64(ourNode.(*tries.LazyVectorCommitmentBranchNode).LeafCount)
						size.Add(size, branchSize)
						size.Sub(size, ourNode.GetSize())
						longest = seg.Branch.LongestBranch
					}
					seg.Branch.LeafCount -= sum
					seg.Branch.Size = branchSize.Sub(branchSize, size).Bytes()
					seg.Branch.LongestBranch = max(longest, seg.Branch.LongestBranch)
					longest++
				}
			}
		}
	}
	slices.Reverse(response.PathSegments)
	for i, ps := range response.PathSegments {
		for _, s := range ps.Segments {
			switch seg := s.Segment.(type) {
			case *protobufs.TreePathSegment_Leaf:
				err := crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().InsertLeafSkeleton(
					nil,
					&tries.LazyVectorCommitmentLeafNode{
						Key:        seg.Leaf.Key,
						Value:      seg.Leaf.Value,
						HashTarget: seg.Leaf.HashTarget,
						Commitment: seg.Leaf.Commitment,
						Size:       new(big.Int).SetBytes(seg.Leaf.Size),
						Store:      crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Store,
					},
					i == 0,
				)
				if err != nil {
					panic(err)
				}
			case *protobufs.TreePathSegment_Branch:
				if isPrefix(toIntSlice(seg.Branch.FullPrefix), toIntSlice(toUint32Slice(branchfork))) {
					seg.Branch.Commitment = nil
				}
				if !slices.Equal(toIntSlice(seg.Branch.FullPrefix), toIntSlice(toUint32Slice(branchfork))) {

					err := crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().InsertBranchSkeleton(
						nil,
						&tries.LazyVectorCommitmentBranchNode{
							Prefix:        toIntSlice(seg.Branch.Prefix),
							Commitment:    seg.Branch.Commitment,
							Size:          new(big.Int).SetBytes(seg.Branch.Size),
							LeafCount:     int(seg.Branch.LeafCount),
							LongestBranch: int(seg.Branch.LongestBranch),
							FullPrefix:    toIntSlice(seg.Branch.FullPrefix),
							Store:         crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Store,
						},
						i == 0,
					)
					if err != nil {
						panic(err)
					}
				}
			}
		}
	}

	time.Sleep(10 * time.Second)
	str, err = client.HyperStream(context.TODO())

	if err != nil {
		log.Fatalf("Client: failed to stream: %v", err)
	}

	err = crdts[1].Sync(str, shardKey, protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS)
	if err != nil {
		log.Fatalf("Client: failed to sync 2: %v", err)
	}
	str.CloseSend()
	crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(false)
	crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(false)

	require.Equal(t, crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Root.GetSize().Int64(), crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Root.GetSize().Int64())
	require.Equal(t, crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Root.(*tries.LazyVectorCommitmentBranchNode).LeafCount, crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Root.(*tries.LazyVectorCommitmentBranchNode).LeafCount)
	if !bytes.Equal(
		crdts[0].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(false),
		crdts[1].(*hgcrdt.HypergraphCRDT).GetVertexAddsSet(shardKey).GetTree().Commit(false),
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
	assert.Greater(t, clientHas, 1, "mismatching vertex data entries")
}

func TestHypergraphSyncWithConcurrentCommits(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	enc := verenc.NewMPCitHVerifiableEncryptor(1)
	inclusionProver := bls48581.NewKZGInclusionProver(logger)

	logDuration := func(step string, start time.Time) {
		t.Logf("%s took %s", step, time.Since(start))
	}

	start := time.Now()
	dataTrees := make([]*tries.VectorCommitmentTree, 10000)
	eg := errgroup.Group{}
	eg.SetLimit(10000)
	for i := 0; i < 10000; i++ {
		eg.Go(func() error {
			dataTrees[i] = buildDataTree(t, inclusionProver)
			return nil
		})
	}
	eg.Wait()
	logDuration("generated data trees", start)

	serverPath := filepath.Join(t.TempDir(), "server")
	clientBase := filepath.Join(t.TempDir(), "clients")

	setupStart := time.Now()
	serverDB := store.NewPebbleDB(logger, &config.DBConfig{Path: serverPath}, 0)
	defer serverDB.Close()

	serverStore := store.NewPebbleHypergraphStore(
		&config.DBConfig{Path: serverPath},
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
		clientPath := filepath.Join(clientBase, fmt.Sprintf("client-%d", i))
		clientDBs[i] = store.NewPebbleDB(logger, &config.DBConfig{Path: clientPath}, 0)
		clientStores[i] = store.NewPebbleHypergraphStore(
			&config.DBConfig{Path: clientPath},
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
		)
		require.NoError(t, err)
		return conn, protobufs.NewHypergraphComparisonServiceClient(conn)
	}

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
				stream, err := client.HyperStream(streamCtx)
				require.NoError(t, err)
				clientHG.Sync(
					stream,
					shardKey,
					protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
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
	serverRoot := serverHG.GetVertexAddsSet(shardKey).GetTree().Commit(false)
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
			stream, err := client.HyperStream(streamCtx)
			require.NoError(t, err)
			err = clientHGs[idx].Sync(
				stream,
				shardKey,
				protobufs.HypergraphPhaseSet_HYPERGRAPH_PHASE_SET_VERTEX_ADDS,
			)
			require.NoError(t, err)
			require.NoError(t, stream.CloseSend())
			cancelStream()
			conn.Close()

			_, err = clientHGs[idx].Commit(101)
			require.NoError(t, err)
			clientRoot := clientHGs[idx].GetVertexAddsSet(shardKey).GetTree().Commit(false)
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
