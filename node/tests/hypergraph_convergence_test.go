package tests

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha512"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/config"
	hg "source.quilibrium.com/quilibrium/monorepo/hypergraph"
	pebblestore "source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/mocks"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

type Operation struct {
	Type      string // "AddVertex", "RemoveVertex", "AddHyperedge", "RemoveHyperedge"
	Vertex    hypergraph.Vertex
	Hyperedge hypergraph.Hyperedge
}

func TestConvergence(t *testing.T) {
	numParties := 4
	numOperations := 10000
	enc := &mocks.MockVerifiableEncryptor{}
	incProver := &mocks.MockInclusionProver{}
	vep := &mocks.MockVerEncProof{}
	ve := &mocks.MockVerEnc{}
	pub, _, _ := ed448.GenerateKey(crand.Reader)
	mockCommit := make([]byte, 74)
	mockCommit[0] = 0x02
	crand.Read(mockCommit[1:])
	incProver.On("CommitRaw", mock.Anything, mock.Anything).Return(mockCommit, nil)
	ve.On("ToBytes").Return([]byte{})
	ve.On("GetStatement").Return(make([]byte, 74))
	vep.On("Compress").Return(ve)
	enc.On("Encrypt", make([]byte, 20), []byte(pub)).Return([]crypto.VerEncProof{
		vep,
	})
	data := enc.Encrypt(make([]byte, 20), pub)
	verenc := data[0].Compress()
	vertices := make([]hypergraph.Vertex, numOperations)
	dataTree := &tries.VectorCommitmentTree{}
	for _, d := range []hypergraph.Encrypted{verenc} {
		dataBytes := d.ToBytes()
		id := sha512.Sum512(dataBytes)
		dataTree.Insert(id[:], dataBytes, d.GetStatement(), big.NewInt(int64(len(data)*55)))
	}
	dataTree.Commit(incProver, false)
	for i := 0; i < numOperations; i++ {
		vertices[i] = hg.NewVertex(
			[32]byte{byte((i >> 8) % 256), byte((i % 256))},
			[32]byte{byte((i >> 8) / 256), byte(i / 256)},
			dataTree.Commit(incProver, false),
			dataTree.GetSize(),
		)
	}

	hyperedges := make([]hypergraph.Hyperedge, numOperations/100)
	for i := 0; i < numOperations/100; i++ {
		hyperedges[i] = hg.NewHyperedge(
			[32]byte{0, 0, byte((i >> 8) % 256), byte(i % 256)},
			[32]byte{0, 0, byte((i >> 8) / 256), byte(i / 256)},
		)
		for j := 0; j < 3; j++ {
			v := vertices[rand.Intn(len(vertices))]
			hyperedges[i].AddExtrinsic(v)
		}
	}

	operations1 := make([]Operation, numOperations)
	operations2 := make([]Operation, numOperations)
	operations3 := make([]Operation, numOperations)
	operations4 := make([]Operation, numOperations)
	for i := 0; i < numOperations; i++ {
		op := rand.Intn(2)
		switch op {
		case 0:
			operations1[i] = Operation{Type: "AddVertex", Vertex: vertices[i]}
		case 1:
			operations2[i] = Operation{Type: "AddVertex", Vertex: vertices[i]}
		}
	}
	for i := 0; i < numOperations; i++ {
		op := rand.Intn(2)
		switch op {
		case 0:
			operations3[i] = Operation{Type: "AddHyperedge", Hyperedge: hyperedges[rand.Intn(len(hyperedges))]}
		case 1:
			operations4[i] = Operation{Type: "RemoveHyperedge", Hyperedge: hyperedges[rand.Intn(len(hyperedges))]}
		}
	}

	crdts := make([]*hg.HypergraphCRDT, numParties)
	var store0 store.KVDB
	for i := 0; i < numParties; i++ {
		logger, _ := zap.NewDevelopment()
		s := pebblestore.NewPebbleDB(logger, &config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, 0)
		if i == 0 {
			store0 = s
		}
		hgs := pebblestore.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, s, logger, enc, incProver)
		crdts[i] = hg.NewHypergraph(logger, hgs, incProver, []int{}, &Nopthenticator{})
		hgs.MarkHypergraphAsComplete()
	}

	for i := 0; i < numParties; i++ {
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(operations1), func(i, j int) { operations1[i], operations1[j] = operations1[j], operations1[i] })
		rand.Shuffle(len(operations2), func(i, j int) { operations2[i], operations2[j] = operations2[j], operations2[i] })
		rand.Shuffle(len(operations3), func(i, j int) { operations3[i], operations3[j] = operations3[j], operations3[i] })
		rand.Shuffle(len(operations4), func(i, j int) { operations4[i], operations4[j] = operations4[j], operations4[i] })

		for _, op := range operations1 {
			switch op.Type {
			case "AddVertex":
				crdts[i].AddVertex(nil, op.Vertex)
			case "RemoveVertex":
				crdts[i].RemoveVertex(nil, op.Vertex)
			case "AddHyperedge":
				crdts[i].AddHyperedge(nil, op.Hyperedge)
			case "RemoveHyperedge":
				crdts[i].RemoveHyperedge(nil, op.Hyperedge)
			}
		}
		for _, op := range operations2 {
			switch op.Type {
			case "AddVertex":
				crdts[i].AddVertex(nil, op.Vertex)
			case "RemoveVertex":
				crdts[i].RemoveVertex(nil, op.Vertex)
			case "AddHyperedge":
				crdts[i].AddHyperedge(nil, op.Hyperedge)
			case "RemoveHyperedge":
				crdts[i].RemoveHyperedge(nil, op.Hyperedge)
			}
		}
		for _, op := range operations3 {
			switch op.Type {
			case "AddVertex":
				crdts[i].AddVertex(nil, op.Vertex)
			case "RemoveVertex":
				crdts[i].RemoveVertex(nil, op.Vertex)
			case "AddHyperedge":
				crdts[i].AddHyperedge(nil, op.Hyperedge)
			case "RemoveHyperedge":
				crdts[i].RemoveHyperedge(nil, op.Hyperedge)
			}
		}
		for _, op := range operations4 {
			switch op.Type {
			case "AddVertex":
				crdts[i].AddVertex(nil, op.Vertex)
			case "RemoveVertex":
				crdts[i].RemoveVertex(nil, op.Vertex)
			case "AddHyperedge":
				crdts[i].AddHyperedge(nil, op.Hyperedge)
			case "RemoveHyperedge":
				crdts[i].RemoveHyperedge(nil, op.Hyperedge)
			}
		}
	}

	crdts[0].GetSize(nil, nil)

	for _, v := range vertices {
		state := crdts[0].LookupVertex(v)
		for i := 1; i < numParties; i++ {
			if crdts[i].LookupVertex(v) != state {
				t.Errorf("Vertex %v has different state in CRDT %d", v, i)
			}
		}
	}
	for _, h := range hyperedges {
		state := crdts[0].LookupHyperedge(h)
		for i := 1; i < numParties; i++ {
			if crdts[i].LookupHyperedge(h) != state {
				t.Errorf("Hyperedge %v has different state in CRDT %d, %v", h, i, state)
			}
		}
	}

	logger, _ := zap.NewDevelopment()
	hgs := pebblestore.NewPebbleHypergraphStore(&config.DBConfig{InMemoryDONOTUSE: true, Path: ".configtest/store"}, store0, logger, enc, incProver)
	compload, err := hgs.LoadHypergraph(&Nopthenticator{})
	if err != nil {
		t.Errorf("Could not load hg, %v", err)
	}

	for _, v := range vertices {
		state := crdts[0].LookupVertex(v)
		if compload.LookupVertex(v) != state {
			t.Errorf("Vertex %v has different state in loaded CRDT", v)
		}
		if state {
			loadvert, err := compload.GetVertex(v.GetID())
			if err != nil {
				t.Errorf("Vertex %v could not be loaded in loaded CRDT, %v", v, err)
			}

			vb1 := v.ToBytes()
			vb2 := loadvert.ToBytes()
			if !bytes.Equal(vb1, vb2) {
				t.Errorf("Vertex %v does not match the one loaded in loaded CRDT\n%x\n%x", v, vb1, vb2)
			}
		}
	}
	for _, h := range hyperedges {
		state := crdts[0].LookupHyperedge(h)
		if compload.LookupHyperedge(h) != state {
			t.Errorf("Hyperedge %v has different state in loaded CRDT", h)
		}
		if state {
			loadhe, err := compload.GetHyperedge(h.GetID())
			if err != nil {
				t.Errorf("Hyperedge %v could not be loaded in loaded CRDT, %v", h, err)
			}

			hb1 := h.ToBytes()
			hb2 := loadhe.ToBytes()
			if !bytes.Equal(hb1, hb2) {
				t.Errorf("Hyperedge %v does not match the one loaded in loaded CRDT\n%x\n%x", h, hb1, hb2)
			}
		}
	}
}
