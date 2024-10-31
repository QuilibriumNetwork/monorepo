package time_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	gotime "time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

func generateTestProvers() (
	keys.KeyManager,
	[]peer.ID,
	[][]byte,
	[][]byte,
	map[string]string,
	*tries.RollingFrecencyCritbitTrie,
) {
	keyManager := keys.NewInMemoryKeyManager()
	peers := []peer.ID{}
	pubKeys := [][]byte{}
	privKeys := [][]byte{}
	addrMap := map[string]string{}
	for i := 0; i < 1000; i++ {
		keyManager.CreateSigningKey(
			fmt.Sprintf("test-key-%d", i),
			keys.KeyTypeEd448,
		)
		k, err := keyManager.GetRawKey(fmt.Sprintf("test-key-%d", i))
		if err != nil {
			panic(err)
		}

		privKey, err := crypto.UnmarshalEd448PrivateKey([]byte(k.PrivateKey))
		if err != nil {
			panic(err)
		}

		privKeys = append(privKeys, []byte(k.PrivateKey))

		pub := privKey.GetPublic()
		id, err := peer.IDFromPublicKey(pub)
		if err != nil {
			panic(err)
		}

		peers = append(peers, id)

		keyManager.CreateSigningKey(
			fmt.Sprintf("proving-key-%d", i),
			keys.KeyTypeEd448,
		)
		pk, err := keyManager.GetRawKey(fmt.Sprintf("proving-key-%d", i))
		if err != nil {
			panic(err)
		}

		pprivKey, err := crypto.UnmarshalEd448PrivateKey([]byte(pk.PrivateKey))
		if err != nil {
			panic(err)
		}

		ppub := pprivKey.GetPublic()
		ppubKey, err := ppub.Raw()
		if err != nil {
			panic(err)
		}

		pubKeys = append(pubKeys, ppubKey)
	}

	proverTrie := &tries.RollingFrecencyCritbitTrie{}

	for i, s := range pubKeys {
		addr, err := poseidon.HashBytes(s)
		if err != nil {
			panic(err)
		}

		addrBytes := addr.Bytes()
		addrBytes = append(make([]byte, 32-len(addrBytes)), addrBytes...)
		proverTrie.Add(addrBytes, 0)
		addrMap[string(addrBytes)] = fmt.Sprintf("proving-key-%d", i)
	}

	return keyManager,
		peers,
		pubKeys,
		privKeys,
		addrMap,
		proverTrie
}

func TestDataTimeReel(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	db := store.NewInMemKVDB()
	clockStore := store.NewPebbleClockStore(db, logger)
	prover := qcrypto.NewWesolowskiFrameProver(logger)
	filter := "0000000000000000000000000000000000000000000000000000000000000000"
	keyManager,
		_,
		pubKeys,
		_,
		addrMap,
		proverTrie := generateTestProvers()

	// We're going to set this up by churning 40 master frames so we don't
	// have to zig zag on master and data frames to confirm data time reel
	// behaviors
	m := time.NewMasterTimeReel(
		logger,
		clockStore,
		&config.EngineConfig{
			Filter:      filter,
			GenesisSeed: strings.Repeat("00", 516),
			Difficulty:  10,
		},
		prover,
	)

	err := m.Start()
	assert.NoError(t, err)

	frame, err := m.Head()
	assert.NoError(t, err)

	filterBytes := []byte{
		0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff,
	}

	// Ok, now onto the data time reel. We're going to test the following
	// scenarios:
	// 1. Z-dist optimal, in order
	// 2. Z-dist optimal, out of order
	// 3. 90% optimal, out of order
	// 4. Malicious majority, out of order
	d := time.NewDataTimeReel(
		filterBytes,
		logger,
		clockStore,
		&config.EngineConfig{
			Filter:      filter,
			GenesisSeed: strings.Repeat("00", 516),
			Difficulty:  10,
		},
		prover,
		func(txn store.Transaction, frame *protobufs.ClockFrame) error { return nil },
		bytes.Repeat([]byte{0x00}, 516),
		&qcrypto.InclusionAggregateProof{
			InclusionCommitments: []*qcrypto.InclusionCommitment{},
			AggregateCommitment:  []byte{},
			Proof:                []byte{},
		},
		pubKeys,
	)

	err = d.Start()
	assert.NoError(t, err)

	frame, err = d.Head()
	assert.NoError(t, err)

	dataFrames := []*protobufs.ClockFrame{}
	datawg := sync.WaitGroup{}
	datawg.Add(1)
	dataFrameCh := d.NewFrameCh()
	go func() {
	loop:
		for {
			select {
			case frame := <-dataFrameCh:
				dataFrames = append(dataFrames, frame)
				if frame.FrameNumber == 500 {
					break loop
				}
			}
		}
		datawg.Done()
	}()

	prev := make([]byte, 32)
	// 1. z-dist optimal – proof submission is strictly master-frame evoked leader
	for i := int64(0); i < 100; i++ {
		proverSelection := proverTrie.FindNearest(
			prev,
		)
		optimalSigner, _ := keyManager.GetSigningKey(
			addrMap[string(proverSelection.External.Key)],
		)
		frame, err = prover.ProveDataClockFrame(
			frame,
			[][]byte{},
			[]*protobufs.InclusionAggregateProof{},
			optimalSigner,
			i+1,
			10,
		)
		d.Insert(frame, false)
		prevBI, _ := frame.GetSelector()
		prev = prevBI.FillBytes(make([]byte, 32))
	}

	// 2. z-dist optimal, out of order – proof submission is strictly master-frame
	// evoked leader, but arrived completely backwards
	insertFrames := []*protobufs.ClockFrame{}

	for i := int64(100); i < 200; i++ {
		proverSelection := proverTrie.FindNearest(
			prev,
		)
		optimalSigner, _ := keyManager.GetSigningKey(
			addrMap[string(proverSelection.External.Key)],
		)
		frame, err = prover.ProveDataClockFrame(
			frame,
			[][]byte{},
			[]*protobufs.InclusionAggregateProof{},
			optimalSigner,
			i+1,
			10,
		)
		insertFrames = append(insertFrames, frame)

		prevBI, _ := frame.GetSelector()
		prev = prevBI.FillBytes(make([]byte, 32))
	}

	for i := 99; i >= 0; i-- {
		err := d.Insert(insertFrames[i], false)
		assert.NoError(t, err)
	}

	// 3. 90% optimal, out of order
	insertFrames = []*protobufs.ClockFrame{}

	for i := int64(200); i < 300; i++ {
		proverSelection := proverTrie.FindNearest(
			prev,
		)
		optimalSigner, _ := keyManager.GetSigningKey(
			addrMap[string(proverSelection.External.Key)],
		)
		frame, err = prover.ProveDataClockFrame(
			frame,
			[][]byte{},
			[]*protobufs.InclusionAggregateProof{},
			optimalSigner,
			i+1,
			10,
		)
		d.Insert(frame, false)

		prevBI, _ := frame.GetSelector()
		prev = prevBI.FillBytes(make([]byte, 32))
	}

	proverSelections := proverTrie.FindNearestAndApproximateNeighbors(
		prev,
	)
	suboptimalSigner2, _ := keyManager.GetSigningKey(
		addrMap[string(proverSelections[2].External.Key)],
	)
	// What we're trying to simulate: consensus heads progressed on a slightly
	// less optimal prover.
	frame, err = prover.ProveDataClockFrame(
		frame,
		[][]byte{},
		[]*protobufs.InclusionAggregateProof{},
		suboptimalSigner2,
		301,
		10,
	)
	insertFrames = append(insertFrames, frame)

	prevBI, _ := frame.GetSelector()
	prev = prevBI.FillBytes(make([]byte, 32))

	for i := int64(301); i < 400; i++ {
		proverSelection := proverTrie.FindNearest(
			prev,
		)
		optimalSigner, _ := keyManager.GetSigningKey(
			addrMap[string(proverSelection.External.Key)],
		)
		frame, err = prover.ProveDataClockFrame(
			frame,
			[][]byte{},
			[]*protobufs.InclusionAggregateProof{},
			optimalSigner,
			i+1,
			10,
		)
		insertFrames = append(insertFrames, frame)
		prevBI, _ := frame.GetSelector()
		prev = prevBI.FillBytes(make([]byte, 32))
	}

	for i := 99; i >= 0; i-- {
		err := d.Insert(insertFrames[i], false)
		assert.NoError(t, err)
	}

	// 4. Malicious majority, out of order – handle a suppressive majority and
	// force consensus on the lowest distance sub-tree:
	insertFrames = []*protobufs.ClockFrame{}
	conflictFrames := []*protobufs.ClockFrame{}
	optimalKeySet := [][]byte{}
	suppressedFrame := frame
	for i := int64(400); i < 500; i++ {
		proverSelections := proverTrie.FindNearestAndApproximateNeighbors(
			prev,
		)
		optimalSigner, _ := keyManager.GetSigningKey(
			addrMap[string(proverSelections[0].External.Key)],
		)
		suboptimalSigner2, _ := keyManager.GetSigningKey(
			addrMap[string(proverSelections[2].External.Key)],
		)
		optimalKeySet = append(optimalKeySet, []byte(
			(optimalSigner.Public()).(ed448.PublicKey),
		))

		// What we're trying to simulate: the majority is intentionally ignoring
		// the most optimal signer
		suppressedFrame, err = prover.ProveDataClockFrame(
			suppressedFrame,
			[][]byte{},
			[]*protobufs.InclusionAggregateProof{},
			optimalSigner,
			i+1,
			10,
		)
		prevBI, _ := suppressedFrame.GetSelector()
		prev = prevBI.FillBytes(make([]byte, 32))

		insertFrames = append(insertFrames, suppressedFrame)
		frame, err = prover.ProveDataClockFrame(
			frame,
			[][]byte{},
			[]*protobufs.InclusionAggregateProof{},
			suboptimalSigner2,
			i+1,
			10,
		)
		conflictFrames = append(conflictFrames, frame)
	}

	rand.Shuffle(100, func(i, j int) {
		insertFrames[i], insertFrames[j] = insertFrames[j], insertFrames[i]
	})

	// todo: restore with prover rings
	// for i := 99; i >= 0; i-- {
	// 	err := d.Insert(conflictFrames[i], false)
	// 	// force linear ordering
	// 	gotime.Sleep(1 * gotime.Second)
	// 	assert.NoError(t, err)
	// }

	// Someone is honest, but running backwards:
	for i := 99; i >= 0; i-- {
		err := d.Insert(insertFrames[i], false)
		gotime.Sleep(1 * gotime.Second)
		assert.NoError(t, err)
	}

	datawg.Wait()

	assert.Equal(t, uint64(500), dataFrames[len(dataFrames)-1].FrameNumber)
	assert.Equal(
		t,
		optimalKeySet[len(optimalKeySet)-1],
		dataFrames[len(dataFrames)-1].GetPublicKeySignatureEd448().PublicKey.KeyValue,
	)
}
