package application_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/txaty/go-merkletree"
	"go.uber.org/zap"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

func TestHandleProverJoin(t *testing.T) {
	log, _ := zap.NewDevelopment()
	bpub, bprivKey, _ := ed448.GenerateKey(rand.Reader)
	app := &application.TokenApplication{
		Beacon:     bpub,
		CoinStore:  store.NewPebbleCoinStore(store.NewInMemKVDB(), log),
		ClockStore: store.NewPebbleClockStore(store.NewInMemKVDB(), log),
		Logger:     log,
		Difficulty: 200000,
		Tries: []*tries.RollingFrecencyCritbitTrie{
			&tries.RollingFrecencyCritbitTrie{},
		},
	}

	baddr, _ := poseidon.HashBytes(bpub)

	app.Tries[0].Add(baddr.FillBytes(make([]byte, 32)), 0)

	peerPrivKey, err := hex.DecodeString("8bdc6de5a6781375b2915a74ccc97c0572ca69766ae41dba40170ee88313ade030ad5e5f4fe4ca111141d54c60e2c73ccbc51e1442366446b3a678a36247e9d0889b384a4e7ce9a6323fe3a386446ec1214d374a42d55fb741d4888f74fbfe60cf2595da44b659eae88db06210bc33c88000")
	if err != nil {
		t.FailNow()
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		t.FailNow()
	}

	pub := privKey.GetPublic()
	pubkey, err := pub.Raw()
	if err != nil {
		t.FailNow()
	}

	peerId, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.FailNow()
	}

	addrBI, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		t.FailNow()
	}

	addr := addrBI.FillBytes(make([]byte, 32))
	wprover := qcrypto.NewWesolowskiFrameProver(app.Logger)
	gen, _, err := wprover.CreateDataGenesisFrame(
		p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3),
		make([]byte, 516),
		10000,
		&qcrypto.InclusionAggregateProof{},
		[][]byte{bpub},
	)
	selbi, _ := gen.GetSelector()
	txn, _ := app.ClockStore.NewTransaction(false)
	app.ClockStore.StageDataClockFrame(selbi.FillBytes(make([]byte, 32)), gen, txn)
	app.ClockStore.CommitDataClockFrame(gen.Filter, 0, selbi.FillBytes(make([]byte, 32)), app.Tries, txn, false)
	txn.Commit()
	join := &protobufs.AnnounceProverJoin{
		Filter:      bytes.Repeat([]byte{0xff}, 32),
		FrameNumber: 0,
	}
	assert.NoError(t, join.SignED448(pubkey, privKey.Sign))
	assert.NoError(t, join.Validate())
	app, success, fail, err := app.ApplyTransitions(
		1,
		&protobufs.TokenRequests{
			Requests: []*protobufs.TokenRequest{
				join.TokenRequest(),
			},
		},
		false,
	)
	assert.NoError(t, err)

	assert.Len(t, success.Requests, 1)
	assert.Len(t, fail.Requests, 0)
	app.Tries = append(app.Tries, &tries.RollingFrecencyCritbitTrie{})
	app.Tries[1].Add(addr, 0)
	txn, _ = app.ClockStore.NewTransaction(false)
	frame1, _ := wprover.ProveDataClockFrame(gen, [][]byte{}, []*protobufs.InclusionAggregateProof{}, bprivKey, time.Now().UnixMilli(), 10000)
	selbi, _ = frame1.GetSelector()
	app.ClockStore.StageDataClockFrame(selbi.FillBytes(make([]byte, 32)), frame1, txn)
	app.ClockStore.CommitDataClockFrame(frame1.Filter, 1, selbi.FillBytes(make([]byte, 32)), app.Tries, txn, false)
	txn.Commit()
	join = &protobufs.AnnounceProverJoin{
		Filter:      bytes.Repeat([]byte{0xff}, 32),
		FrameNumber: 0,
	}
	assert.NoError(t, join.SignED448(pubkey, privKey.Sign))
	assert.NoError(t, join.Validate())
	_, success, fail, err = app.ApplyTransitions(
		2,
		&protobufs.TokenRequests{
			Requests: []*protobufs.TokenRequest{
				join.TokenRequest(),
			},
		},
		false,
	)
	assert.Error(t, err)
	txn, _ = app.ClockStore.NewTransaction(false)
	frame2, _ := wprover.ProveDataClockFrame(frame1, [][]byte{}, []*protobufs.InclusionAggregateProof{}, bprivKey, time.Now().UnixMilli(), 10000)
	selbi, _ = frame2.GetSelector()
	app.ClockStore.StageDataClockFrame(selbi.FillBytes(make([]byte, 32)), frame2, txn)
	app.ClockStore.CommitDataClockFrame(frame2.Filter, 2, selbi.FillBytes(make([]byte, 32)), app.Tries, txn, false)
	txn.Commit()

	challenge := []byte{}
	challenge = append(challenge, []byte(peerId)...)
	challenge = binary.BigEndian.AppendUint64(
		challenge,
		2,
	)
	individualChallenge := append([]byte{}, challenge...)
	individualChallenge = binary.BigEndian.AppendUint32(
		individualChallenge,
		uint32(0),
	)
	individualChallenge = append(individualChallenge, frame2.Output...)
	fmt.Printf("%x\n", individualChallenge)
	out1, _ := wprover.CalculateChallengeProof(individualChallenge, 10000)

	individualChallenge = append([]byte{}, challenge...)
	individualChallenge = binary.BigEndian.AppendUint32(
		individualChallenge,
		uint32(1),
	)
	individualChallenge = append(individualChallenge, frame2.Output...)
	fmt.Printf("%x\n", individualChallenge)
	out2, _ := wprover.CalculateChallengeProof(individualChallenge, 10000)

	proofTree, output, err := tries.PackOutputIntoPayloadAndProof(
		[]merkletree.DataBlock{tries.NewProofLeaf(out1), tries.NewProofLeaf(out2)},
		2,
		frame2,
		nil,
	)
	assert.NoError(t, err)

	mint := &protobufs.MintCoinRequest{
		Proofs: output,
	}
	assert.NoError(t, mint.SignED448(pubkey, privKey.Sign))
	assert.NoError(t, mint.Validate())

	app, success, _, err = app.ApplyTransitions(2, &protobufs.TokenRequests{
		Requests: []*protobufs.TokenRequest{
			mint.TokenRequest(),
		},
	}, false)

	assert.NoError(t, err)
	assert.Len(t, success.Requests, 1)
	assert.Len(t, app.TokenOutputs.Outputs, 1)
	txn, _ = app.CoinStore.NewTransaction(false)
	for i, o := range app.TokenOutputs.Outputs {
		switch e := o.Output.(type) {
		case *protobufs.TokenOutput_Coin:
			a, err := token.GetAddressOfCoin(e.Coin, 1, uint64(i))
			assert.NoError(t, err)
			err = app.CoinStore.PutCoin(txn, 1, a, e.Coin)
			assert.NoError(t, err)
		case *protobufs.TokenOutput_DeletedCoin:
			c, err := app.CoinStore.GetCoinByAddress(txn, e.DeletedCoin.Address)
			assert.NoError(t, err)
			err = app.CoinStore.DeleteCoin(txn, e.DeletedCoin.Address, c)
			assert.NoError(t, err)
		case *protobufs.TokenOutput_Proof:
			a, err := token.GetAddressOfPreCoinProof(e.Proof)
			assert.NoError(t, err)
			err = app.CoinStore.PutPreCoinProof(txn, 1, a, e.Proof)
			assert.NoError(t, err)
		case *protobufs.TokenOutput_DeletedProof:
			a, err := token.GetAddressOfPreCoinProof(e.DeletedProof)
			assert.NoError(t, err)
			c, err := app.CoinStore.GetPreCoinProofByAddress(a)
			assert.NoError(t, err)
			err = app.CoinStore.DeletePreCoinProof(txn, a, c)
			assert.NoError(t, err)
		}
	}
	err = txn.Commit()
	txn, _ = app.ClockStore.NewTransaction(false)
	frame3, _ := wprover.ProveDataClockFrame(frame2, [][]byte{}, []*protobufs.InclusionAggregateProof{}, bprivKey, time.Now().UnixMilli(), 10000)
	selbi, _ = frame3.GetSelector()
	app.ClockStore.StageDataClockFrame(selbi.FillBytes(make([]byte, 32)), frame3, txn)
	app.ClockStore.CommitDataClockFrame(frame3.Filter, 3, selbi.FillBytes(make([]byte, 32)), app.Tries, txn, false)
	txn.Commit()

	proofTree, output, err = tries.PackOutputIntoPayloadAndProof(
		[]merkletree.DataBlock{tries.NewProofLeaf(out1), tries.NewProofLeaf(out2)},
		2,
		frame3,
		proofTree,
	)
	assert.NoError(t, err)

	mint = &protobufs.MintCoinRequest{
		Proofs: output,
	}
	assert.NoError(t, mint.SignED448(pubkey, privKey.Sign))
	assert.NoError(t, mint.Validate())

	app, success, _, err = app.ApplyTransitions(3, &protobufs.TokenRequests{
		Requests: []*protobufs.TokenRequest{
			mint.TokenRequest(),
		},
	}, false)
	assert.NoError(t, err)
	assert.Len(t, success.Requests, 1)
	assert.Len(t, app.TokenOutputs.Outputs, 3)
}
