package token

import (
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/mr-tron/base58"
	"github.com/shopspring/decimal"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/vdf"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	hypergraph "source.quilibrium.com/quilibrium/monorepo/node/hypergraph/application"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

var BridgeAddress = "1ac3290d57e064bdb5a57e874b59290226a9f9730d69f1d963600883789d6ee2"

type BridgedPeerJson struct {
	Amount     string `json:"amount"`
	Identifier string `json:"identifier"`
	Variant    string `json:"variant"`
}

type FirstRetroJson struct {
	PeerId string `json:"peerId"`
	Reward string `json:"reward"`
}

type SecondRetroJson struct {
	PeerId      string `json:"peerId"`
	Reward      string `json:"reward"`
	JanPresence bool   `json:"janPresence"`
	FebPresence bool   `json:"febPresence"`
	MarPresence bool   `json:"marPresence"`
	AprPresence bool   `json:"aprPresence"`
	MayPresence bool   `json:"mayPresence"`
}

type ThirdRetroJson struct {
	PeerId string `json:"peerId"`
	Reward string `json:"reward"`
}

type FourthRetroJson struct {
	PeerId string `json:"peerId"`
	Reward string `json:"reward"`
}

//go:embed bridged.json
var bridgedPeersJsonBinary []byte

//go:embed ceremony_vouchers.json
var ceremonyVouchersJsonBinary []byte

//go:embed first_retro.json
var firstRetroJsonBinary []byte

//go:embed second_retro.json
var secondRetroJsonBinary []byte

//go:embed third_retro.json
var thirdRetroJsonBinary []byte

//go:embed fourth_retro.json
var fourthRetroJsonBinary []byte

var firstRetro []*FirstRetroJson
var secondRetro []*SecondRetroJson
var thirdRetro []*ThirdRetroJson
var fourthRetro []*FourthRetroJson

func LoadAggregatedSeniorityMap(network uint) {
	if network != 0 {
		// testnet values are fixed to confirm test behaviors
		firstRetro = []*FirstRetroJson{
			{
				PeerId: "QmTG8UAmrYBdLi76CEkXK7equRcoRRKBjbkK44oT6TcEGU",
				Reward: "157208",
			},
			{
				PeerId: "QmRZMVG1VbBWMEensjqBS7XqBzNfCoA5HxdDwCuouUeY16",
				Reward: "157208",
			},
			{
				PeerId: "QmWwqsH3vwPkRufqtdS1sgxgWwg8i4sgsfpeDy9BbX259p",
				Reward: "78604",
			},
			{
				PeerId: "QmNtGTnGLpi35sLmrgwd2EaUJFNz99WBd7ZzzRaw8GYo9e",
				Reward: "78604",
			},
			{
				PeerId: "QmSjeYnJAbUEq3vdVP89PNbKuTfFgLXZ1cLKaWShbs2hvW",
				Reward: "78604",
			},
			{
				PeerId: "QmQrhv7bymSWPaJsatr3kdp14GP2JpTE128syPVj3eUjLy",
				Reward: "78604",
			},
			{
				PeerId: "QmNPx7PKUS6bz9MbJciWPDDRi6ufJ6vBgVqGrSXaUyUgb6",
				Reward: "39302",
			},
			{
				PeerId: "QmSdBumdhuWwMvb38XkExqGoGQ2jjjaFaVWKejEynFZJ8L",
				Reward: "39302",
			},
			{
				PeerId: "Qma3bMDgVjCNgvSd3uomekF4v7Pq4VkTyT5R31FfdrqSan",
				Reward: "39302",
			},
		}
		secondRetro = []*SecondRetroJson{
			{
				PeerId:      "QmeafLbKKfmRKQdF7LK1Z3ayNbzwRLmRpZCtjBXrGKZzht",
				Reward:      "1000",
				JanPresence: true,
				FebPresence: true,
				MarPresence: false,
				AprPresence: false,
				MayPresence: false,
			},
			{
				PeerId:      "QmaPh3cY9Gi8CbBr4H7nTZUABu8cJwXxRnp2utgg1urGjp",
				Reward:      "1000",
				JanPresence: true,
				FebPresence: true,
				MarPresence: false,
				AprPresence: false,
				MayPresence: false,
			},
			{
				PeerId:      "QmapvC4ApSxBz1J6Cdfra8375pJRo1FKp1bad5mLvn3KEK",
				Reward:      "1000",
				JanPresence: true,
				FebPresence: true,
				MarPresence: false,
				AprPresence: false,
				MayPresence: false,
			},
			{
				PeerId:      "QmUbgmwR3Z8Vp9zHHeuGRxRrfh4YzLF5CbW48Ur8Kx9jAP",
				Reward:      "1000",
				JanPresence: true,
				FebPresence: true,
				MarPresence: false,
				AprPresence: false,
				MayPresence: false,
			},
			{
				PeerId:      "QmYM47WUWSz8X13rXpcR2RPagSVAnjkwRw9V5Ps7X6quit",
				Reward:      "1000",
				JanPresence: true,
				FebPresence: true,
				MarPresence: false,
				AprPresence: false,
				MayPresence: false,
			},
			{
				PeerId:      "QmUVZVDBRusH8wh8qfVoveTp9PwZTb2PxMXSLdbcznUVEo",
				Reward:      "1000",
				JanPresence: true,
				FebPresence: true,
				MarPresence: false,
				AprPresence: false,
				MayPresence: false,
			},
			{
				PeerId:      "QmZCMe29zbGkqceyzjjmzND9nDUMcWyMBUZSzMhns1sejH",
				Reward:      "1000",
				JanPresence: true,
				FebPresence: true,
				MarPresence: false,
				AprPresence: false,
				MayPresence: false,
			},
		}
		thirdRetro = []*ThirdRetroJson{
			{
				PeerId: "QmZ36PUzJYMM7Mz319cXwDZNtYuhtuFChcWep2ZY25ZGMN",
				Reward: "1000",
			},
			{
				PeerId: "QmaQuJGk6fGrYYTQiBFFasKLxSKkEkPaywEKoVbnXULEEG",
				Reward: "1000",
			},
		}
		fourthRetro = []*FourthRetroJson{}
		return
	}

	firstRetro = []*FirstRetroJson{}
	secondRetro = []*SecondRetroJson{}
	thirdRetro = []*ThirdRetroJson{}
	fourthRetro = []*FourthRetroJson{}

	err := json.Unmarshal(firstRetroJsonBinary, &firstRetro)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(secondRetroJsonBinary, &secondRetro)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(thirdRetroJsonBinary, &thirdRetro)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(fourthRetroJsonBinary, &fourthRetro)
	if err != nil {
		panic(err)
	}
}

func RebuildPeerSeniority(network uint) (map[string]uint64, error) {
	if network != 0 {
		// testnet values are fixed to confirm test behaviors
		firstRetro = []*FirstRetroJson{
			{
				PeerId: "QmTG8UAmrYBdLi76CEkXK7equRcoRRKBjbkK44oT6TcEGU",
				Reward: "157208",
			},
			{
				PeerId: "QmVDhgHgpvFG2ZiCYhUPKXA8i5j8Fp9zoGE5Bc6SLwsiuA",
				Reward: "157208",
			},
			{
				PeerId: "QmRZMVG1VbBWMEensjqBS7XqBzNfCoA5HxdDwCuouUeY16",
				Reward: "157208",
			},
			{
				PeerId: "QmPpk2cbkpzAiadWDQVCL4XBukLNNY4BujT9LYq3DYE3ZR",
				Reward: "157208",
			},
			{
				PeerId: "QmR3Xuc3t7zbnUy5fcC4iY58fnHEsFmzYra6JgY9sRqE8Y",
				Reward: "157208",
			},
			{
				PeerId: "QmPjwYSn29VoYogxAzGbh5kgGYB5rZFauSS66c3J4KkK4j",
				Reward: "78604",
			},
			{
				PeerId: "QmayFGarM7BVPYWnjAF7rBQAczXniELHKPKHS5VY8URZBd",
				Reward: "78604",
			},
			{
				PeerId: "QmWwqsH3vwPkRufqtdS1sgxgWwg8i4sgsfpeDy9BbX259p",
				Reward: "78604",
			},
			{
				PeerId: "QmNtGTnGLpi35sLmrgwd2EaUJFNz99WBd7ZzzRaw8GYo9e",
				Reward: "78604",
			},
			{
				PeerId: "QmNPx7PKUS6bz9MbJciWPDDRi6ufJ6vBgVqGrSXaUyUgb6",
				Reward: "39302",
			},
			{
				PeerId: "QmSdBumdhuWwMvb38XkExqGoGQ2jjjaFaVWKejEynFZJ8L",
				Reward: "39302",
			},
			{
				PeerId: "Qma3bMDgVjCNgvSd3uomekF4v7Pq4VkTyT5R31FfdrqSan",
				Reward: "39302",
			},
			{
				PeerId: "QmbQ9Bp4SvspysHLTAYQtFN7MY9Acae4AwVFjTy3rp7Q2A",
				Reward: "39302",
			},
			{
				PeerId: "QmUDWLhZMRoCoqkJAqvi815EJwjQAZoTm2oa9LkRwqeeAW",
				Reward: "78604",
			},
		}
		secondRetro = []*SecondRetroJson{
			{
				PeerId:      "QmPpk2cbkpzAiadWDQVCL4XBukLNNY4BujT9LYq3DYE3ZR",
				Reward:      "1000",
				JanPresence: true,
				FebPresence: true,
				MarPresence: false,
				AprPresence: false,
				MayPresence: false,
			},
			{
				PeerId:      "Qma3bMDgVjCNgvSd3uomekF4v7Pq4VkTyT5R31FfdrqSan",
				Reward:      "1000",
				JanPresence: true,
				FebPresence: true,
				MarPresence: false,
				AprPresence: false,
				MayPresence: false,
			},
			{
				PeerId:      "QmeafLbKKfmRKQdF7LK1Z3ayNbzwRLmRpZCtjBXrGKZzht",
				Reward:      "1000",
				JanPresence: true,
				FebPresence: true,
				MarPresence: false,
				AprPresence: false,
				MayPresence: false,
			},
			{
				PeerId:      "QmUbgmwR3Z8Vp9zHHeuGRxRrfh4YzLF5CbW48Ur8Kx9jAP",
				Reward:      "1000",
				JanPresence: true,
				FebPresence: true,
				MarPresence: false,
				AprPresence: false,
				MayPresence: false,
			},
			{
				PeerId:      "QmYM47WUWSz8X13rXpcR2RPagSVAnjkwRw9V5Ps7X6quit",
				Reward:      "1000",
				JanPresence: true,
				FebPresence: true,
				MarPresence: false,
				AprPresence: false,
				MayPresence: false,
			},
			{
				PeerId:      "QmUVZVDBRusH8wh8qfVoveTp9PwZTb2PxMXSLdbcznUVEo",
				Reward:      "1000",
				JanPresence: true,
				FebPresence: true,
				MarPresence: false,
				AprPresence: false,
				MayPresence: false,
			},
			{
				PeerId:      "QmZCMe29zbGkqceyzjjmzND9nDUMcWyMBUZSzMhns1sejH",
				Reward:      "1000",
				JanPresence: true,
				FebPresence: true,
				MarPresence: false,
				AprPresence: false,
				MayPresence: false,
			},
			{
				PeerId:      "QmXDWA4f3J5WxmseBfuCEsZNv8aeAkUrJ7fqoxr894tFCi",
				Reward:      "1000",
				JanPresence: true,
				FebPresence: true,
				MarPresence: false,
				AprPresence: false,
				MayPresence: false,
			},
			{
				PeerId:      "QmYSwFqgVKUFGkNM8Ae4DrarCjGKPJ4u7oJvRhrmx3YPpB",
				Reward:      "1000",
				JanPresence: true,
				FebPresence: true,
				MarPresence: false,
				AprPresence: false,
				MayPresence: false,
			},
		}
		thirdRetro = []*ThirdRetroJson{
			{
				PeerId: "QmZ36PUzJYMM7Mz319cXwDZNtYuhtuFChcWep2ZY25ZGMN",
				Reward: "1000",
			},
			{
				PeerId: "QmaQuJGk6fGrYYTQiBFFasKLxSKkEkPaywEKoVbnXULEEG",
				Reward: "1000",
			},
			{
				PeerId: "QmYKSNoRkpL3ufKLhNUS77jirDJ5zWg9yGZmrBJhBcsaoE",
				Reward: "1000",
			},
			{
				PeerId: "QmZCMe29zbGkqceyzjjmzND9nDUMcWyMBUZSzMhns1sejH",
				Reward: "1000",
			},
		}
		fourthRetro = []*FourthRetroJson{
			{
				PeerId: "QmaQuJGk6fGrYYTQiBFFasKLxSKkEkPaywEKoVbnXULEEG",
				Reward: "1000",
			},
		}
	} else {
		firstRetro = []*FirstRetroJson{}
		secondRetro = []*SecondRetroJson{}
		thirdRetro = []*ThirdRetroJson{}
		fourthRetro = []*FourthRetroJson{}

		err := json.Unmarshal(firstRetroJsonBinary, &firstRetro)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(secondRetroJsonBinary, &secondRetro)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(thirdRetroJsonBinary, &thirdRetro)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(fourthRetroJsonBinary, &fourthRetro)
		if err != nil {
			return nil, err
		}
	}

	peerSeniority := map[string]uint64{}
	for _, f := range firstRetro {
		// these don't have decimals so we can shortcut
		max := 157208
		actual, err := strconv.Atoi(f.Reward)
		if err != nil {
			return nil, err
		}

		p, _ := base58.Decode(f.PeerId)
		addr, _ := poseidon.HashBytes(p)

		peerSeniority[string(
			addr.FillBytes(make([]byte, 32)),
		)] = uint64(10 * 6 * 60 * 24 * 92 / (max / actual))
	}

	for _, f := range secondRetro {
		p, _ := base58.Decode(f.PeerId)
		addr, _ := poseidon.HashBytes(p)
		addrBytes := string(addr.FillBytes(make([]byte, 32)))

		if _, ok := peerSeniority[addrBytes]; !ok {
			peerSeniority[addrBytes] = 0
		}

		if f.JanPresence {
			peerSeniority[addrBytes] = peerSeniority[addrBytes] + (10 * 6 * 60 * 24 * 31)
		}

		if f.FebPresence {
			peerSeniority[addrBytes] = peerSeniority[addrBytes] + (10 * 6 * 60 * 24 * 29)
		}

		if f.MarPresence {
			peerSeniority[addrBytes] = peerSeniority[addrBytes] + (10 * 6 * 60 * 24 * 31)
		}

		if f.AprPresence {
			peerSeniority[addrBytes] = peerSeniority[addrBytes] + (10 * 6 * 60 * 24 * 30)
		}

		if f.MayPresence {
			peerSeniority[addrBytes] = peerSeniority[addrBytes] + (10 * 6 * 60 * 24 * 31)
		}
	}

	for _, f := range thirdRetro {
		p, _ := base58.Decode(f.PeerId)
		addr, _ := poseidon.HashBytes(p)
		addrBytes := string(addr.FillBytes(make([]byte, 32)))

		if _, ok := peerSeniority[addrBytes]; !ok {
			peerSeniority[addrBytes] = 0
		}

		peerSeniority[addrBytes] = peerSeniority[addrBytes] + (10 * 6 * 60 * 24 * 30)
	}

	for _, f := range fourthRetro {
		p, _ := base58.Decode(f.PeerId)
		addr, _ := poseidon.HashBytes(p)
		addrBytes := string(addr.FillBytes(make([]byte, 32)))

		if _, ok := peerSeniority[addrBytes]; !ok {
			peerSeniority[addrBytes] = 0
		}

		peerSeniority[addrBytes] = peerSeniority[addrBytes] + (10 * 6 * 60 * 24 * 31)
	}

	return peerSeniority, nil
}

// Creates a genesis state for the intrinsic
func CreateGenesisState(
	logger *zap.Logger,
	engineConfig *config.EngineConfig,
	testProverKeys [][]byte,
	inclusionProver qcrypto.InclusionProver,
	clockStore store.ClockStore,
	coinStore store.CoinStore,
	hypergraphStore store.HypergraphStore,
	hg *hypergraph.Hypergraph,
	mpcithVerEnc *qcrypto.MPCitHVerifiableEncryptor,
	network uint,
) (
	[]byte,
	*qcrypto.InclusionAggregateProof,
	[][]byte,
	map[string]uint64,
) {
	logger = logger.With(zap.String("stage", "create-genesis-state"))
	genesis := config.GetGenesis()
	if genesis == nil {
		logger.Panic("genesis is nil")
	}

	seed, err := hex.DecodeString(engineConfig.GenesisSeed)
	if err != nil {
		logger.Panic("failed to decode genesis seed", zap.Error(err))
	}

	logger.Info("creating genesis frame from message:")
	for i, l := range strings.Split(string(seed), "|") {
		if i == 0 {
			logger.Info(l)
		} else {
			logger.Info(fmt.Sprintf("Blockstamp ending in 0x%x", l))
		}
	}

	difficulty := engineConfig.Difficulty
	if difficulty != 200000 {
		difficulty = 200000
	}

	b := sha3.Sum256(seed)
	v := vdf.New(difficulty, b)

	v.Execute()
	o := v.GetOutput()
	inputMessage := o[:]

	logger.Info("encoding all prior state")

	if network == 0 {
		bridged := []*BridgedPeerJson{}
		vouchers := []string{}
		firstRetro = []*FirstRetroJson{}
		secondRetro = []*SecondRetroJson{}
		thirdRetro = []*ThirdRetroJson{}
		fourthRetro = []*FourthRetroJson{}

		err = json.Unmarshal(bridgedPeersJsonBinary, &bridged)
		if err != nil {
			logger.Panic("failed to unmarshal bridged peers json", zap.Error(err))
		}

		err = json.Unmarshal(ceremonyVouchersJsonBinary, &vouchers)
		if err != nil {
			logger.Panic("failed to unmarshal ceremony vouchers json", zap.Error(err))
		}

		err = json.Unmarshal(firstRetroJsonBinary, &firstRetro)
		if err != nil {
			logger.Panic("failed to unmarshal first retro json", zap.Error(err))
		}

		err = json.Unmarshal(secondRetroJsonBinary, &secondRetro)
		if err != nil {
			logger.Panic("failed to unmarshal second retro json", zap.Error(err))
		}

		err = json.Unmarshal(thirdRetroJsonBinary, &thirdRetro)
		if err != nil {
			logger.Panic("failed to unmarshal third retro json", zap.Error(err))
		}

		err = json.Unmarshal(fourthRetroJsonBinary, &fourthRetro)
		if err != nil {
			logger.Panic("failed to unmarshal fourth retro json", zap.Error(err))
		}

		bridgedAddrs := map[string]struct{}{}

		logger.Info("encoding bridged token state")
		bridgeTotal := decimal.Zero
		for _, b := range bridged {
			amt, err := decimal.NewFromString(b.Amount)
			if err != nil {
				logger.Panic("failed to parse bridged amount", zap.Error(err))
			}
			bridgeTotal = bridgeTotal.Add(amt)
			bridgedAddrs[b.Identifier] = struct{}{}
		}

		voucherTotals := map[string]decimal.Decimal{}
		peerIdTotals := map[string]decimal.Decimal{}
		peerSeniority := map[string]uint64{}
		logger.Info("encoding first retro state")
		for _, f := range firstRetro {
			p, _ := base58.Decode(f.PeerId)
			addr, _ := poseidon.HashBytes(p)
			addrBytes := string(addr.FillBytes(make([]byte, 32)))
			if _, ok := bridgedAddrs[f.PeerId]; !ok {
				peerIdTotals[f.PeerId], err = decimal.NewFromString(f.Reward)
				if err != nil {
					logger.Panic("failed to parse first retro amount", zap.Error(err))
				}
			}

			// these don't have decimals so we can shortcut
			max := 157208
			actual, err := strconv.Atoi(f.Reward)
			if err != nil {
				logger.Panic("failed to parse first retro amount", zap.Error(err))
			}

			peerSeniority[addrBytes] = uint64(10 * 6 * 60 * 24 * 92 / (max / actual))
		}

		logger.Info("encoding voucher state")
		for _, v := range vouchers {
			if _, ok := bridgedAddrs[v]; !ok {
				voucherTotals[v] = decimal.NewFromInt(50)
			}
		}

		logger.Info("encoding second retro state")
		for _, f := range secondRetro {
			p, _ := base58.Decode(f.PeerId)
			addr, _ := poseidon.HashBytes(p)
			addrBytes := string(addr.FillBytes(make([]byte, 32)))

			if _, ok := bridgedAddrs[f.PeerId]; !ok {
				existing, ok := peerIdTotals[f.PeerId]

				amount, err := decimal.NewFromString(f.Reward)
				if err != nil {
					logger.Panic("failed to parse second retro amount", zap.Error(err))
				}

				if !ok {
					peerIdTotals[f.PeerId] = amount
				} else {
					peerIdTotals[f.PeerId] = existing.Add(amount)
				}
			}

			if _, ok := peerSeniority[addrBytes]; !ok {
				peerSeniority[addrBytes] = 0
			}

			if f.JanPresence {
				peerSeniority[addrBytes] = peerSeniority[addrBytes] + (10 * 6 * 60 * 24 * 31)
			}

			if f.FebPresence {
				peerSeniority[addrBytes] = peerSeniority[addrBytes] + (10 * 6 * 60 * 24 * 29)
			}

			if f.MarPresence {
				peerSeniority[addrBytes] = peerSeniority[addrBytes] + (10 * 6 * 60 * 24 * 31)
			}

			if f.AprPresence {
				peerSeniority[addrBytes] = peerSeniority[addrBytes] + (10 * 6 * 60 * 24 * 30)
			}

			if f.MayPresence {
				peerSeniority[addrBytes] = peerSeniority[addrBytes] + (10 * 6 * 60 * 24 * 31)
			}
		}

		logger.Info("encoding third retro state")
		for _, f := range thirdRetro {
			p, _ := base58.Decode(f.PeerId)
			addr, _ := poseidon.HashBytes(p)
			addrBytes := string(addr.FillBytes(make([]byte, 32)))

			existing, ok := peerIdTotals[f.PeerId]

			amount, err := decimal.NewFromString(f.Reward)
			if err != nil {
				logger.Panic("failed to parse third retro amount", zap.Error(err))
			}

			if !ok {
				peerIdTotals[f.PeerId] = amount
			} else {
				peerIdTotals[f.PeerId] = existing.Add(amount)
			}

			if _, ok := peerSeniority[addrBytes]; !ok {
				peerSeniority[addrBytes] = 0
			}

			peerSeniority[addrBytes] = peerSeniority[addrBytes] + (10 * 6 * 60 * 24 * 30)
		}

		logger.Info("encoding fourth retro state")
		for _, f := range fourthRetro {
			p, _ := base58.Decode(f.PeerId)
			addr, _ := poseidon.HashBytes(p)
			addrBytes := string(addr.FillBytes(make([]byte, 32)))

			existing, ok := peerIdTotals[f.PeerId]

			amount, err := decimal.NewFromString(f.Reward)
			if err != nil {
				logger.Panic("failed to parse fourth retro amount", zap.Error(err))
			}

			if !ok {
				peerIdTotals[f.PeerId] = amount
			} else {
				peerIdTotals[f.PeerId] = existing.Add(amount)
			}

			if _, ok := peerSeniority[addrBytes]; !ok {
				peerSeniority[addrBytes] = 0
			}

			peerSeniority[addrBytes] = peerSeniority[addrBytes] + (10 * 6 * 60 * 24 * 31)
		}

		genesisState := &protobufs.TokenOutputs{
			Outputs: []*protobufs.TokenOutput{},
		}

		factor, _ := decimal.NewFromString("8000000000")
		bridgeAddressHex, err := hex.DecodeString(BridgeAddress)
		if err != nil {
			logger.Panic("failed to decode bridge address", zap.Error(err))
		}

		totalExecutions := 0
		logger.Info(
			"creating execution state",
			zap.Int(
				"coin_executions",
				totalExecutions,
			),
		)
		genesisState.Outputs = append(genesisState.Outputs, &protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_Coin{
				Coin: &protobufs.Coin{
					Amount: bridgeTotal.Mul(factor).BigInt().FillBytes(
						make([]byte, 32),
					),
					Intersection: make([]byte, 1024),
					Owner: &protobufs.AccountRef{
						Account: &protobufs.AccountRef_ImplicitAccount{
							ImplicitAccount: &protobufs.ImplicitAccount{
								Address: bridgeAddressHex,
							},
						},
					},
				},
			},
		})
		totalExecutions++

		for peerId, total := range peerIdTotals {
			if totalExecutions%1000 == 0 {
				logger.Info(
					"creating execution state",
					zap.Int(
						"coin_executions",
						totalExecutions,
					),
				)
			}
			peerBytes, err := base58.Decode(peerId)
			if err != nil {
				logger.Panic("failed to decode peer id", zap.Error(err))
			}

			addr, err := poseidon.HashBytes(peerBytes)
			if err != nil {
				logger.Panic("failed to hash peer id", zap.Error(err))
			}

			genesisState.Outputs = append(genesisState.Outputs, &protobufs.TokenOutput{
				Output: &protobufs.TokenOutput_Coin{
					Coin: &protobufs.Coin{
						Amount: total.Mul(factor).BigInt().FillBytes(
							make([]byte, 32),
						),
						Intersection: make([]byte, 1024),
						Owner: &protobufs.AccountRef{
							Account: &protobufs.AccountRef_ImplicitAccount{
								ImplicitAccount: &protobufs.ImplicitAccount{
									Address: addr.FillBytes(make([]byte, 32)),
								},
							},
						},
					},
				},
			})
			totalExecutions++
		}

		for voucher, total := range voucherTotals {
			if totalExecutions%1000 == 0 {
				logger.Info(
					"creating execution state",
					zap.Int(
						"coin_executions",
						totalExecutions,
					),
				)
			}
			keyBytes, err := hex.DecodeString(voucher[2:])
			if err != nil {
				logger.Panic("failed to decode voucher", zap.Error(err))
			}

			addr, err := poseidon.HashBytes(keyBytes)
			if err != nil {
				logger.Panic("failed to hash voucher", zap.Error(err))
			}

			genesisState.Outputs = append(genesisState.Outputs, &protobufs.TokenOutput{
				Output: &protobufs.TokenOutput_Coin{
					Coin: &protobufs.Coin{
						Amount: total.Mul(factor).BigInt().FillBytes(
							make([]byte, 32),
						),
						Intersection: make([]byte, 1024),
						Owner: &protobufs.AccountRef{
							Account: &protobufs.AccountRef_ImplicitAccount{
								ImplicitAccount: &protobufs.ImplicitAccount{
									Address: addr.FillBytes(make([]byte, 32)),
								},
							},
						},
					},
				},
			})
			totalExecutions++
		}

		logger.Info(
			"serializing execution state to store, this may take some time...",
			zap.Int(
				"coin_executions",
				totalExecutions,
			),
		)
		txn, err := coinStore.NewTransaction(false)
		for _, output := range genesisState.Outputs {
			if err != nil {
				logger.Panic("failed to create transaction", zap.Error(err))
			}

			address, err := GetAddressOfCoin(output.GetCoin(), 0, 0)
			if err != nil {
				logger.Panic("failed to get address of coin", zap.Error(err))
			}
			err = coinStore.PutCoin(
				txn,
				0,
				address,
				output.GetCoin(),
			)
			if err != nil {
				logger.Panic("failed to put coin", zap.Error(err))
			}

			value := []byte{}
			value = append(value, make([]byte, 8)...)
			value = append(value, output.GetCoin().Amount...)
			// implicit
			value = append(value, 0x00)
			value = append(
				value,
				output.GetCoin().Owner.GetImplicitAccount().GetAddress()...,
			)
			// domain len
			value = append(value, 0x00)
			value = append(value, output.GetCoin().Intersection...)

			proofs := mpcithVerEnc.EncryptAndCompress(
				value,
				config.GetGenesis().Beacon,
			)
			compressed := []hypergraph.Encrypted{}
			for _, d := range proofs {
				compressed = append(compressed, d)
			}
			vertTree, commitment, err := hypergraphStore.CommitAndSaveVertexData(
				txn,
				append(append([]byte{}, application.TOKEN_ADDRESS...), address...),
				compressed,
			)
			if err != nil {
				txn.Abort()
				logger.Panic("failed to commit and save vertex data", zap.Error(err))
			}

			if err := hg.AddVertex(
				nil,
				hypergraph.NewVertex(
					[32]byte(application.TOKEN_ADDRESS),
					[32]byte(address),
					commitment,
					vertTree.GetSize(),
				),
			); err != nil {
				txn.Abort()
				logger.Panic("failed to add vertex", zap.Error(err))
			}
		}
		if err := txn.Commit(); err != nil {
			logger.Panic("failed to commit transaction", zap.Error(err))
		}

		txn, err = clockStore.NewTransaction(false)
		if err != nil {
			logger.Panic("failed to create transaction", zap.Error(err))
		}

		err = clockStore.PutPeerSeniorityMap(
			txn,
			p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3),
			map[string]uint64{},
		)
		if err != nil {
			logger.Panic("failed to put peer seniority map", zap.Error(err))
		}

		intrinsicFilter := p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3)

		if err = txn.Commit(); err != nil {
			logger.Panic("failed to commit transaction", zap.Error(err))
		}

		logger.Info("encoded transcript")

		outputBytes, err := proto.Marshal(genesisState)
		if err != nil {
			logger.Panic("failed to marshal genesis state", zap.Error(err))
		}

		executionOutput := &protobufs.IntrinsicExecutionOutput{
			Address: intrinsicFilter,
			Output:  outputBytes,
			Proof:   seed,
		}

		data, err := proto.Marshal(executionOutput)
		if err != nil {
			logger.Panic("failed to marshal execution output", zap.Error(err))
		}

		logger.Debug("encoded execution output")
		digest := sha3.NewShake256()
		_, err = digest.Write(data)
		if err != nil {
			logger.Panic("failed to write digest", zap.Error(err))
		}

		expand := make([]byte, 1024)
		_, err = digest.Read(expand)
		if err != nil {
			logger.Panic("failed to read digest", zap.Error(err))
		}

		commitment, err := inclusionProver.CommitRaw(
			expand,
			16,
		)
		if err != nil {
			logger.Panic("failed to commit raw", zap.Error(err))
		}

		logger.Debug("creating kzg proof")
		proof, err := inclusionProver.ProveRaw(
			expand,
			int(expand[0]%16),
			16,
		)
		if err != nil {
			logger.Panic("failed to prove raw", zap.Error(err))
		}

		logger.Info("finalizing execution proof")

		return inputMessage, &qcrypto.InclusionAggregateProof{
			InclusionCommitments: []*qcrypto.InclusionCommitment{
				&qcrypto.InclusionCommitment{
					TypeUrl:    protobufs.IntrinsicExecutionOutputType,
					Data:       data,
					Commitment: commitment,
				},
			},
			AggregateCommitment: commitment,
			Proof:               proof,
		}, [][]byte{genesis.Beacon}, map[string]uint64{}
	} else {
		logger.Info(
			"THIS IS A TESTNET GENESIS, DO NOT CONNECT THIS NODE TO MAINNET",
		)

		genesisState := &protobufs.TokenOutputs{
			Outputs: []*protobufs.TokenOutput{},
		}

		addr, err := poseidon.HashBytes(genesis.Beacon)
		if err != nil {
			logger.Panic("failed to hash beacon", zap.Error(err))
		}

		factor, _ := new(big.Int).SetString("8000000000", 10)

		genesisState.Outputs = append(genesisState.Outputs, &protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_Coin{
				Coin: &protobufs.Coin{
					Amount: factor.Mul(factor, big.NewInt(0x0fffffff)).FillBytes(
						make([]byte, 32),
					),
					Intersection: make([]byte, 1024),
					Owner: &protobufs.AccountRef{
						Account: &protobufs.AccountRef_ImplicitAccount{
							ImplicitAccount: &protobufs.ImplicitAccount{
								Address: addr.FillBytes(make([]byte, 32)),
							},
						},
					},
				},
			},
		})

		logger.Info("serializing execution state to store")
		txn, err := coinStore.NewTransaction(false)
		for _, output := range genesisState.Outputs {
			if err != nil {
				logger.Panic("failed to create transaction", zap.Error(err))
			}

			address, err := GetAddressOfCoin(output.GetCoin(), 0, 0)
			if err != nil {
				logger.Panic("failed to get address of coin", zap.Error(err))
			}
			err = coinStore.PutCoin(
				txn,
				0,
				address,
				output.GetCoin(),
			)
			if err != nil {
				logger.Panic("failed to put coin", zap.Error(err))
			}
			coinBytes, err := proto.Marshal(output.GetCoin())
			if err != nil {
				logger.Panic("failed to marshal coin", zap.Error(err))
			}

			data := []byte{}
			data = binary.BigEndian.AppendUint64(data, 0)
			data = append(data, coinBytes...)
			proofs := mpcithVerEnc.EncryptAndCompress(
				data,
				config.GetGenesis().Beacon,
			)
			compressed := []hypergraph.Encrypted{}
			for _, d := range proofs {
				compressed = append(compressed, d)
			}
			vertTree, commitment, err := hypergraphStore.CommitAndSaveVertexData(
				txn,
				append(append([]byte{}, application.TOKEN_ADDRESS...), address...),
				compressed,
			)
			if err != nil {
				txn.Abort()
				logger.Panic("failed to commit and save vertex data", zap.Error(err))
			}

			if err := hg.AddVertex(
				nil,
				hypergraph.NewVertex(
					[32]byte(application.TOKEN_ADDRESS),
					[32]byte(address),
					commitment,
					vertTree.GetSize(),
				),
			); err != nil {
				txn.Abort()
				logger.Panic("failed to add vertex", zap.Error(err))
			}
		}
		intrinsicFilter := p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3)

		if err := txn.Commit(); err != nil {
			logger.Panic("failed to commit transaction", zap.Error(err))
		}

		logger.Info("encoded transcript")

		outputBytes, err := proto.Marshal(genesisState)
		if err != nil {
			logger.Panic("failed to marshal genesis state", zap.Error(err))
		}

		executionOutput := &protobufs.IntrinsicExecutionOutput{
			Address: intrinsicFilter,
			Output:  outputBytes,
			Proof:   seed,
		}

		data, err := proto.Marshal(executionOutput)
		if err != nil {
			logger.Panic("failed to marshal execution output", zap.Error(err))
		}

		logger.Debug("encoded execution output")
		digest := sha3.NewShake256()
		_, err = digest.Write(data)
		if err != nil {
			logger.Panic("failed to write digest", zap.Error(err))
		}

		expand := make([]byte, 1024)
		_, err = digest.Read(expand)
		if err != nil {
			logger.Panic("failed to read digest", zap.Error(err))
		}

		commitment, err := inclusionProver.CommitRaw(
			expand,
			16,
		)
		if err != nil {
			logger.Panic("failed to commit raw", zap.Error(err))
		}

		logger.Debug("creating kzg proof")
		proof, err := inclusionProver.ProveRaw(
			expand,
			int(expand[0]%16),
			16,
		)
		if err != nil {
			logger.Panic("failed to prove raw", zap.Error(err))
		}

		logger.Info("finalizing execution proof")

		m, _ := RebuildPeerSeniority(network)

		return inputMessage, &qcrypto.InclusionAggregateProof{
			InclusionCommitments: []*qcrypto.InclusionCommitment{
				&qcrypto.InclusionCommitment{
					TypeUrl:    protobufs.IntrinsicExecutionOutputType,
					Data:       data,
					Commitment: commitment,
				},
			},
			AggregateCommitment: commitment,
			Proof:               proof,
		}, [][]byte{genesis.Beacon}, m
	}
}
