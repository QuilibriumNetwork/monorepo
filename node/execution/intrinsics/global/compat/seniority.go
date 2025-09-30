package compat

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strconv"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/mr-tron/base58"
)

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

//go:embed first_retro.json
var firstRetroJsonBinary []byte

//go:embed second_retro.json
var secondRetroJsonBinary []byte

//go:embed third_retro.json
var thirdRetroJsonBinary []byte

//go:embed fourth_retro.json
var fourthRetroJsonBinary []byte

//go:embed mainnet_244200_seniority.json
var mainnetSeniorityJsonBinary []byte

var firstRetro []*FirstRetroJson
var secondRetro []*SecondRetroJson
var thirdRetro []*ThirdRetroJson
var fourthRetro []*FourthRetroJson
var mainnetSeniority map[string]uint64

func RebuildPeerSeniority(network uint) error {
	if network != 0 {
		firstRetro = []*FirstRetroJson{}
		secondRetro = []*SecondRetroJson{}
		thirdRetro = []*ThirdRetroJson{}
		fourthRetro = []*FourthRetroJson{}
		mainnetSeniority = map[string]uint64{}
	} else {
		firstRetro = []*FirstRetroJson{}
		secondRetro = []*SecondRetroJson{}
		thirdRetro = []*ThirdRetroJson{}
		fourthRetro = []*FourthRetroJson{}
		mainnetSeniority = map[string]uint64{}

		err := json.Unmarshal(firstRetroJsonBinary, &firstRetro)
		if err != nil {
			return err
		}

		err = json.Unmarshal(secondRetroJsonBinary, &secondRetro)
		if err != nil {
			return err
		}

		err = json.Unmarshal(thirdRetroJsonBinary, &thirdRetro)
		if err != nil {
			return err
		}

		err = json.Unmarshal(fourthRetroJsonBinary, &fourthRetro)
		if err != nil {
			return err
		}

		err = json.Unmarshal(mainnetSeniorityJsonBinary, &mainnetSeniority)
		if err != nil {
			return err
		}
	}

	return nil
}

// OverrideSeniority overrides values set in the internal globals, this method
// should strictly be used for testing purposes
func OverrideSeniority(
	first *FirstRetroJson,
	second *SecondRetroJson,
	third *ThirdRetroJson,
	fourth *FourthRetroJson,
	mainnetPeerId string,
	seniority uint64,
) {
	firstRetro = append(firstRetro, first)
	secondRetro = append(secondRetro, second)
	thirdRetro = append(thirdRetro, third)
	fourthRetro = append(fourthRetro, fourth)
	if mainnetSeniority == nil {
		mainnetSeniority = make(map[string]uint64)
	}
	mainnetSeniority[mainnetPeerId] = seniority
}

func GetAggregatedSeniority(peerIds []string) *big.Int {
	highestFirst := uint64(0)
	highestSecond := uint64(0)
	highestThird := uint64(0)
	highestFourth := uint64(0)

	for _, f := range firstRetro {
		found := false
		for _, p := range peerIds {
			if p != f.PeerId {
				continue
			}
			found = true
		}
		if !found {
			continue
		}
		// these don't have decimals so we can shortcut
		max := 157208
		actual, err := strconv.Atoi(f.Reward)
		if err != nil {
			panic(err)
		}

		s := uint64(10 * 6 * 60 * 24 * 92 / (max / actual))
		if s > uint64(highestFirst) {
			highestFirst = s
		}
	}

	for _, f := range secondRetro {
		found := false
		for _, p := range peerIds {
			if p != f.PeerId {
				continue
			}
			found = true
		}
		if !found {
			continue
		}

		amt := uint64(0)
		if f.JanPresence {
			amt += (10 * 6 * 60 * 24 * 31)
		}

		if f.FebPresence {
			amt += (10 * 6 * 60 * 24 * 29)
		}

		if f.MarPresence {
			amt += (10 * 6 * 60 * 24 * 31)
		}

		if f.AprPresence {
			amt += (10 * 6 * 60 * 24 * 30)
		}

		if f.MayPresence {
			amt += (10 * 6 * 60 * 24 * 31)
		}

		if amt > uint64(highestSecond) {
			highestSecond = amt
		}
	}

	for _, f := range thirdRetro {
		found := false
		for _, p := range peerIds {
			if p != f.PeerId {
				continue
			}
			found = true
		}
		if !found {
			continue
		}

		s := uint64(10 * 6 * 60 * 24 * 30)
		if s > uint64(highestThird) {
			highestThird = s
		}
	}

	for _, f := range fourthRetro {
		found := false
		for _, p := range peerIds {
			if p != f.PeerId {
				continue
			}
			found = true
		}
		if !found {
			continue
		}

		s := uint64(10 * 6 * 60 * 24 * 31)
		if s > uint64(highestFourth) {
			highestFourth = s
		}
	}

	// Calculate current aggregated value
	currentAggregated := highestFirst + highestSecond + highestThird + highestFourth

	highestMainnetSeniority := uint64(0)
	for _, peerId := range peerIds {
		// Decode base58
		decoded, err := base58.Decode(peerId)
		if err != nil {
			continue
		}

		// Hash with poseidon
		hashBI, err := poseidon.HashBytes(decoded)
		if err != nil {
			continue
		}

		// Convert to 32-byte address
		address := hashBI.FillBytes(make([]byte, 32))

		// Encode as hex string
		addressHex := hex.EncodeToString(address)

		// Look up in mainnetSeniority
		if seniority, exists := mainnetSeniority[addressHex]; exists {
			if seniority > highestMainnetSeniority {
				highestMainnetSeniority = seniority
			}
		}
	}

	// Return the higher value between current aggregated and mainnetSeniority
	if highestMainnetSeniority > currentAggregated {
		return new(big.Int).SetUint64(highestMainnetSeniority)
	}
	return new(big.Int).SetUint64(currentAggregated)
}
