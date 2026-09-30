package compat

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/mr-tron/base58"
	"go.uber.org/zap"
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
			return fmt.Errorf("failed to unmarshal first_retro.json: %w", err)
		}

		err = json.Unmarshal(secondRetroJsonBinary, &secondRetro)
		if err != nil {
			return fmt.Errorf("failed to unmarshal second_retro.json: %w", err)
		}

		err = json.Unmarshal(thirdRetroJsonBinary, &thirdRetro)
		if err != nil {
			return fmt.Errorf("failed to unmarshal third_retro.json: %w", err)
		}

		err = json.Unmarshal(fourthRetroJsonBinary, &fourthRetro)
		if err != nil {
			return fmt.Errorf("failed to unmarshal fourth_retro.json: %w", err)
		}

		err = json.Unmarshal(mainnetSeniorityJsonBinary, &mainnetSeniority)
		if err != nil {
			return fmt.Errorf("failed to unmarshal mainnet_244200_seniority.json: %w", err)
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
	logger := zap.L()
	logger.Debug(
		"GetAggregatedSeniority called",
		zap.Strings("peer_ids", peerIds),
		zap.Int("mainnet_seniority_map_size", len(mainnetSeniority)),
	)

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

	logger.Debug(
		"retro seniority calculation complete",
		zap.Uint64("highest_first", highestFirst),
		zap.Uint64("highest_second", highestSecond),
		zap.Uint64("highest_third", highestThird),
		zap.Uint64("highest_fourth", highestFourth),
		zap.Uint64("current_aggregated", currentAggregated),
	)

	highestMainnetSeniority := uint64(0)
	for _, peerId := range peerIds {
		// Decode base58
		decoded, err := base58.Decode(peerId)
		if err != nil {
			logger.Warn(
				"failed to decode peer ID from base58",
				zap.String("peer_id", peerId),
				zap.Error(err),
			)
			continue
		}

		// Hash with poseidon
		hashBI, err := poseidon.HashBytes(decoded)
		if err != nil {
			logger.Warn(
				"failed to hash peer ID with poseidon",
				zap.String("peer_id", peerId),
				zap.Error(err),
			)
			continue
		}

		// Convert to 32-byte address
		address := hashBI.FillBytes(make([]byte, 32))

		// Encode as hex string
		addressHex := hex.EncodeToString(address)

		// Look up in mainnetSeniority
		if seniority, exists := mainnetSeniority[addressHex]; exists {
			logger.Debug(
				"found mainnet seniority for peer",
				zap.String("peer_id", peerId),
				zap.String("address_hex", addressHex),
				zap.Uint64("seniority", seniority),
			)
			if seniority > highestMainnetSeniority {
				highestMainnetSeniority = seniority
			}
		} else {
			logger.Debug(
				"no mainnet seniority found for peer",
				zap.String("peer_id", peerId),
				zap.String("address_hex", addressHex),
			)
		}
	}

	// Return the higher value between current aggregated and mainnetSeniority
	logger.Info(
		"GetAggregatedSeniority result",
		zap.Uint64("retro_aggregated", currentAggregated),
		zap.Uint64("highest_mainnet_seniority", highestMainnetSeniority),
		zap.Bool("using_mainnet", highestMainnetSeniority > currentAggregated),
	)

	if highestMainnetSeniority > currentAggregated {
		return new(big.Int).SetUint64(highestMainnetSeniority)
	}
	return new(big.Int).SetUint64(currentAggregated)
}
