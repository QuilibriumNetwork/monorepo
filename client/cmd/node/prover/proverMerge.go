package prover

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"

	"github.com/shopspring/decimal"
	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	nodeConfig "source.quilibrium.com/quilibrium/monorepo/node/config"
)

var DryRun bool

var proverConfigMergeCmd = &cobra.Command{
	Use:   "merge",
	Short: "Merges config data for prover seniority",
	Long: `Merges config data for prover seniority:
	
	merge <Primary Config Path> [<Additional Config Paths>...]

	Use with --dry-run to evaluate seniority score, this may take a while...
	`,
	Run: func(c *cobra.Command, args []string) {
		if len(args) <= 1 {
			fmt.Println("missing configs")
			os.Exit(1)
		}

		primaryConfig, err := nodeConfig.LoadConfig(args[0], "", true)
		if err != nil {
			fmt.Printf("invalid config directory: %s\n", args[0])
			os.Exit(1)
		}

		otherPaths := []string{}
		peerIds := []string{utils.GetPeerIDFromConfig(primaryConfig).String()}
		for _, p := range args[1:] {
			if !path.IsAbs(p) {
				fmt.Printf("%s is not an absolute path\n", p)
			}
			cfg, err := nodeConfig.LoadConfig(p, "", true)
			if err != nil {
				fmt.Printf("invalid config directory: %s\n", p)
				os.Exit(1)
			}

			peerId := utils.GetPeerIDFromConfig(cfg).String()
			peerIds = append(peerIds, peerId)
			otherPaths = append(otherPaths, p)
		}

		if DryRun {
			bridged := []*utils.BridgedPeerJson{}
			firstRetro := []*utils.FirstRetroJson{}
			secondRetro := []*utils.SecondRetroJson{}
			thirdRetro := []*utils.ThirdRetroJson{}
			fourthRetro := []*utils.FourthRetroJson{}

			err = json.Unmarshal(bridgedPeersJsonBinary, &bridged)
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(firstRetroJsonBinary, &firstRetro)
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

			bridgedAddrs := map[string]struct{}{}

			bridgeTotal := decimal.Zero
			for _, b := range bridged {
				amt, err := decimal.NewFromString(b.Amount)
				if err != nil {
					panic(err)
				}
				bridgeTotal = bridgeTotal.Add(amt)
				bridgedAddrs[b.Identifier] = struct{}{}
			}

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

			fmt.Printf("Effective seniority score: %d\n", highestFirst+highestSecond+highestThird+highestFourth)
		} else {
			for _, p := range args[1:] {
				primaryConfig.Engine.MultisigProverEnrollmentPaths = append(
					primaryConfig.Engine.MultisigProverEnrollmentPaths,
					p,
				)
			}
			err := nodeConfig.SaveConfig(args[0], primaryConfig)
			if err != nil {
				panic(err)
			}
		}
	},
}

//go:embed premainnet-data/bridged.json
var bridgedPeersJsonBinary []byte

//go:embed premainnet-data/first_retro.json
var firstRetroJsonBinary []byte

//go:embed premainnet-data/second_retro.json
var secondRetroJsonBinary []byte

//go:embed premainnet-data/third_retro.json
var thirdRetroJsonBinary []byte

//go:embed premainnet-data/fourth_retro.json
var fourthRetroJsonBinary []byte

func init() {
	proverConfigMergeCmd.Flags().BoolVar(&DryRun, "dry-run", false, "Evaluate seniority score without merging configs")
	ProverCmd.AddCommand(proverConfigMergeCmd)
}
