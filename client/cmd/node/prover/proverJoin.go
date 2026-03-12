package prover

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

var delegateAddress string

var NodeProverJoinCmd = &cobra.Command{
	Use:   "join [filter1] [filter2] ...",
	Short: "Joins the prover to the network",
	Long: `Joins the prover to the network for the specified shard filters.

	join [filter1] [filter2] ... [--delegate <address>]

	If no filters are specified, joins all shards (all-0xFF filter).
	Each filter is a hex-encoded 32-byte shard identifier.

	--delegate: optional 32-byte hex reward delegate address (currently
	            uses the node's configured DelegateAddress)
	`,
	Run: func(cmd *cobra.Command, args []string) {
		client, conn, err := getNodeClient()
		if err != nil {
			fmt.Printf("Failed to connect: %v\n", err)
			os.Exit(1)
		}
		defer conn.Close()

		var filters [][]byte
		if len(args) > 0 {
			for _, arg := range args {
				f, err := hex.DecodeString(arg)
				if err != nil {
					fmt.Printf("Invalid filter hex %q: %v\n", arg, err)
					os.Exit(1)
				}
				filters = append(filters, f)
			}
		} else {
			filters = [][]byte{bytes.Repeat([]byte{0xff}, 32)}
		}

		var delegate []byte
		if delegateAddress != "" {
			delegate, err = hex.DecodeString(delegateAddress)
			if err != nil {
				fmt.Printf("Invalid delegate address hex: %v\n", err)
				os.Exit(1)
			}
		}

		fmt.Println("Requesting join (VDF proof computation may take a while)...")
		_, err = client.RequestJoin(
			cmd.Context(),
			&protobufs.RequestJoinRequest{
				Filters:  filters,
				Delegate: delegate,
			},
		)
		if err != nil {
			fmt.Printf("Failed to request join: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Prover join submitted successfully")
	},
}

func init() {
	NodeProverJoinCmd.Flags().StringVar(
		&delegateAddress,
		"delegate",
		"",
		"Optional 32-byte hex reward delegate address",
	)
}
