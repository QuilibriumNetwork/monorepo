package token

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func GetGRPCClient() (*grpc.ClientConn, error) {
	customRpc := ClientConfig.CustomRpc

	var addr string
	if customRpc != "" {
		addr = customRpc
	} else {
		addr = "rpc.quilibrium.com:8337"
	}

	credentials := credentials.NewTLS(&tls.Config{InsecureSkipVerify: false})
	if !LightNode {
		ma, err := multiaddr.NewMultiaddr(NodeConfig.ListenGRPCMultiaddr)
		if err != nil {
			panic(err)
		}

		_, addr, err = mn.DialArgs(ma)
		if err != nil {
			panic(err)
		}
		credentials = insecure.NewCredentials()
	}

	return grpc.Dial(
		addr,
		grpc.WithTransportCredentials(
			credentials,
		),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(600*1024*1024),
			grpc.MaxCallRecvMsgSize(600*1024*1024),
		),
	)
}

// CoinData represents a combined structure for coin information,
// including frame and address data.
type CoinData struct {
	Amount      string
	Coin        *protobufs.Coin
	FrameNumber uint64
	Address     []byte
	Timestamp   string
}

func GetAccountCoins(includeMetadata bool) ([]CoinData, error) {
	conn, err := GetGRPCClient()
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	client := protobufs.NewNodeServiceClient(conn)
	peerId := utils.GetPeerIDFromConfig(NodeConfig)
	privKey, err := utils.GetPrivKeyFromConfig(NodeConfig)
	if err != nil {
		panic(err)
	}

	addr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		panic(err)
	}

	addrBytes := addr.FillBytes(make([]byte, 32))

	resp, err := client.GetTokensByAccount(
		context.Background(),
		&protobufs.GetTokensByAccountRequest{
			Address:         addrBytes,
			IncludeMetadata: includeMetadata,
		},
	)
	if err != nil {
		panic(err)
	}

	if len(resp.Coins) != len(resp.FrameNumbers) {
		return nil, errors.New("invalid response from RPC")
	}

	pub, err := privKey.GetPublic().Raw()
	if err != nil {
		panic(err)
	}

	altAddr, err := poseidon.HashBytes([]byte(pub))
	if err != nil {
		panic(err)
	}

	altAddrBytes := altAddr.FillBytes(make([]byte, 32))
	resp2, err := client.GetTokensByAccount(
		context.Background(),
		&protobufs.GetTokensByAccountRequest{
			Address:         altAddrBytes,
			IncludeMetadata: includeMetadata,
		},
	)
	if err != nil {
		panic(err)
	}

	if len(resp2.Coins) != len(resp2.FrameNumbers) {
		return nil, errors.New("invalid response from RPC")
	}

	// Merge coin data from both responses into a unified list
	mergedData := make([]CoinData, 0, len(resp.Coins)+len(resp2.Coins))

	// Add data from first response (resp)
	for i := 0; i < len(resp.Coins); i++ {

		coin := resp.Coins[i]
		amount := new(big.Int).SetBytes(coin.Amount)
		conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
		r := new(big.Rat).SetFrac(amount, conversionFactor)

		data := CoinData{
			Amount:      r.FloatString(12),
			Coin:        resp.Coins[i],
			FrameNumber: resp.FrameNumbers[i],
			Address:     resp.Addresses[i],
		}
		if len(resp.Timestamps) > i {
			t := time.UnixMilli(resp.Timestamps[i])
			data.Timestamp = t.Format(time.RFC3339)
		}
		mergedData = append(mergedData, data)
	}

	// Add data from second response (resp2)
	for i := 0; i < len(resp2.Coins); i++ {
		coin := resp2.Coins[i]
		amount := new(big.Int).SetBytes(coin.Amount)
		conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
		r := new(big.Rat).SetFrac(amount, conversionFactor)

		data := CoinData{
			Amount:      r.FloatString(12),
			Coin:        resp2.Coins[i],
			FrameNumber: resp2.FrameNumbers[i],
			Address:     resp2.Addresses[i],
		}
		if len(resp2.Timestamps) > i {
			t := time.UnixMilli(resp2.Timestamps[i])
			data.Timestamp = t.Format(time.RFC3339)
		}
		mergedData = append(mergedData, data)
	}

	return mergedData, nil
}

// IsAccountCoin checks if the given coin address is owned by the account.
func IsAccountCoin(address []byte, coins []CoinData) bool {
	if len(coins) == 0 {
		return false
	}

	for _, coin := range coins {
		if bytes.Equal(coin.Address, address) {
			return true
		}
	}

	return false
}

func PromptTokenForTransfer(coins []CoinData) (string, error) {
	fmt.Println("Please select a coin to transfer:")
	for i, coin := range coins {
		fmt.Printf("%d. %s\n", i+1, coin.Amount)
	}

	var selectedCoinIndex int
	fmt.Scanln(&selectedCoinIndex)

	if selectedCoinIndex < 1 || selectedCoinIndex > len(coins) {
		return "", errors.New("invalid coin index")
	}

	return hex.EncodeToString(coins[selectedCoinIndex-1].Address), nil
}

func CleanAddress(address string) ([]byte, error) {
	address = strings.ReplaceAll(address, "0x", "")
	address = strings.TrimSpace(address)
	addressBytes, err := hex.DecodeString(address)
	if err != nil {
		return nil, err
	}
	return addressBytes, nil
}
