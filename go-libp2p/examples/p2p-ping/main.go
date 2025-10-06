package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	ma "github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
)

func main() {
	// Command-line flags
	var (
		timeout = flag.Duration("timeout", 10*time.Second, "connection and ping timeout")
	)
	flag.Parse()

	fmt.Println("P2P Ping Tool - Reading multiaddresses from stdin...")
	fmt.Println("Enter multiaddresses one per line (Ctrl+D to finish):")
	fmt.Println()

	// Create a minimal libp2p client
	client, err := createClient()
	if err != nil {
		log.Fatal("Failed to create libp2p client:", err)
	}
	defer client.Close()

	fmt.Printf("Client started (ID: %s)\n", client.ID())
	fmt.Println("=" + strings.Repeat("=", 60))

	// Create ping service
	pingService := ping.NewPingService(client)

	// Read multiaddresses from stdin
	scanner := bufio.NewScanner(os.Stdin)
	var results []PingResult
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		addrStr := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if addrStr == "" {
			continue
		}

		fmt.Printf("[%d] Testing: %s\n", lineNum, addrStr)

		result := pingPeer(client, pingService, addrStr, *timeout)
		results = append(results, result)

		// Print immediate result
		if result.Success {
			fmt.Printf("    ✓ SUCCESS - RTT: %v\n", result.RTT)
		} else {
			fmt.Printf("    ✗ FAILED - %s\n", result.Error)
		}
		fmt.Println()
	}

	if err := scanner.Err(); err != nil {
		log.Fatal("Error reading stdin:", err)
	}

	// Print summary
	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Printf("Summary: %d addresses tested\n", len(results))

	successful := 0
	for _, r := range results {
		if r.Success {
			successful++
		}
	}

	fmt.Printf("Successful: %d/%d (%.1f%%)\n", successful, len(results),
		float64(successful)/float64(len(results))*100)
}

type PingResult struct {
	Address string
	Success bool
	RTT     time.Duration
	Error   string
}

func pingPeer(client host.Host, pingService *ping.PingService, addrStr string, timeout time.Duration) PingResult {
	result := PingResult{Address: addrStr}

	// Parse target multiaddr
	targetAddr, err := ma.NewMultiaddr(addrStr)
	if err != nil {
		result.Error = fmt.Sprintf("Invalid multiaddr: %v", err)
		return result
	}

	// Resolve DNS addresses if present
	resolvedAddrs := []ma.Multiaddr{targetAddr}
	if madns.Matches(targetAddr) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		resolved, err := madns.Resolve(ctx, targetAddr)
		if err != nil {
			result.Error = fmt.Sprintf("DNS resolution failed: %v", err)
			return result
		}
		resolvedAddrs = resolved
	}

	// Extract peer ID from the original address
	_, peerIDStr := ma.SplitLast(targetAddr)
	if peerIDStr == nil || peerIDStr.Protocol().Code != ma.P_P2P {
		result.Error = "Multiaddr must end with /p2p/<peer-id>"
		return result
	}

	peerID, err := peer.Decode(peerIDStr.Value())
	if err != nil {
		result.Error = fmt.Sprintf("Invalid peer ID: %v", err)
		return result
	}

	// Create AddrInfo with resolved addresses (without /p2p/ suffix)
	var cleanAddrs []ma.Multiaddr
	for _, addr := range resolvedAddrs {
		// Remove the /p2p/<peer-id> suffix if present
		if addr.Equal(targetAddr) {
			cleanAddr, _ := ma.SplitLast(addr)
			cleanAddrs = append(cleanAddrs, cleanAddr)
		} else {
			cleanAddrs = append(cleanAddrs, addr)
		}
	}

	targetInfo := &peer.AddrInfo{
		ID:    peerID,
		Addrs: cleanAddrs,
	}

	// Connect to the target peer with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	err = client.Connect(ctx, *targetInfo)
	if err != nil {
		result.Error = fmt.Sprintf("Connection failed: %v", err)
		return result
	}

	// Perform single ping
	pingCtx, pingCancel := context.WithTimeout(context.Background(), timeout)
	defer pingCancel()

	pingResult := <-pingService.Ping(pingCtx, targetInfo.ID)
	if pingResult.Error != nil {
		result.Error = fmt.Sprintf("Ping failed: %v", pingResult.Error)
		return result
	}

	result.Success = true
	result.RTT = pingResult.RTT
	return result
}

func createClient() (host.Host, error) {
	// Create a minimal libp2p client with no listening addresses
	// This makes it a client-only node that can connect to others but doesn't accept connections
	opts := []libp2p.Option{
		libp2p.NoListenAddrs, // Don't listen on any addresses - client only
		libp2p.SwarmOpts(
			swarm.WithUDPBlackHoleSuccessCounter(
				&swarm.BlackHoleSuccessCounter{
					N:            8000,
					MinSuccesses: 1,
					Name:         "permissive-udp",
				},
			),
			swarm.WithIPv6BlackHoleSuccessCounter(
				&swarm.BlackHoleSuccessCounter{
					N:            8000,
					MinSuccesses: 1,
					Name:         "permissive-ip6",
				},
			),
		),
	}

	return libp2p.New(opts...)
}
