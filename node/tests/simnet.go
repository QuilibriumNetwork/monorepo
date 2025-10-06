package tests

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/swarm"
	simlibp2p "github.com/libp2p/go-libp2p/x/simlibp2p"
	"github.com/marcopolo/simnet"
	"github.com/stretchr/testify/require"
)

func GenerateSimnetHosts(t *testing.T, count int, opts []libp2p.Option) (
	*simnet.Simnet,
	*simlibp2p.SimpleLibp2pNetworkMeta,
	func(),
) {
	latency := 400 * time.Millisecond
	linkSettings := simnet.NodeBiDiLinkSettings{
		Downlink: simnet.LinkSettings{
			BitsPerSecond: 20 * simlibp2p.OneMbps,
			Latency:       latency / 2,
		}, // Divide by two since this is latency for each direction
		Uplink: simnet.LinkSettings{
			BitsPerSecond: 1 * simlibp2p.OneMbps,
			Latency:       latency / 2,
		},
	}
	set := []simlibp2p.NodeLinkSettingsAndIndex{}
	for i := 0; i < count; i++ {
		set = append(set, simlibp2p.NodeLinkSettingsAndIndex{
			LinkSettings: linkSettings,
			Idx:          i,
		})
	}
	network, meta, err := simlibp2p.SimpleLibp2pNetwork(
		set,
		simlibp2p.NetworkSettings{
			OptsForHostIdx: func(idx int) []libp2p.Option {
				return []libp2p.Option{
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
			},
		},
	)
	require.NoError(t, err)
	network.Start()
	return network, meta, func() {
		network.Close()

		for _, node := range meta.Nodes {
			node.Close()
		}
	}
}

func ConnectSimnetHosts(t *testing.T, a, b host.Host) {
	err := a.Connect(
		context.Background(),
		peer.AddrInfo{
			ID:    b.ID(),
			Addrs: b.Addrs(),
		},
	)
	require.NoError(t, err)
}
