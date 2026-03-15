package utils

import (
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"source.quilibrium.com/quilibrium/monorepo/config"

	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
)

func GetGRPCClient(
	lightNode bool,
	customRpc string,
	cfg *config.Config,
) (*grpc.ClientConn, error) {
	var addr string
	if customRpc != "" {
		addr = customRpc
	} else {
		addr = "rpc.quilibrium.com:8337"
	}

	credentials := credentials.NewTLS(&tls.Config{InsecureSkipVerify: false})
	if !lightNode {
		ma, err := multiaddr.NewMultiaddr(cfg.ListenGRPCMultiaddr)
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
			grpc.MaxCallSendMsgSize(100*1024*1024),
			grpc.MaxCallRecvMsgSize(100*1024*1024),
		),
	)
}
