package token

import (
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
)

func GetGRPCClient() (*grpc.ClientConn, error) {
	addr := "rpc.quilibrium.com:8337"
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
