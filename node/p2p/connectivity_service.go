package p2p

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
	ma "github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	grpcpeer "google.golang.org/grpc/peer"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

type connectivityService struct {
	protobufs.UnimplementedConnectivityServiceServer
	logger *zap.Logger
	host   host.Host
	ping   *ping.PingService
}

func newConnectivityService(
	logger *zap.Logger,
	h host.Host,
) *connectivityService {
	return &connectivityService{
		logger: logger,
		host:   h,
		ping:   ping.NewPingService(h),
	}
}

func (s *connectivityService) TestConnectivity(
	ctx context.Context,
	req *protobufs.ConnectivityTestRequest,
) (*protobufs.ConnectivityTestResponse, error) {
	resp := &protobufs.ConnectivityTestResponse{}
	peerID := peer.ID(req.GetPeerId())
	if peerID == "" {
		resp.ErrorMessage = "peer id required"
		return resp, nil
	}

	reqMaddrStrs := req.GetMultiaddrs()
	reqMaddrs := getValidMultiaddrs(reqMaddrStrs)

	// categorize submitted multiaddrs into public and private
	publicMaddrs, privateMaddrs := categorizePublicPrivateMultiaddrs(reqMaddrs)

	if len(publicMaddrs)+len(privateMaddrs) == 0 {
		resp.ErrorMessage = "no valid multiaddrs to test"
		return resp, nil
	}

	// ping public multiaddrs first
	if err := s.pingPeer(ctx, peerID, publicMaddrs); err == nil {
		resp.Success = true
		return resp, nil
	}

	// get remote IP address from the gRPC peer context
	pr, ok := grpcpeer.FromContext(ctx)
	if !ok || pr.Addr == nil {
		resp.ErrorMessage = "unable to determine peer information from context"
		return resp, nil
	}

	remoteAddr := pr.Addr.String()
	remoteHost, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		resp.ErrorMessage = fmt.Sprintf("unable to parse remote host from remote address: %s", remoteAddr)
		return resp, nil
	}

	remoteIP, err := netip.ParseAddr(remoteHost)

	if err != nil {
		resp.ErrorMessage = fmt.Sprintf("unable to parse remote ip from remote host: %s", remoteHost)
		return resp, nil
	}

	s.logger.Debug(
		"connectivity test from peer",
		zap.String("peer_id", peerID.String()),
		zap.String("remote_ip", remoteIP.String()),
	)

	// replace private multiaddr IPs with remote IP
	guessAddrs := make([]ma.Multiaddr, 0, len(privateMaddrs))
	for _, maddr := range privateMaddrs {
		guessAddr, err := replaceMultiaddrIP(maddr, remoteIP)
		if err == nil {
			guessAddrs = append(guessAddrs, guessAddr)
		}
	}

	// ping guessed public multiaddrs
	if err := s.pingPeer(ctx, peerID, guessAddrs); err != nil {
		resp.ErrorMessage = err.Error()
		return resp, nil
	}

	resp.Success = true
	return resp, nil
}

func categorizePublicPrivateMultiaddrs(reqMaddrs []ma.Multiaddr) ([]ma.Multiaddr, []ma.Multiaddr) {
	publicMaddrs := make([]ma.Multiaddr, 0, len(reqMaddrs))
	privateMaddrs := make([]ma.Multiaddr, 0, len(reqMaddrs))

	for _, maddr := range reqMaddrs {
		if isPubl, _ := mn.IsPublicAddr(maddr); isPubl {
			publicMaddrs = append(publicMaddrs, maddr)
		} else if isPriv, _ := mn.IsPrivateAddr(maddr); isPriv {
			privateMaddrs = append(privateMaddrs, maddr)
		}
	}
	return publicMaddrs, privateMaddrs
}

func getValidMultiaddrs(reqMaddrStrs []string) []ma.Multiaddr {
	reqMaddrs := make([]ma.Multiaddr, 0, len(reqMaddrStrs))

	for _, maddrStr := range reqMaddrStrs {
		maddr, err := ma.NewMultiaddr(maddrStr)
		if err == nil {
			reqMaddrs = append(reqMaddrs, maddr)
		}
	}
	return reqMaddrs
}

func replaceMultiaddrIP(maddr ma.Multiaddr, ip netip.Addr) (ma.Multiaddr, error) {
	ipComp, rest := ma.SplitFirst(maddr)

	if ipComp.Protocol().Code == ma.P_IP6 {
		// if remote IP is IPv4, convert to IPv4-in-IPv6
		if ip.Is4() {
			ip = netip.AddrFrom16(ip.As16())
		}
	} else if ipComp.Protocol().Code == ma.P_IP4 {
		// if remote IP is IPv4-in-IPv6, unmap, skip IPv6
		if ip.Is4In6() {
			ip = ip.Unmap()
		} else if ip.Is6() {
			return nil, errors.New("can't put IPv6 remote IP into IPv4 multiaddr")
		}
	} else {
		// skip other protocols
		return nil, errors.New("unsupported multiaddr protocol")
	}

	newIpComp, err := ma.NewComponent(ipComp.Protocol().Name, ip.String())
	if err != nil {
		return nil, err
	}
	return ma.Join(newIpComp, rest), nil
}

func (s *connectivityService) pingPeer(ctx context.Context, peerID peer.ID, addrs []ma.Multiaddr) error {
	s.logger.Debug(
		"attempting to connect to peer",
		zap.String("peer_id", peerID.String()),
		zap.Any("addrs", addrs),
	)

	s.host.Peerstore().AddAddrs(peerID, addrs, peerstore.TempAddrTTL)

	connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err := s.host.Connect(connectCtx, peer.AddrInfo{
		ID:    peerID,
		Addrs: addrs,
	})
	if err != nil {
		return err
	}

	defer s.host.Network().ClosePeer(peerID)

	pingCtx, cancelPing := context.WithTimeout(ctx, 10*time.Second)
	defer cancelPing()

	select {
	case <-pingCtx.Done():
		return pingCtx.Err()
	case result := <-s.ping.Ping(pingCtx, peerID):
		if result.Error != nil {
			return result.Error
		}
	}
	return nil
}
