package ferret

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	protobufs "source.quilibrium.com/quilibrium/monorepo/protobufs"
)

type streamState struct {
	sendCh chan *protobufs.ProxyData
	done   chan struct{}
	alive  bool
}

type FerretProxyServer struct {
	protobufs.UnimplementedFerretProxyServer

	mu    sync.Mutex
	cond  *sync.Cond
	alice *streamState
	bob   *streamState
}

// NewFerretProxyServer provides a gRPC-based proxy that tunnels a local TCP
// connection (created by the Ferret OT library) between Alice (TCP server)
// and Bob (TCP client). The proxy server only routes ProxyData frames
// between AliceProxy and BobProxy streams; each client wrapper bridges
// TCP <-> gRPC locally.
func NewFerretProxyServer() *FerretProxyServer {
	s := &FerretProxyServer{}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// StartProxyServer starts a gRPC server that routes AliceProxy <-> BobProxy.
// listenAddr format examples: ":9999", "127.0.0.1:0" (ephemeral port)
func StartProxyServer(listenAddr string) (*grpc.Server, net.Listener, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen %s: %w", listenAddr, err)
	}

	g := grpc.NewServer()
	protobufs.RegisterFerretProxyServer(g, NewFerretProxyServer())

	go func() {
		if serveErr := g.Serve(ln); serveErr != nil {
		}
	}()
	return g, ln, nil
}

// helper to register a side and spawn the sender goroutine
func (s *FerretProxyServer) registerSide(which string) *streamState {
	st := &streamState{
		sendCh: make(chan *protobufs.ProxyData, 64),
		done:   make(chan struct{}),
		alive:  true,
	}
	s.cond.L.Lock()
	if which == "alice" {
		s.alice = st
	} else {
		s.bob = st
	}
	s.cond.Broadcast()
	s.cond.L.Unlock()
	return st
}

// fetch the peer's stream state, waiting until it exists or ctx is done
func (s *FerretProxyServer) peerState(
	ctx context.Context,
	which string,
) (*streamState, error) {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	waitCount := 0
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if which == "alice" && s.alice != nil {
			return s.alice, nil
		}
		if which == "bob" && s.bob != nil {
			return s.bob, nil
		}
		waitCount++
		if waitCount%20 == 0 {
		}
		s.cond.Wait()
	}
}

// dialWithRetry tries until 'total' deadline
func dialWithRetry(addr string, total time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(total)
	var last error
	tries := 0
	for time.Now().Before(deadline) {
		tries++
		c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			return c, nil
		}
		last = err
		time.Sleep(50 * time.Millisecond)
	}
	return nil, fmt.Errorf("dial %s failed: %w", addr, last)
}

func (s *FerretProxyServer) cleanup(which string) {
	s.cond.L.Lock()
	defer s.cond.L.Unlock()
	var st *streamState
	if which == "alice" {
		st = s.alice
		s.alice = nil
	} else {
		st = s.bob
		s.bob = nil
	}
	if st != nil && st.alive {
		st.alive = false
		// Do NOT close sendCh; other goroutines may still select peer.sendCh <- msg
		close(st.done)
	}
	s.cond.Broadcast()
}

// AliceProxy: route frames from Alice -> Bob and Bob -> Alice
func (s *FerretProxyServer) AliceProxy(
	stream protobufs.FerretProxy_AliceProxyServer,
) error {
	st := s.registerSide("alice")
	ctx := stream.Context()

	// Sender goroutine (server -> Alice stream)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-st.done:
				return
			case msg := <-st.sendCh:
				if msg == nil {
					continue
				}
				if err := stream.Send(msg); err != nil {
					return
				}
			}
		}
	}()

	// Receiver loop (Alice -> Bob)
recvAlice:
	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				break
			}
			break
		}

		peer, perr := s.peerState(ctx, "bob")
		if perr != nil {
			break
		}
		// forward to Bob
		select {
		case peer.sendCh <- msg:
		case <-peer.done: // peer went away
			break recvAlice
		case <-ctx.Done():
			break recvAlice
		}
	}

	s.cleanup("alice")
	wg.Wait()
	return nil
}

// BobProxy: route frames from Bob -> Alice and Alice -> Bob
func (s *FerretProxyServer) BobProxy(
	stream protobufs.FerretProxy_BobProxyServer,
) error {
	st := s.registerSide("bob")
	ctx := stream.Context()

	// Sender goroutine (server -> Bob stream)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-st.done:
				return
			case msg := <-st.sendCh:
				if msg == nil {
					continue
				}
				if err := stream.Send(msg); err != nil {
					return
				}
			}
		}
	}()

	// Receiver loop (Bob -> Alice)
recvBob:
	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				break
			}
			break
		}

		peer, perr := s.peerState(ctx, "alice")
		if perr != nil {
			break
		}
		// forward to Alice
		select {
		case peer.sendCh <- msg:
		case <-peer.done: // peer went away
			break recvBob
		case <-ctx.Done():
			break recvBob
		}
	}

	s.cleanup("bob")
	wg.Wait()
	return nil
}

// AliceProxyClient bridges between Alice's local Ferret TCP server and the gRPC
// AliceProxy stream.
type AliceProxyClient struct {
	conn   *grpc.ClientConn
	stream protobufs.FerretProxy_AliceProxyClient
	tcp    net.Conn
}

// StartAliceProxy dials the proxy at serverAddr and bridges to Alice's local
// TCP server at ferretPort.
func StartAliceProxy(
	ctx context.Context,
	serverAddr string,
	ferretPort int,
) (*AliceProxyClient, error) {
	cc, err := grpc.Dial(
		serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}

	cli := protobufs.NewFerretProxyClient(cc)
	stream, err := cli.AliceProxy(ctx)
	if err != nil {
		_ = cc.Close()
		return nil, fmt.Errorf("AliceProxy: %w", err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", ferretPort)
	tcpConn, err := dialWithRetry(addr, 10*time.Second) // <-- retry
	if err != nil {
		_ = stream.CloseSend()
		_ = cc.Close()
		return nil, fmt.Errorf("dial alice TCP %d: %w", ferretPort, err)
	}

	c := &AliceProxyClient{conn: cc, stream: stream, tcp: tcpConn}
	c.startPumps(ctx)
	return c, nil
}

func (c *AliceProxyClient) startPumps(ctx context.Context) {
	// TCP -> gRPC
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := c.tcp.Read(buf)
			if n > 0 {
				if sendErr := c.stream.Send(
					&protobufs.ProxyData{Data: append([]byte(nil), buf[:n]...)},
				); sendErr != nil {
					return
				}
			}
			if err != nil {
				// half-close send side; no extra frame after CloseSend
				_ = c.stream.CloseSend()
				return
			}
		}
	}()

	// gRPC -> TCP
	go func() {
		for {
			msg, err := c.stream.Recv()
			if err != nil {
				_ = c.tcp.Close()
				return
			}
			data := msg.GetData()
			if len(data) == 0 {
				continue
			}
			if _, err := c.tcp.Write(data); err != nil {
				_ = c.tcp.Close()
				return
			}
		}
	}()
}

func (c *AliceProxyClient) Close() error {
	if c.stream != nil {
		_ = c.stream.CloseSend()
	}
	if c.tcp != nil {
		_ = c.tcp.Close()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// BobProxyClient exposes a local TCP listener for Bob's Ferret to connect to,
// and bridges that socket to the gRPC BobProxy stream.
type BobProxyClient struct {
	conn   *grpc.ClientConn
	stream protobufs.FerretProxy_BobProxyClient
	ln     net.Listener
	tcp    net.Conn
	port   int
}

// StartBobProxy starts the gRPC BobProxy stream and a local TCP listener
// (127.0.0.1:0). It returns the listener's port immediately; an accept loop
// runs in the background and begins pumping once the first connection arrives.
func StartBobProxy(ctx context.Context, serverAddr string) (
	*BobProxyClient,
	int,
	error,
) {
	cc, err := grpc.Dial(
		serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, 0, fmt.Errorf("dial proxy: %w", err)
	}
	cli := protobufs.NewFerretProxyClient(cc)
	stream, err := cli.BobProxy(ctx)
	if err != nil {
		_ = cc.Close()
		return nil, 0, fmt.Errorf("BobProxy: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = stream.CloseSend()
		_ = cc.Close()
		return nil, 0, fmt.Errorf("listen local: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	c := &BobProxyClient{conn: cc, stream: stream, ln: ln, port: port}
	c.startAcceptAndPumps(ctx)
	return c, port, nil
}

func (c *BobProxyClient) startAcceptAndPumps(ctx context.Context) {
	go func() {
		_ = c.ln.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Minute))
		tcpConn, err := c.ln.Accept()
		if err != nil {
			_ = c.stream.CloseSend()
			_ = c.conn.Close()
			_ = c.ln.Close()
			return
		}
		c.tcp = tcpConn
		_ = c.ln.Close() // single-use listener

		// TCP -> gRPC
		go func() {
			buf := make([]byte, 32*1024)
			for {
				n, err := c.tcp.Read(buf)
				if n > 0 {
					if sendErr := c.stream.Send(
						&protobufs.ProxyData{Data: append([]byte(nil), buf[:n]...)},
					); sendErr != nil {
						return
					}
				}
				if err != nil {
					_ = c.stream.CloseSend() // half-close; no extra frame
					return
				}
			}
		}()

		// gRPC -> TCP
		go func() {
			for {
				msg, err := c.stream.Recv()
				if err != nil {
					_ = c.tcp.Close()
					return
				}
				data := msg.GetData()
				if len(data) == 0 {
					continue
				}
				if _, err := c.tcp.Write(data); err != nil {
					_ = c.tcp.Close()
					return
				}
			}
		}()
	}()
}

func (c *BobProxyClient) Port() int { return c.port }

func (c *BobProxyClient) Close() error {
	if c.stream != nil {
		_ = c.stream.CloseSend()
	}
	if c.tcp != nil {
		_ = c.tcp.Close()
	}
	if c.ln != nil {
		_ = c.ln.Close()
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// StartAliceFerretWithProxy creates Alice's Ferret OT TCP server and attaches
// the proxy bridge. It returns the FerretOT instance and the proxy client
// (caller should Close both when done).
func StartAliceFerretWithProxy(
	ctx context.Context,
	proxyAddr string,
	ferretPort int,
	threads int,
	length uint64,
	choices []bool,
	malicious bool,
) (*FerretOT, *AliceProxyClient, error) {

	// Kick off the proxy dial first/in parallel so it can satisfy the accept
	// NewFerretOT waits on.
	apCh := make(chan *AliceProxyClient, 1)
	errCh := make(chan error, 1)
	go func() {
		ap, err := StartAliceProxy(ctx, proxyAddr, ferretPort) // has retry now
		if err != nil {
			errCh <- err
			return
		}
		apCh <- ap
	}()

	alice, err := NewFerretOT(
		ALICE,
		"",
		ferretPort,
		threads,
		length,
		choices,
		malicious,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("new alice ferret: %w", err)
	}

	// Wait for the proxy to finish connecting (it should succeed quickly once
	// Ferret is listening).
	var ap *AliceProxyClient
	select {
	case ap = <-apCh:
	case err := <-errCh:
		return nil, nil, err
	case <-time.After(15 * time.Second):
		return nil, nil, fmt.Errorf("alice proxy did not connect in time")
	}

	return alice, ap, nil
}

// StartBobFerretWithProxy starts the proxy Bob-side listener and returns its
// port, then creates Bob's Ferret OT that connects to that port. The proxy
// bridge begins pumping when Ferret connects.
func StartBobFerretWithProxy(
	ctx context.Context,
	proxyAddr string,
	threads int,
	length uint64,
	choices []bool,
	malicious bool,
) (*FerretOT, *BobProxyClient, error) {
	bp, port, err := StartBobProxy(ctx, proxyAddr)
	if err != nil {
		return nil, nil, err
	}
	bob, err := NewFerretOT(
		BOB,
		"127.0.0.1",
		port,
		threads,
		length,
		choices,
		malicious,
	)
	if err != nil {
		_ = bp.Close()
		return nil, nil, fmt.Errorf("new bob ferret: %w", err)
	}
	return bob, bp, nil
}
