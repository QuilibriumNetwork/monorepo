//go:build !js && !wasm

package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	npprof "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	rdebug "runtime/debug"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pbnjay/memory"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/app"
	qgrpc "source.quilibrium.com/quilibrium/monorepo/node/internal/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/rpc"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	qruntime "source.quilibrium.com/quilibrium/monorepo/utils/runtime"
)

var (
	configDirectory = flag.String(
		"config",
		filepath.Join(".", ".config"),
		"the configuration directory",
	)
	peerId = flag.Bool(
		"peer-id",
		false,
		"print the peer id to stdout from the config and exit",
	)
	cpuprofile = flag.String(
		"cpuprofile",
		"",
		"write cpu profile to file",
	)
	memprofile = flag.String(
		"memprofile",
		"",
		"write memory profile after 20m to this file",
	)
	pprofServer = flag.String(
		"pprof-server",
		"",
		"enable pprof server on specified address (e.g. localhost:6060)",
	)
	prometheusServer = flag.String(
		"prometheus-server",
		"",
		"enable prometheus server on specified address (e.g. localhost:8080)",
	)
	nodeInfo = flag.Bool(
		"node-info",
		false,
		"print node related information",
	)
	debug = flag.Bool(
		"debug",
		false,
		"sets log output to debug (verbose)",
	)
	dhtOnly = flag.Bool(
		"dht-only",
		false,
		"sets a node to run strictly as a dht bootstrap peer (not full node)",
	)
	network = flag.Uint(
		"network",
		0,
		"sets the active network for the node (mainnet = 0, primary testnet = 1)",
	)
	signatureCheck = flag.Bool(
		"signature-check",
		signatureCheckDefault(),
		"enables or disables signature validation (default true or value of QUILIBRIUM_SIGNATURE_CHECK env var)",
	)
	core = flag.Int(
		"core",
		0,
		"specifies the core of the process (defaults to zero, the initial launcher)",
	)
	parentProcess = flag.Int(
		"parent-process",
		0,
		"specifies the parent process pid for a data worker",
	)
	compactDB = flag.Bool(
		"compact-db",
		false,
		"compacts the database and exits",
	)

	// *char flags
	blockchar         = "█"
	bver              = "Bloom"
	char      *string = &blockchar
	ver       *string = &bver
)

func signatureCheckDefault() bool {
	envVarValue, envVarExists := os.LookupEnv("QUILIBRIUM_SIGNATURE_CHECK")
	if envVarExists {
		def, err := strconv.ParseBool(envVarValue)
		if err == nil {
			return def
		} else {
			fmt.Println(
				"Invalid environment variable QUILIBRIUM_SIGNATURE_CHECK, must be 'true' or 'false':",
				envVarValue,
			)
		}
	}

	return true
}

// monitorParentProcess watches parent process and signals quit channel if
// parent dies
func monitorParentProcess(
	parentProcessId int,
	quitCh chan struct{},
	logger *zap.Logger,
) {
	for {
		time.Sleep(1 * time.Second)
		proc, err := os.FindProcess(parentProcessId)
		if err != nil {
			logger.Error("parent process not found, terminating")
			close(quitCh)
			return
		}

		// Windows returns an error if the process is dead, nobody else does
		if runtime.GOOS != "windows" {
			err := proc.Signal(syscall.Signal(0))
			if err != nil {
				logger.Error("parent process not found, terminating")
				close(quitCh)
				return
			}
		}
	}
}

func main() {
	config.Flags(&char, &ver)
	flag.Parse()
	var logger *zap.Logger
	if *debug {
		logger, _ = zap.NewDevelopment()
	} else {
		logger, _ = zap.NewProduction()
	}

	if *signatureCheck {
		if runtime.GOOS == "windows" {
			logger.Info("Signature check not available for windows yet, skipping...")
		} else {
			ex, err := os.Executable()
			if err != nil {
				logger.Panic(
					"Failed to get executable path",
					zap.Error(err),
					zap.String("executable", ex),
				)
			}

			b, err := os.ReadFile(ex)
			if err != nil {
				logger.Panic(
					"Error encountered during signature check – are you running this "+
						"from source? (use --signature-check=false)",
					zap.Error(err),
				)
			}

			checksum := sha3.Sum256(b)
			digest, err := os.ReadFile(ex + ".dgst")
			if err != nil {
				logger.Fatal("digest file not found", zap.Error(err))
			}

			parts := strings.Split(string(digest), " ")
			if len(parts) != 2 {
				logger.Fatal("Invalid digest file format")
			}

			digestBytes, err := hex.DecodeString(parts[1][:64])
			if err != nil {
				logger.Fatal("invalid digest file format", zap.Error(err))
			}

			if !bytes.Equal(checksum[:], digestBytes) {
				logger.Fatal("invalid digest for node")
			}

			count := 0

			for i := 1; i <= len(config.Signatories); i++ {
				signatureFile := fmt.Sprintf(ex+".dgst.sig.%d", i)
				sig, err := os.ReadFile(signatureFile)
				if err != nil {
					continue
				}

				pubkey, _ := hex.DecodeString(config.Signatories[i-1])
				if !ed448.Verify(pubkey, digest, sig, "") {
					logger.Fatal(
						"failed signature check for signatory",
						zap.Int("signatory", i),
					)
				}
				count++
			}

			if count < ((len(config.Signatories)-4)/2)+((len(config.Signatories)-4)%2) {
				logger.Fatal("quorum on signatures not met")
			}

			logger.Info("signature check passed")
		}
	} else {
		logger.Info("signature check disabled, skipping...")
	}

	if *core == 0 {
		logger = logger.With(zap.String("process", "master"))
	} else {
		logger = logger.With(zap.String("process", fmt.Sprintf("worker %d", *core)))
	}

	if *memprofile != "" && *core == 0 {
		go func() {
			for {
				time.Sleep(5 * time.Minute)
				f, err := os.Create(*memprofile)
				if err != nil {
					logger.Fatal("failed to create memory profile file", zap.Error(err))
				}
				pprof.WriteHeapProfile(f)
				f.Close()
			}
		}()
	}

	if *cpuprofile != "" && *core == 0 {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			logger.Fatal("failed to create cpu profile file", zap.Error(err))
		}
		defer f.Close()
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if *pprofServer != "" && *core == 0 {
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/debug/pprof/", npprof.Index)
			mux.HandleFunc("/debug/pprof/cmdline", npprof.Cmdline)
			mux.HandleFunc("/debug/pprof/profile", npprof.Profile)
			mux.HandleFunc("/debug/pprof/symbol", npprof.Symbol)
			mux.HandleFunc("/debug/pprof/trace", npprof.Trace)
			logger.Fatal(
				"Failed to start pprof server",
				zap.Error(http.ListenAndServe(*pprofServer, mux)),
			)
		}()
	}

	if *prometheusServer != "" && *core == 0 {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			logger.Fatal(
				"Failed to start prometheus server",
				zap.Error(http.ListenAndServe(*prometheusServer, mux)),
			)
		}()
	}

	if *peerId {
		config, err := config.LoadConfig(*configDirectory, "", false)
		if err != nil {
			logger.Fatal("failed to load config", zap.Error(err))
		}

		printPeerID(logger, config.P2P)
		return
	}

	if *nodeInfo {
		config, err := config.LoadConfig(*configDirectory, "", false)
		if err != nil {
			logger.Fatal("failed to load config", zap.Error(err))
		}

		printNodeInfo(logger, config)
		return
	}

	if *core == 0 {
		config.PrintLogo(*char)
		config.PrintVersion(uint8(*network), *char, *ver)
		fmt.Println(" ")
	}

	nodeConfig, err := config.LoadConfig(*configDirectory, "", false)
	if err != nil {
		logger.Fatal("failed to load config", zap.Error(err))
	}

	if *compactDB {
		db := store.NewPebbleDB(logger, nodeConfig.DB, uint(*core))
		if err := db.CompactAll(); err != nil {
			logger.Fatal("failed to compact database", zap.Error(err))
		}
		if err := db.Close(); err != nil {
			logger.Fatal("failed to close database", zap.Error(err))
		}
		return
	}

	if *network != 0 {
		if nodeConfig.P2P.BootstrapPeers[0] == config.BootstrapPeers[0] {
			logger.Fatal(
				"node has specified to run outside of mainnet but is still " +
					"using default bootstrap list. this will fail. exiting.",
			)
		}

		nodeConfig.P2P.Network = uint8(*network)
		logger.Warn(
			"node is operating outside of mainnet – be sure you intended to do this.",
		)
	}

	if *dhtOnly {
		done := make(chan os.Signal, 1)
		signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
		dht, err := app.NewDHTNode(logger, nodeConfig, 0)
		if err != nil {
			logger.Error("failed to start dht node", zap.Error(err))
		}

		go func() {
			dht.Start()
		}()

		<-done
		dht.Stop()
		return
	}

	if len(nodeConfig.Engine.DataWorkerP2PMultiaddrs) == 0 {
		maxProcs, numCPU := runtime.GOMAXPROCS(0), runtime.NumCPU()
		if maxProcs > numCPU && !nodeConfig.Engine.AllowExcessiveGOMAXPROCS {
			logger.Fatal(
				"GOMAXPROCS is set higher than the number of available cpus.",
			)
		}
		nodeConfig.Engine.DataWorkerCount = qruntime.WorkerCount(
			nodeConfig.Engine.DataWorkerCount, true, true,
		)
	}

	if len(nodeConfig.Engine.DataWorkerP2PMultiaddrs) !=
		len(nodeConfig.Engine.DataWorkerStreamMultiaddrs) {
		logger.Fatal("mismatch of worker count for p2p and stream multiaddrs")
	}

	if *core != 0 {
		rdebug.SetMemoryLimit(nodeConfig.Engine.DataWorkerMemoryLimit)

		if *parentProcess == 0 &&
			len(nodeConfig.Engine.DataWorkerP2PMultiaddrs) == 0 {
			logger.Fatal("parent process pid not specified")
		}

		rpcMultiaddr := fmt.Sprintf(
			nodeConfig.Engine.DataWorkerBaseListenMultiaddr,
			int(nodeConfig.Engine.DataWorkerBaseStreamPort)+*core-1,
		)

		if len(nodeConfig.Engine.DataWorkerStreamMultiaddrs) != 0 {
			rpcMultiaddr = nodeConfig.Engine.DataWorkerStreamMultiaddrs[*core-1]
		}

		dataWorkerNode, err := app.NewDataWorkerNode(
			logger,
			nodeConfig,
			uint(*core),
			rpcMultiaddr,
			*parentProcess,
		)
		if err != nil {
			logger.Panic("failed to create data worker node", zap.Error(err))
		}

		if *parentProcess != 0 {
			go monitorParentProcess(
				*parentProcess,
				dataWorkerNode.GetQuitChannel(),
				logger,
			)
		}

		err = dataWorkerNode.Start()
		if err != nil {
			logger.Panic("failed to start data worker node", zap.Error(err))
		}

		dataWorkerNode.Stop()
		return
	} else {
		totalMemory := int64(memory.TotalMemory())
		dataWorkerReservedMemory := int64(0)
		if len(nodeConfig.Engine.DataWorkerStreamMultiaddrs) == 0 {
			dataWorkerReservedMemory =
				nodeConfig.Engine.DataWorkerMemoryLimit * int64(
					nodeConfig.Engine.DataWorkerCount,
				)
		}
		switch availableOverhead := totalMemory - dataWorkerReservedMemory; {
		case totalMemory < dataWorkerReservedMemory:
			logger.Warn(
				"the memory allocated to data workers exceeds the total system memory",
				zap.Int64("total_memory", totalMemory),
				zap.Int64("data_worker_reserved_memory", dataWorkerReservedMemory),
			)
			logger.Warn("you are at risk of running out of memory during runtime")
		case availableOverhead < 8*1024*1024*1024:
			logger.Warn(
				"the memory available to the node, unallocated to "+
					"the data workers, is less than 8gb",
				zap.Int64("available_overhead", availableOverhead),
			)
			logger.Warn("you are at risk of running out of memory during runtime")
		default:
			if _, limit := os.LookupEnv("GOMEMLIMIT"); !limit {
				rdebug.SetMemoryLimit(availableOverhead * 8 / 10)
			}
			if _, explicitGOGC := os.LookupEnv("GOGC"); !explicitGOGC {
				rdebug.SetGCPercent(10)
			}
		}
	}

	logger.Info("starting node...")

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	// Create MasterNode for core 0
	masterNode, err := app.NewMasterNode(logger, nodeConfig, uint(*core))
	if err != nil {
		logger.Panic("failed to create master node", zap.Error(err))
	}

	// Start the master node
	quitCh := make(chan struct{})
	go func() {
		if err := masterNode.Start(); err != nil {
			logger.Error("master node start error", zap.Error(err))
			close(quitCh)
		}
	}()
	defer masterNode.Stop()

	if nodeConfig.ListenGRPCMultiaddr != "" {
		srv, err := rpc.NewRPCServer(
			nodeConfig,
			masterNode.GetLogger(),
			masterNode.GetKeyManager(),
			masterNode.GetPubSub(),
			masterNode.GetPeerInfoProvider(),
			masterNode.GetWorkerManager(),
			masterNode.GetProverRegistry(),
			masterNode.GetExecutionEngineManager(),
		)
		if err != nil {
			logger.Panic("failed to new rpc server", zap.Error(err))
		}
		if err := srv.Start(); err != nil {
			logger.Panic("failed to start rpc server", zap.Error(err))
		}
		defer srv.Stop()
	}

	diskFullCh := make(chan error, 1)
	monitor := store.NewDiskMonitor(
		uint(*core),
		*nodeConfig.DB,
		logger,
		diskFullCh,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	monitor.Start(ctx)

	select {
	case <-done:
	case <-diskFullCh:
	case <-quitCh:
	}
}

func getPeerID(logger *zap.Logger, p2pConfig *config.P2PConfig) peer.ID {
	peerPrivKey, err := hex.DecodeString(p2pConfig.PeerPrivKey)
	if err != nil {
		logger.Panic("error to decode peer private key",
			zap.Error(errors.Wrap(err, "error unmarshaling peerkey")))
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		logger.Panic("error to unmarshal ed448 private key",
			zap.Error(errors.Wrap(err, "error unmarshaling peerkey")))
	}

	pub := privKey.GetPublic()
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		logger.Panic("error to get peer id", zap.Error(err))
	}

	return id
}

func printPeerID(logger *zap.Logger, p2pConfig *config.P2PConfig) {
	id := getPeerID(logger, p2pConfig)

	fmt.Println("Peer ID: " + id.String())
}

func printNodeInfo(logger *zap.Logger, cfg *config.Config) {
	if cfg.ListenGRPCMultiaddr == "" {
		logger.Fatal("gRPC Not Enabled, Please Configure")
	}

	printPeerID(logger, cfg.P2P)

	conn, err := ConnectToNode(logger, cfg)
	if err != nil {
		logger.Fatal(
			"could not connect to node. if it is still booting, please wait.",
			zap.Error(err),
		)
	}
	defer conn.Close()

	client := protobufs.NewNodeServiceClient(conn)

	nodeInfo, err := FetchNodeInfo(client)
	if err != nil {
		logger.Panic("failed to fetch node info", zap.Error(err))
	}

	fmt.Println("Version: " + config.FormatVersion(nodeInfo.Version))
	fmt.Println("Seniority: " + new(big.Int).SetBytes(
		nodeInfo.PeerSeniority,
	).String())
	fmt.Println("Active Workers:", nodeInfo.Workers)
}

var defaultGrpcAddress = "localhost:8337"

// Connect to the node via GRPC
func ConnectToNode(logger *zap.Logger, nodeConfig *config.Config) (*grpc.ClientConn, error) {
	addr := defaultGrpcAddress
	if nodeConfig.ListenGRPCMultiaddr != "" {
		ma, err := multiaddr.NewMultiaddr(nodeConfig.ListenGRPCMultiaddr)
		if err != nil {
			logger.Panic("error parsing multiaddr", zap.Error(err))
		}

		_, addr, err = mn.DialArgs(ma)
		if err != nil {
			logger.Panic("error getting dial args", zap.Error(err))
		}
	}

	return qgrpc.DialContext(
		context.Background(),
		addr,
		grpc.WithTransportCredentials(
			insecure.NewCredentials(),
		),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallSendMsgSize(600*1024*1024),
			grpc.MaxCallRecvMsgSize(600*1024*1024),
		),
	)
}

type TokenBalance struct {
	Owned            *big.Int
	UnconfirmedOwned *big.Int
}

func FetchNodeInfo(
	client protobufs.NodeServiceClient,
) (*protobufs.NodeInfoResponse, error) {
	info, err := client.GetNodeInfo(
		context.Background(),
		&protobufs.GetNodeInfoRequest{},
	)
	if err != nil {
		return nil, errors.Wrap(err, "error getting node info")
	}

	return info, nil
}
