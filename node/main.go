//go:build !js && !wasm

package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	npprof "net/http/pprof"
	"os"
	"os/exec"
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
	"github.com/pbnjay/memory"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/app"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto/kzg"
	qruntime "source.quilibrium.com/quilibrium/monorepo/node/internal/runtime"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/rpc"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/utils"
)

var (
	configDirectory = flag.String(
		"config",
		filepath.Join(".", ".config"),
		"the configuration directory",
	)
	balance = flag.Bool(
		"balance",
		false,
		"print the node's confirmed token balance to stdout and exit",
	)
	dbConsole = flag.Bool(
		"db-console",
		false,
		"starts the node in database console mode",
	)
	importPrivKey = flag.String(
		"import-priv-key",
		"",
		"creates a new config using a specific key from the phase one ceremony",
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
	integrityCheck = flag.Bool(
		"integrity-check",
		false,
		"runs an integrity check on the store, helpful for confirming backups are not corrupted (defaults to false)",
	)
	lightProver = flag.Bool(
		"light-prover",
		true,
		"when enabled, frame execution validation is skipped",
	)
	compactDB = flag.Bool(
		"compact-db",
		false,
		"compacts the database and exits",
	)
	strictSyncServer = flag.String(
		"strict-sync-server",
		"",
		"runs only a server to listen for hypersync requests, uses multiaddr format (e.g. /ip4/0.0.0.0/tcp/8339)",
	)
	strictSyncClient = flag.String(
		"strict-sync-client",
		"",
		"runs only a client to connect to a server listening for hypersync requests, uses multiaddr format (e.g. /ip4/127.0.0.1/tcp/8339)",
	)
)

func signatureCheckDefault() bool {
	envVarValue, envVarExists := os.LookupEnv("QUILIBRIUM_SIGNATURE_CHECK")
	if envVarExists {
		def, err := strconv.ParseBool(envVarValue)
		if err == nil {
			return def
		} else {
			utils.GetLogger().Error(
				"Invalid environment variable QUILIBRIUM_SIGNATURE_CHECK, must be 'true' or 'false'.",
				zap.String("envVarValue", envVarValue))
		}
	}

	return true
}

func main() {
	flag.Parse()
	logger := utils.GetLogger()

	if *signatureCheck {
		sLogger := logger.With(zap.String("stage", "signature-check"))
		if runtime.GOOS == "windows" {
			sLogger.Info("Signature check not available for windows yet, skipping...")
		} else {
			ex, err := os.Executable()
			if err != nil {
				sLogger.Panic("Failed to get executable path", zap.Error(err), zap.String("executable", ex))
			}

			b, err := os.ReadFile(ex)
			if err != nil {
				sLogger.Panic("Error encountered during signature check – are you running this "+
					"from source? (use --signature-check=false)",
					zap.Error(err))
			}

			checksum := sha3.Sum256(b)
			digest, err := os.ReadFile(ex + ".dgst")
			if err != nil {
				sLogger.Fatal("Digest file not found", zap.Error(err))
			}

			parts := strings.Split(string(digest), " ")
			if len(parts) != 2 {
				sLogger.Fatal("Invalid digest file format")
			}

			digestBytes, err := hex.DecodeString(parts[1][:64])
			if err != nil {
				sLogger.Fatal("Invalid digest file format", zap.Error(err))
			}

			if !bytes.Equal(checksum[:], digestBytes) {
				sLogger.Fatal("Invalid digest for node")
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
					sLogger.Fatal("Failed signature check for signatory", zap.Int("signatory", i))
				}
				count++
			}

			if count < ((len(config.Signatories)-4)/2)+((len(config.Signatories)-4)%2) {
				sLogger.Fatal("Quorum on signatures not met")
			}

			sLogger.Info("Signature check passed")
		}
	} else {
		logger.Info("Signature check disabled, skipping...")
	}

	if *memprofile != "" && *core == 0 {
		go func() {
			for {
				time.Sleep(5 * time.Minute)
				f, err := os.Create(*memprofile)
				if err != nil {
					logger.Fatal("Failed to create memory profile file", zap.Error(err))
				}
				pprof.WriteHeapProfile(f)
				f.Close()
			}
		}()
	}

	if *cpuprofile != "" && *core == 0 {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			logger.Fatal("Failed to create CPU profile file", zap.Error(err))
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
			logger.Fatal("Failed to start pprof server", zap.Error(http.ListenAndServe(*pprofServer, mux)))
		}()
	}

	if *prometheusServer != "" && *core == 0 {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			logger.Fatal("Failed to start prometheus server", zap.Error(http.ListenAndServe(*prometheusServer, mux)))
		}()
	}

	if *balance {
		config, err := config.LoadConfig(*configDirectory, "", false)
		if err != nil {
			logger.Fatal("Failed to load config", zap.Error(err))
		}

		printBalance(config)

		return
	}

	if *peerId {
		config, err := config.LoadConfig(*configDirectory, "", false)
		if err != nil {
			logger.Fatal("Failed to load config", zap.Error(err))
		}

		printPeerID(config.P2P)
		return
	}

	if *importPrivKey != "" {
		config, err := config.LoadConfig(*configDirectory, *importPrivKey, false)
		if err != nil {
			logger.Fatal("Failed to load config", zap.Error(err))
		}

		printPeerID(config.P2P)
		logger.Info("Import completed, you are ready for the launch.")
		return
	}

	if *nodeInfo {
		config, err := config.LoadConfig(*configDirectory, "", false)
		if err != nil {
			logger.Fatal("Failed to load config", zap.Error(err))
		}

		printNodeInfo(config)
		return
	}

	if !*dbConsole && *core == 0 {
		config.PrintLogo()
		config.PrintVersion(uint8(*network))
		fmt.Println(" ")
	}

	nodeConfig, err := config.LoadConfig(*configDirectory, "", false)
	if err != nil {
		logger.Fatal("Failed to load config", zap.Error(err))
	}

	if *compactDB && *core == 0 {
		db := store.NewPebbleDB(nodeConfig.DB)
		if err := db.CompactAll(); err != nil {
			logger.Fatal("Failed to compact database", zap.Error(err))
		}
		if err := db.Close(); err != nil {
			logger.Fatal("Failed to close database", zap.Error(err))
		}
		return
	}

	if *network != 0 {
		if nodeConfig.P2P.BootstrapPeers[0] == config.BootstrapPeers[0] {
			logger.Fatal(
				"Node has specified to run outside of mainnet but is still " +
					"using default bootstrap list. This will fail. Exiting.",
			)
		}

		nodeConfig.Engine.GenesisSeed = fmt.Sprintf(
			"%02x%s",
			byte(*network),
			nodeConfig.Engine.GenesisSeed,
		)
		nodeConfig.P2P.Network = uint8(*network)
		logger.Warn(
			"Node is operating outside of mainnet – be sure you intended to do this.",
		)
	}

	// If it's not explicitly set to true, we should defer to flags
	if !nodeConfig.Engine.FullProver {
		nodeConfig.Engine.FullProver = !*lightProver
	}

	clearIfTestData(*configDirectory, nodeConfig)

	if *dbConsole {
		console, err := app.NewDBConsole(nodeConfig)
		if err != nil {
			logger.Panic("Failed to start database console", zap.Error(err))
		}

		console.Run()
		return
	}

	if *dhtOnly {
		done := make(chan os.Signal, 1)
		signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
		dht, err := app.NewDHTNode(nodeConfig)
		if err != nil {
			logger.Error("Failed to start DHT node", zap.Error(err))
		}

		go func() {
			dht.Start()
		}()

		<-done
		dht.Stop()
		return
	}

	if len(nodeConfig.Engine.DataWorkerMultiaddrs) == 0 {
		maxProcs, numCPU := runtime.GOMAXPROCS(0), runtime.NumCPU()
		if maxProcs > numCPU && !nodeConfig.Engine.AllowExcessiveGOMAXPROCS {
			logger.Fatal("GOMAXPROCS is set higher than the number of available CPUs.")
		}

		nodeConfig.Engine.DataWorkerCount = qruntime.WorkerCount(
			nodeConfig.Engine.DataWorkerCount, true,
		)
	}

	if *core != 0 {
		rdebug.SetMemoryLimit(nodeConfig.Engine.DataWorkerMemoryLimit)

		if *parentProcess == 0 && len(nodeConfig.Engine.DataWorkerMultiaddrs) == 0 {
			logger.Fatal("parent process pid not specified")
		}

		rpcMultiaddr := fmt.Sprintf(
			nodeConfig.Engine.DataWorkerBaseListenMultiaddr,
			int(nodeConfig.Engine.DataWorkerBaseListenPort)+*core-1,
		)

		if len(nodeConfig.Engine.DataWorkerMultiaddrs) != 0 {
			rpcMultiaddr = nodeConfig.Engine.DataWorkerMultiaddrs[*core-1]
		}

		srv, err := rpc.NewDataWorkerIPCServer(
			rpcMultiaddr,
			logger,
			uint32(*core)-1,
			qcrypto.NewWesolowskiFrameProver(logger),
			nodeConfig,
			*parentProcess,
		)
		if err != nil {
			logger.Panic("Failed to start data worker server", zap.Error(err))
		}

		err = srv.Start()
		if err != nil {
			logger.Panic("Failed to start data worker server", zap.Error(err))
		}
		return
	} else {
		totalMemory := int64(memory.TotalMemory())
		dataWorkerReservedMemory := int64(0)
		if len(nodeConfig.Engine.DataWorkerMultiaddrs) == 0 {
			dataWorkerReservedMemory = nodeConfig.Engine.DataWorkerMemoryLimit * int64(nodeConfig.Engine.DataWorkerCount)
		}
		switch availableOverhead := totalMemory - dataWorkerReservedMemory; {
		case totalMemory < dataWorkerReservedMemory:
			logger.Warn("The memory allocated to data workers exceeds the total system memory.",
				zap.Int64("totalMemory", totalMemory),
				zap.Int64("dataWorkerReservedMemory", dataWorkerReservedMemory),
			)
			logger.Warn("You are at risk of running out of memory during runtime.")
		case availableOverhead < 8*1024*1024*1024:
			logger.Warn("The memory available to the node, unallocated to the data workers, is less than 8GiB.",
				zap.Int64("availableOverhead", availableOverhead))
			logger.Warn("You are at risk of running out of memory during runtime.")
		default:
			if _, explicitGOMEMLIMIT := os.LookupEnv("GOMEMLIMIT"); !explicitGOMEMLIMIT {
				rdebug.SetMemoryLimit(availableOverhead * 8 / 10)
			}
			if _, explicitGOGC := os.LookupEnv("GOGC"); !explicitGOGC {
				rdebug.SetGCPercent(10)
			}
		}
	}

	logger.Info("Loading ceremony state and starting node...")

	if !*integrityCheck {
		go spawnDataWorkers(nodeConfig)
		defer stopDataWorkers()
	}

	kzg.Init()

	report := RunSelfTestIfNeeded(*configDirectory, nodeConfig)

	if *core == 0 {
		for {
			genesis, err := config.DownloadAndVerifyGenesis(uint(nodeConfig.P2P.Network))
			if err != nil {
				time.Sleep(10 * time.Minute)
				continue
			}

			nodeConfig.Engine.GenesisSeed = genesis.GenesisSeedHex
			break
		}
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	var node *app.Node
	if *debug && *strictSyncServer == "" && *strictSyncClient == "" {
		node, err = app.NewDebugNode(nodeConfig, report)
	} else if *strictSyncServer != "" {
		logger.Info("Running in strict sync server mode, will not connect to regular p2p network...")

		node, err = app.NewStrictSyncNode(
			nodeConfig,
			report,
			rpc.NewStandaloneHypersyncServer(
				nodeConfig.DB,
				*strictSyncServer,
			),
		)
	} else if *strictSyncClient != "" {
		logger.Info("Running in strict sync client mode, will not connect to regular p2p network...")

		node, err = app.NewStrictSyncNode(
			nodeConfig,
			report,
			rpc.NewStandaloneHypersyncClient(nodeConfig.DB, *strictSyncClient, done),
		)
	} else {
		node, err = app.NewNode(nodeConfig, report)
	}

	if err != nil {
		logger.Panic("Failed to start node", zap.Error(err))
	}

	if *integrityCheck {
		logger.Info("Running integrity check...")
		node.VerifyProofIntegrity()
		logger.Info("Integrity check passed!")
		return
	}

	// runtime.GOMAXPROCS(1)

	node.Start()
	defer node.Stop()

	if nodeConfig.ListenGRPCMultiaddr != "" && *strictSyncServer == "" &&
		*strictSyncClient == "" {
		srv, err := rpc.NewRPCServer(
			nodeConfig.ListenGRPCMultiaddr,
			nodeConfig.ListenRestMultiaddr,
			node.GetLogger(),
			node.GetDataProofStore(),
			node.GetClockStore(),
			node.GetCoinStore(),
			node.GetKeyManager(),
			node.GetPubSub(),
			node.GetMasterClock(),
			node.GetExecutionEngines(),
		)
		if err != nil {
			logger.Panic("Failed to new RPC server", zap.Error(err))
		}
		if err := srv.Start(); err != nil {
			logger.Panic("Failed to start RPC server", zap.Error(err))
		}
		defer srv.Stop()
	}

	<-done
}

var dataWorkers []*exec.Cmd

func spawnDataWorkers(nodeConfig *config.Config) {
	logger := utils.GetLogger().With(zap.String("stage", "spawn-data-worker"))
	if len(nodeConfig.Engine.DataWorkerMultiaddrs) != 0 {
		logger.Warn("Data workers configured by multiaddr, be sure these are running...")
		return
	}

	process, err := os.Executable()
	if err != nil {
		logger.Panic("Failed to get executable path", zap.Error(err))
	}

	dataWorkers = make([]*exec.Cmd, nodeConfig.Engine.DataWorkerCount)
	logger.Info("Spawning data workers", zap.Int("count", nodeConfig.Engine.DataWorkerCount))

	for i := 1; i <= nodeConfig.Engine.DataWorkerCount; i++ {
		i := i
		go func() {
			for {
				args := []string{
					fmt.Sprintf("--core=%d", i),
					fmt.Sprintf("--parent-process=%d", os.Getpid()),
				}
				args = append(args, os.Args[1:]...)
				cmd := exec.Command(process, args...)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stdout
				err := cmd.Start()
				if err != nil {
					logger.Panic("Failed to start data worker",
						zap.String("cmd", cmd.String()),
						zap.Error(err))
				}

				dataWorkers[i-1] = cmd
				cmd.Wait()
				time.Sleep(25 * time.Millisecond)
				logger.Info("Data worker stopped, restarting...", zap.Int("worker-number", i))
			}
		}()
	}
}

func stopDataWorkers() {
	for i := 0; i < len(dataWorkers); i++ {
		err := dataWorkers[i].Process.Signal(os.Kill)
		if err != nil {
			utils.GetLogger().Info("unable to kill worker",
				zap.Int("pid", dataWorkers[i].Process.Pid),
				zap.Error(err),
			)
		}
	}
}

func RunSelfTestIfNeeded(
	configDir string,
	nodeConfig *config.Config,
) *protobufs.SelfTestReport {
	logger := utils.GetLogger()

	cores := runtime.GOMAXPROCS(0)
	if len(nodeConfig.Engine.DataWorkerMultiaddrs) != 0 {
		cores = len(nodeConfig.Engine.DataWorkerMultiaddrs) + 1
	}

	memory := memory.TotalMemory()
	d, err := os.Stat(filepath.Join(configDir, "store"))
	if d == nil {
		err := os.Mkdir(filepath.Join(configDir, "store"), 0755)
		if err != nil {
			logger.Panic("Failed to create store directory", zap.Error(err))
		}
	}

	report := &protobufs.SelfTestReport{}

	report.Cores = uint32(cores)
	report.Memory = binary.BigEndian.AppendUint64([]byte{}, memory)
	disk := utils.GetDiskSpace(nodeConfig.DB.Path)
	report.Storage = binary.BigEndian.AppendUint64([]byte{}, disk)
	logger.Info("writing report")

	report.Capabilities = []*protobufs.Capability{
		{
			ProtocolIdentifier: 0x020000,
		},
	}
	reportBytes, err := proto.Marshal(report)
	if err != nil {
		logger.Panic("Failed to marshal self test report", zap.Error(err))
	}

	err = os.WriteFile(
		filepath.Join(configDir, "SELF_TEST"),
		reportBytes,
		fs.FileMode(0600),
	)
	if err != nil {
		logger.Panic("Failed to write self test report", zap.Error(err))
	}

	return report
}

func clearIfTestData(configDir string, nodeConfig *config.Config) {
	logger := utils.GetLogger().With(zap.String("stage", "clear-test-data"))
	_, err := os.Stat(filepath.Join(configDir, "RELEASE_VERSION"))
	if os.IsNotExist(err) {
		logger.Info("Clearing test data...")
		err := os.RemoveAll(nodeConfig.DB.Path)
		if err != nil {
			logger.Panic("Failed to remove test data", zap.Error(err))
		}

		versionFile, err := os.OpenFile(
			filepath.Join(configDir, "RELEASE_VERSION"),
			os.O_CREATE|os.O_RDWR,
			fs.FileMode(0600),
		)
		if err != nil {
			logger.Panic("Failed to open RELEASE_VERSION file", zap.Error(err))
		}

		_, err = versionFile.Write([]byte{0x01, 0x00, 0x00})
		if err != nil {
			logger.Panic("Failed to write RELEASE_VERSION file", zap.Error(err))
		}

		err = versionFile.Close()
		if err != nil {
			logger.Panic("Failed to close RELEASE_VERSION file", zap.Error(err))
		}
	}
}

func printBalance(config *config.Config) {
	logger := utils.GetLogger()
	if config.ListenGRPCMultiaddr == "" {
		logger.Fatal("gRPC Not Enabled, Please Configure")
	}

	conn, err := app.ConnectToNode(config)
	if err != nil {
		logger.Panic("Connect to node failed", zap.Error(err))
	}
	defer conn.Close()

	client := protobufs.NewNodeServiceClient(conn)

	balance, err := app.FetchTokenBalance(client)
	if err != nil {
		logger.Panic("Failed to fetch token balance", zap.Error(err))
	}

	conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
	r := new(big.Rat).SetFrac(balance.Owned, conversionFactor)
	fmt.Println("Owned balance:", r.FloatString(12), "QUIL")
	fmt.Println("Note: bridged balance is not reflected here, you must bridge back to QUIL to use QUIL on mainnet.")
}

func getPeerID(p2pConfig *config.P2PConfig) peer.ID {
	logger := utils.GetLogger()
	peerPrivKey, err := hex.DecodeString(p2pConfig.PeerPrivKey)
	if err != nil {
		logger.Panic("Error to decode peer private key",
			zap.Error(errors.Wrap(err, "error unmarshaling peerkey")))
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		logger.Panic("Error to unmarshal ed448 private key",
			zap.Error(errors.Wrap(err, "error unmarshaling peerkey")))
	}

	pub := privKey.GetPublic()
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		logger.Panic("Error to get peer id", zap.Error(err))
	}

	return id
}

func printPeerID(p2pConfig *config.P2PConfig) {
	id := getPeerID(p2pConfig)

	fmt.Println("Peer ID: " + id.String())
}

func printNodeInfo(cfg *config.Config) {
	logger := utils.GetLogger()
	if cfg.ListenGRPCMultiaddr == "" {
		logger.Fatal("gRPC Not Enabled, Please Configure")
	}

	printPeerID(cfg.P2P)

	conn, err := app.ConnectToNode(cfg)
	if err != nil {
		logger.Fatal("Could not connect to node. If it is still booting, please wait.", zap.Error(err))
	}
	defer conn.Close()

	client := protobufs.NewNodeServiceClient(conn)

	nodeInfo, err := app.FetchNodeInfo(client)
	if err != nil {
		logger.Panic("Failed to fetch node info", zap.Error(err))
	}

	fmt.Println("Version: " + config.FormatVersion(nodeInfo.Version))
	fmt.Println("Max Frame: " + strconv.FormatUint(nodeInfo.GetMaxFrame(), 10))
	if nodeInfo.ProverRing == -1 {
		fmt.Println("Not in Prover Ring")
	} else {
		fmt.Println("Prover Ring: " + strconv.FormatUint(
			uint64(nodeInfo.ProverRing),
			10,
		))
	}
	fmt.Println("Seniority: " + new(big.Int).SetBytes(
		nodeInfo.PeerSeniority,
	).String())
	fmt.Println("Active Workers:", nodeInfo.Workers)
	printBalance(cfg)
}
