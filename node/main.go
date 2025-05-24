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
	"log"
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
	migrate = flag.String(
		"migrate",
		"",
		"migrate from Pebble to MDBX from specified path (e.g. /home/user/backup/.config/store)",
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
)

func signatureCheckDefault() bool {
	envVarValue, envVarExists := os.LookupEnv("QUILIBRIUM_SIGNATURE_CHECK")
	if envVarExists {
		def, err := strconv.ParseBool(envVarValue)
		if err == nil {
			return def
		} else {
			fmt.Println("Invalid environment variable QUILIBRIUM_SIGNATURE_CHECK, must be 'true' or 'false'. Got: " + envVarValue)
		}
	}

	return true
}

func main() {
	flag.Parse()

	if *signatureCheck {
		if runtime.GOOS == "windows" {
			fmt.Println("Signature check not available for windows yet, skipping...")
		} else {
			ex, err := os.Executable()
			if err != nil {
				panic(err)
			}

			b, err := os.ReadFile(ex)
			if err != nil {
				fmt.Println(
					"Error encountered during signature check – are you running this " +
						"from source? (use --signature-check=false)",
				)
				panic(err)
			}

			checksum := sha3.Sum256(b)
			digest, err := os.ReadFile(ex + ".dgst")
			if err != nil {
				fmt.Println("Digest file not found")
				os.Exit(1)
			}

			parts := strings.Split(string(digest), " ")
			if len(parts) != 2 {
				fmt.Println("Invalid digest file format")
				os.Exit(1)
			}

			digestBytes, err := hex.DecodeString(parts[1][:64])
			if err != nil {
				fmt.Println("Invalid digest file format")
				os.Exit(1)
			}

			if !bytes.Equal(checksum[:], digestBytes) {
				fmt.Println("Invalid digest for node")
				os.Exit(1)
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
					fmt.Printf("Failed signature check for signatory #%d\n", i)
					os.Exit(1)
				}
				count++
			}

			if count < ((len(config.Signatories)-4)/2)+((len(config.Signatories)-4)%2) {
				fmt.Printf("Quorum on signatures not met")
				os.Exit(1)
			}

			fmt.Println("Signature check passed")
		}
	} else {
		fmt.Println("Signature check disabled, skipping...")
	}

	if *memprofile != "" && *core == 0 {
		go func() {
			for {
				time.Sleep(5 * time.Minute)
				f, err := os.Create(*memprofile)
				if err != nil {
					log.Fatal(err)
				}
				pprof.WriteHeapProfile(f)
				f.Close()
			}
		}()
	}

	if *cpuprofile != "" && *core == 0 {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
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
			log.Fatal(http.ListenAndServe(*pprofServer, mux))
		}()
	}

	if *prometheusServer != "" && *core == 0 {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			log.Fatal(http.ListenAndServe(*prometheusServer, mux))
		}()
	}

	if *balance {
		config, err := config.LoadConfig(*configDirectory, "", false)
		if err != nil {
			panic(err)
		}

		printBalance(config)

		return
	}

	if *peerId {
		config, err := config.LoadConfig(*configDirectory, "", false)
		if err != nil {
			panic(err)
		}

		printPeerID(config.P2P)
		return
	}

	if *importPrivKey != "" {
		config, err := config.LoadConfig(*configDirectory, *importPrivKey, false)
		if err != nil {
			panic(err)
		}

		printPeerID(config.P2P)
		fmt.Println("Import completed, you are ready for the launch.")
		return
	}

	if *nodeInfo {
		config, err := config.LoadConfig(*configDirectory, "", false)
		if err != nil {
			panic(err)
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
		panic(err)
	}

	if *compactDB && *core == 0 {
		db := store.NewMDBXDB(nodeConfig.DB)
		if err := db.CompactAll(); err != nil {
			panic(err)
		}
		if err := db.Close(); err != nil {
			panic(err)
		}
		return
	}

	if *network != 0 {
		if nodeConfig.P2P.BootstrapPeers[0] == config.BootstrapPeers[0] {
			fmt.Println(
				"Node has specified to run outside of mainnet but is still " +
					"using default bootstrap list. This will fail. Exiting.",
			)
			os.Exit(1)
		}

		nodeConfig.Engine.GenesisSeed = fmt.Sprintf(
			"%02x%s",
			byte(*network),
			nodeConfig.Engine.GenesisSeed,
		)
		nodeConfig.P2P.Network = uint8(*network)
		fmt.Println(
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
			panic(err)
		}

		console.Run()
		return
	}
	if *migrate != "" {
		fmt.Printf("Migrating from Pebble to MDBX from %s\n", *migrate)
		d, err := os.Stat(filepath.Join(*migrate, "LOCK"))
		if err != nil || d == nil {
			fmt.Printf("%s does not look like a pebble db! Double check your path", *migrate)
			return
		}
		dbConfig := &config.DBConfig{
			Path: *migrate,
		}
		pebbleInput := store.NewPebbleDB(dbConfig)
		mdbxOutput := store.NewMDBXDB(nodeConfig.DB)

		allIter, err := pebbleInput.NewIter(nil, nil)
		if err != nil {
			panic(err)
		}
		batch := mdbxOutput.NewBatch(false)
		total := 0
		for allIter.First(); allIter.Valid(); allIter.Next() {
			err := batch.Set(allIter.Key(), allIter.Value())
			if err != nil {
				panic(err)
			}
			total++
			if total%10_000 == 0 {
				err := batch.Commit()
				if err != nil {
					panic(err)
				}
				fmt.Printf("Commit. Total: %d\n", total)
			}
		}
		err = batch.Commit()
		if err != nil {
			panic(err)
		}
		fmt.Printf("Commit. Total: %d\n", total)
		err = allIter.Close()
		if err != nil {
			panic(err)
		}
		err = pebbleInput.Close()
		if err != nil {
			panic(err)
		}
		err = mdbxOutput.Close()
		if err != nil {
			panic(err)
		}
		fmt.Println("Done.")

		return
	}

	if *dhtOnly {
		done := make(chan os.Signal, 1)
		signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
		dht, err := app.NewDHTNode(nodeConfig)
		if err != nil {
			panic(err)
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
			fmt.Println("GOMAXPROCS is set higher than the number of available CPUs.")
			os.Exit(1)
		}

		nodeConfig.Engine.DataWorkerCount = qruntime.WorkerCount(
			nodeConfig.Engine.DataWorkerCount, true,
		)
	}

	if *core != 0 {
		rdebug.SetMemoryLimit(nodeConfig.Engine.DataWorkerMemoryLimit)

		if *parentProcess == 0 && len(nodeConfig.Engine.DataWorkerMultiaddrs) == 0 {
			panic("parent process pid not specified")
		}

		l, err := zap.NewProduction()
		if err != nil {
			panic(err)
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
			l,
			uint32(*core)-1,
			qcrypto.NewWesolowskiFrameProver(l),
			nodeConfig,
			*parentProcess,
		)
		if err != nil {
			panic(err)
		}

		err = srv.Start()
		if err != nil {
			panic(err)
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
			fmt.Println("The memory allocated to data workers exceeds the total system memory.")
			fmt.Println("You are at risk of running out of memory during runtime.")
		case availableOverhead < 8*1024*1024*1024:
			fmt.Println("The memory available to the node, unallocated to the data workers, is less than 8GiB.")
			fmt.Println("You are at risk of running out of memory during runtime.")
		default:
			if _, explicitGOMEMLIMIT := os.LookupEnv("GOMEMLIMIT"); !explicitGOMEMLIMIT {
				rdebug.SetMemoryLimit(availableOverhead * 8 / 10)
			}
			if _, explicitGOGC := os.LookupEnv("GOGC"); !explicitGOGC {
				rdebug.SetGCPercent(10)
			}
		}
	}

	fmt.Println("Loading ceremony state and starting node...")

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
	if *debug {
		node, err = app.NewDebugNode(nodeConfig, report)
	} else {
		node, err = app.NewNode(nodeConfig, report)
	}

	if err != nil {
		panic(err)
	}

	if *integrityCheck {
		fmt.Println("Running integrity check...")
		node.VerifyProofIntegrity()
		fmt.Println("Integrity check passed!")
		return
	}

	// runtime.GOMAXPROCS(1)

	node.Start()
	defer node.Stop()

	if nodeConfig.ListenGRPCMultiaddr != "" {
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
			panic(err)
		}
		if err := srv.Start(); err != nil {
			panic(err)
		}
		defer srv.Stop()
	}

	<-done
}

var dataWorkers []*exec.Cmd

func spawnDataWorkers(nodeConfig *config.Config) {
	if len(nodeConfig.Engine.DataWorkerMultiaddrs) != 0 {
		fmt.Println(
			"Data workers configured by multiaddr, be sure these are running...",
		)
		return
	}

	process, err := os.Executable()
	if err != nil {
		panic(err)
	}

	dataWorkers = make([]*exec.Cmd, nodeConfig.Engine.DataWorkerCount)
	fmt.Printf("Spawning %d data workers...\n", nodeConfig.Engine.DataWorkerCount)

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
					panic(err)
				}

				dataWorkers[i-1] = cmd
				cmd.Wait()
				time.Sleep(25 * time.Millisecond)
				fmt.Printf("Data worker %d stopped, restarting...\n", i)
			}
		}()
	}
}

func stopDataWorkers() {
	for i := 0; i < len(dataWorkers); i++ {
		err := dataWorkers[i].Process.Signal(os.Kill)
		if err != nil {
			fmt.Printf(
				"fatal: unable to kill worker with pid %d, please kill this process!\n",
				dataWorkers[i].Process.Pid,
			)
		}
	}
}

func RunSelfTestIfNeeded(
	configDir string,
	nodeConfig *config.Config,
) *protobufs.SelfTestReport {
	logger, _ := zap.NewProduction()

	cores := runtime.GOMAXPROCS(0)
	if len(nodeConfig.Engine.DataWorkerMultiaddrs) != 0 {
		cores = len(nodeConfig.Engine.DataWorkerMultiaddrs) + 1
	}

	memory := memory.TotalMemory()
	d, err := os.Stat(filepath.Join(configDir, "store"))
	if d == nil {
		err := os.Mkdir(filepath.Join(configDir, "store"), 0755)
		if err != nil {
			panic(err)
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
		panic(err)
	}

	err = os.WriteFile(
		filepath.Join(configDir, "SELF_TEST"),
		reportBytes,
		fs.FileMode(0600),
	)
	if err != nil {
		panic(err)
	}

	return report
}

func clearIfTestData(configDir string, nodeConfig *config.Config) {
	_, err := os.Stat(filepath.Join(configDir, "RELEASE_VERSION"))
	if os.IsNotExist(err) {
		fmt.Println("Clearing test data...")
		err := os.RemoveAll(nodeConfig.DB.Path)
		if err != nil {
			panic(err)
		}

		versionFile, err := os.OpenFile(
			filepath.Join(configDir, "RELEASE_VERSION"),
			os.O_CREATE|os.O_RDWR,
			fs.FileMode(0600),
		)
		if err != nil {
			panic(err)
		}

		_, err = versionFile.Write([]byte{0x01, 0x00, 0x00})
		if err != nil {
			panic(err)
		}

		err = versionFile.Close()
		if err != nil {
			panic(err)
		}
	}
}

func printBalance(config *config.Config) {
	if config.ListenGRPCMultiaddr == "" {
		_, _ = fmt.Fprintf(os.Stderr, "gRPC Not Enabled, Please Configure\n")
		os.Exit(1)
	}

	conn, err := app.ConnectToNode(config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	client := protobufs.NewNodeServiceClient(conn)

	balance, err := app.FetchTokenBalance(client)
	if err != nil {
		panic(err)
	}

	conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
	r := new(big.Rat).SetFrac(balance.Owned, conversionFactor)
	fmt.Println("Owned balance:", r.FloatString(12), "QUIL")
	fmt.Println("Note: bridged balance is not reflected here, you must bridge back to QUIL to use QUIL on mainnet.")
}

func getPeerID(p2pConfig *config.P2PConfig) peer.ID {
	peerPrivKey, err := hex.DecodeString(p2pConfig.PeerPrivKey)
	if err != nil {
		panic(errors.Wrap(err, "error unmarshaling peerkey"))
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		panic(errors.Wrap(err, "error unmarshaling peerkey"))
	}

	pub := privKey.GetPublic()
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		panic(errors.Wrap(err, "error getting peer id"))
	}

	return id
}

func printPeerID(p2pConfig *config.P2PConfig) {
	id := getPeerID(p2pConfig)

	fmt.Println("Peer ID: " + id.String())
}

func printNodeInfo(cfg *config.Config) {
	if cfg.ListenGRPCMultiaddr == "" {
		_, _ = fmt.Fprintf(os.Stderr, "gRPC Not Enabled, Please Configure\n")
		os.Exit(1)
	}

	printPeerID(cfg.P2P)

	conn, err := app.ConnectToNode(cfg)
	if err != nil {
		fmt.Println("Could not connect to node. If it is still booting, please wait.")
		os.Exit(1)
	}
	defer conn.Close()

	client := protobufs.NewNodeServiceClient(conn)

	nodeInfo, err := app.FetchNodeInfo(client)
	if err != nil {
		panic(err)
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
