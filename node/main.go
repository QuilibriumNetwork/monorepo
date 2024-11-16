//go:build !js && !wasm

package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
	"source.quilibrium.com/quilibrium/monorepo/node/utils"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pbnjay/memory"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"source.quilibrium.com/quilibrium/monorepo/node/app"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto/kzg"
	"source.quilibrium.com/quilibrium/monorepo/node/rpc"
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

	if *core != 0 {
		// runtime.GOMAXPROCS(2)
		rdebug.SetGCPercent(9999)

		if nodeConfig.Engine.DataWorkerMemoryLimit == 0 {
			nodeConfig.Engine.DataWorkerMemoryLimit = 1792 * 1024 * 1024 // 1.75GiB
		}

		rdebug.SetMemoryLimit(nodeConfig.Engine.DataWorkerMemoryLimit)

		if nodeConfig.Engine.DataWorkerBaseListenMultiaddr == "" {
			nodeConfig.Engine.DataWorkerBaseListenMultiaddr = "/ip4/127.0.0.1/tcp/%d"
		}

		if nodeConfig.Engine.DataWorkerBaseListenPort == 0 {
			nodeConfig.Engine.DataWorkerBaseListenPort = 40000
		}

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
	}

	fmt.Println("Loading ceremony state and starting node...")

	if !*integrityCheck {
		go spawnDataWorkers(nodeConfig)
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

	RunForkRepairIfNeeded(nodeConfig)

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

		go func() {
			err := srv.Start()
			if err != nil {
				panic(err)
			}
		}()
	}

	node.Start()

	<-done
	stopDataWorkers()
	node.Stop()
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

	cores := runtime.GOMAXPROCS(0)
	dataWorkers = make([]*exec.Cmd, cores-1)
	fmt.Printf("Spawning %d data workers...\n", cores-1)

	for i := 1; i <= cores-1; i++ {
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

//go:embed overrideFrames.json
var overrideFramesData []byte

func RunForkRepairIfNeeded(
	nodeConfig *config.Config,
) {
	logger, _ := zap.NewDevelopment()
	db := store.NewPebbleDB(&config.DBConfig{Path: nodeConfig.DB.Path})
	defer db.Close()
	clockStore := store.NewPebbleClockStore(db, logger)
	coinStore := store.NewPebbleCoinStore(db, logger)
	filter := p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3)
	frame, _, err := clockStore.GetDataClockFrame(filter, uint64(48995), false)
	if err != nil {
		fmt.Println("No repair needed.")
		return
	}

	compareSel, _ := frame.GetSelector()
	badFrameSelector, _ := hex.DecodeString("16515bf99a55d24c35d1dd0a0c7d778154e5ffa6dfa3ad164f11355f4cb00056")

	if bytes.Equal(badFrameSelector, compareSel.FillBytes(make([]byte, 32))) {
		logger.Info("performing fork repair")
		txn, _ := coinStore.NewTransaction()
		_, outs, _ := application.GetOutputsFromClockFrame(frame)
		logger.Info("removing invalid frame at position 48995")
		for i, output := range outs.Outputs {
			switch o := output.Output.(type) {
			case *protobufs.TokenOutput_Coin:
				address, _ := token.GetAddressOfCoin(o.Coin, frame.FrameNumber, uint64(i))
				coin, err := coinStore.GetCoinByAddress(txn, address)
				if err != nil {
					fmt.Println(err)
					return
				}
				if err = coinStore.DeleteCoin(txn, address, coin); err != nil {
					txn.Abort()
					fmt.Println(err)
					return
				}
			case *protobufs.TokenOutput_Proof:
				address, _ := token.GetAddressOfPreCoinProof(o.Proof)
				proof, err := coinStore.GetPreCoinProofByAddress(address)
				if err != nil {
					txn.Abort()
					fmt.Println(err)
					return
				}
				if err = coinStore.DeletePreCoinProof(txn, address, proof); err != nil {
					txn.Abort()
					fmt.Println(err)
					return
				}
			}
		}

		if err = txn.Commit(); err != nil {
			txn.Abort()

			logger.Error("could not commit data", zap.Error(err))
			return
		}

		logger.Info("inserting valid frame starting at position 48995")
		type OverrideFrames struct {
			FrameData []byte `json:"frameData"`
		}
		overrideFramesJson := []*OverrideFrames{}
		if err = json.Unmarshal(overrideFramesData, &overrideFramesJson); err != nil {
			txn.Abort()
			logger.Error("could not unmarshal overriding frame data", zap.Error(err))
			return
		}

		for _, overrideFrame := range overrideFramesJson {
			override := &protobufs.ClockFrame{}
			if err := proto.Unmarshal(overrideFrame.FrameData, override); err != nil {
				logger.Error("could not unmarshal frame data", zap.Error(err))
				return
			}

			txn, _ := clockStore.NewTransaction()
			if err := overrideHead(
				txn,
				clockStore,
				coinStore,
				override,
				logger,
			); err != nil {
				txn.Abort()
				logger.Error("could not override frame data", zap.Error(err))
				return
			}

			if err = txn.Commit(); err != nil {
				txn.Abort()

				logger.Error("could not commit data", zap.Error(err))
				return
			}
		}
	} else {
		fmt.Println("No repair needed.")
		return
	}
}

func overrideHead(
	txn store.Transaction,
	clockStore store.ClockStore,
	coinStore store.CoinStore,
	frame *protobufs.ClockFrame,
	logger *zap.Logger,
) error {
	selector, err := frame.GetSelector()
	if err != nil {
		panic(err)
	}
	filter := p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3)

	_, ts, err := clockStore.GetDataClockFrame(
		filter,
		frame.FrameNumber-1,
		false,
	)
	if err != nil {
		logger.Error("could not get frame", zap.Error(err), zap.Uint64("frame", frame.FrameNumber-1))
		return errors.Wrap(err, "set head")
	}

	if err := clockStore.StageDataClockFrame(
		selector.FillBytes(make([]byte, 32)),
		frame,
		txn,
	); err != nil {
		panic(err)
	}

	if ts, err = processFrame(txn, frame, ts, coinStore, clockStore, logger); err != nil {
		logger.Error("invalid frame execution, unwinding", zap.Error(err))
		txn.Abort()
		return errors.Wrap(err, "set head")
	}

	if err := clockStore.CommitDataClockFrame(
		filter,
		frame.FrameNumber,
		selector.FillBytes(make([]byte, 32)),
		ts,
		txn,
		false,
	); err != nil {
		panic(err)
	}

	return nil
}

func processFrame(
	txn store.Transaction,
	frame *protobufs.ClockFrame,
	triesAtFrame []*tries.RollingFrecencyCritbitTrie,
	coinStore store.CoinStore,
	clockStore store.ClockStore,
	logger *zap.Logger,
) ([]*tries.RollingFrecencyCritbitTrie, error) {
	f, err := coinStore.GetLatestFrameProcessed()
	if err != nil || f == frame.FrameNumber {
		return nil, errors.Wrap(err, "process frame")
	}

	logger.Info(
		"evaluating next frame",
		zap.Uint64(
			"frame_number",
			frame.FrameNumber,
		),
	)
	m, err := clockStore.GetPeerSeniorityMap(frame.Filter)
	if err != nil {
		logger.Error(
			"error while materializing seniority map",
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "process frame")
	}
	peerSeniority := token.NewFromMap(m)

	app, err := application.MaterializeApplicationFromFrame(
		nil,
		frame,
		triesAtFrame,
		coinStore,
		clockStore,
		nil,
		logger,
	)
	if err != nil {
		logger.Error(
			"error while materializing application from frame",
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "process frame")
	}

	proverTrieJoinRequests := [][]byte{}
	proverTrieLeaveRequests := [][]byte{}

	for i, output := range app.TokenOutputs.Outputs {
		i := i
		if frame.FrameNumber == 0 {
			i = 0
		}
		switch o := output.Output.(type) {
		case *protobufs.TokenOutput_Coin:
			address, err := token.GetAddressOfCoin(o.Coin, frame.FrameNumber, uint64(i))
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			err = coinStore.PutCoin(
				txn,
				frame.FrameNumber,
				address,
				o.Coin,
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_DeletedCoin:
			coin, err := coinStore.GetCoinByAddress(txn, o.DeletedCoin.Address)
			if err != nil {
				if frame.FrameNumber == 48997 {
					// special case, the fork happened at 48995, state replayed here
					continue
				}
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			err = coinStore.DeleteCoin(
				txn,
				o.DeletedCoin.Address,
				coin,
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_Proof:
			address, err := token.GetAddressOfPreCoinProof(o.Proof)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			err = coinStore.PutPreCoinProof(
				txn,
				frame.FrameNumber,
				address,
				o.Proof,
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			if len(o.Proof.Amount) == 32 &&
				!bytes.Equal(o.Proof.Amount, make([]byte, 32)) &&
				o.Proof.Commitment != nil {
				addr := string(o.Proof.Owner.GetImplicitAccount().Address)
				for _, t := range app.Tries {
					if t.Contains([]byte(addr)) {
						t.Add([]byte(addr), frame.FrameNumber)
						break
					}
				}
				if _, ok := (*peerSeniority)[addr]; !ok {
					(*peerSeniority)[addr] = token.NewPeerSeniorityItem(10, addr)
				} else {
					(*peerSeniority)[addr] = token.NewPeerSeniorityItem(
						(*peerSeniority)[addr].GetSeniority()+10,
						addr,
					)
				}
			}
		case *protobufs.TokenOutput_DeletedProof:
			address, err := token.GetAddressOfPreCoinProof(o.DeletedProof)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			err = coinStore.DeletePreCoinProof(
				txn,
				address,
				o.DeletedProof,
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_Announce:
			peerIds := []string{}
			for _, sig := range o.Announce.PublicKeySignaturesEd448 {
				peerId, err := getPeerIdFromSignature(sig)
				if err != nil {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				peerIds = append(peerIds, peerId.String())
			}

			mergeable := true
			for i, peerId := range peerIds {
				addr, err := getAddressFromSignature(
					o.Announce.PublicKeySignaturesEd448[i],
				)
				if err != nil {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}
				sen, ok := (*peerSeniority)[string(addr)]
				if !ok {
					continue
				}

				peer := new(big.Int).SetUint64(sen.GetSeniority())
				if peer.Cmp(token.GetAggregatedSeniority([]string{peerId})) != 0 {
					mergeable = false
					break
				}
			}

			if mergeable {
				addr, err := getAddressFromSignature(
					o.Announce.PublicKeySignaturesEd448[0],
				)
				if err != nil {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				additional := uint64(0)
				_, prfs, err := coinStore.GetPreCoinProofsForOwner(addr)
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				for _, pr := range prfs {
					if pr.IndexProof == nil && pr.Difficulty == 0 && pr.Commitment == nil {
						// approximate average per interval:
						add := new(big.Int).SetBytes(pr.Amount)
						add.Quo(add, big.NewInt(58800000))
						if add.Cmp(big.NewInt(4000000)) > 0 {
							add = big.NewInt(4000000)
						}
						additional = add.Uint64()
					}
				}

				(*peerSeniority)[string(addr)] = token.NewPeerSeniorityItem(
					token.GetAggregatedSeniority(peerIds).Uint64()+additional,
					string(addr),
				)

				for _, sig := range o.Announce.PublicKeySignaturesEd448[1:] {
					addr, err := getAddressFromSignature(
						sig,
					)
					if err != nil {
						txn.Abort()
						return nil, errors.Wrap(err, "process frame")
					}

					(*peerSeniority)[string(addr)] = token.NewPeerSeniorityItem(0, string(addr))
				}
			}
		case *protobufs.TokenOutput_Join:
			addr, err := getAddressFromSignature(o.Join.PublicKeySignatureEd448)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			if _, ok := (*peerSeniority)[string(addr)]; !ok {
				(*peerSeniority)[string(addr)] = token.NewPeerSeniorityItem(20, string(addr))
			} else {
				(*peerSeniority)[string(addr)] = token.NewPeerSeniorityItem(
					(*peerSeniority)[string(addr)].GetSeniority()+20,
					string(addr),
				)
			}
			proverTrieJoinRequests = append(proverTrieJoinRequests, addr)
		case *protobufs.TokenOutput_Leave:
			addr, err := getAddressFromSignature(o.Leave.PublicKeySignatureEd448)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			proverTrieLeaveRequests = append(proverTrieLeaveRequests, addr)
		case *protobufs.TokenOutput_Pause:
			_, err := getAddressFromSignature(o.Pause.PublicKeySignatureEd448)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_Resume:
			_, err := getAddressFromSignature(o.Resume.PublicKeySignatureEd448)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_Penalty:
			addr := string(o.Penalty.Account.GetImplicitAccount().Address)
			if _, ok := (*peerSeniority)[addr]; !ok {
				(*peerSeniority)[addr] = token.NewPeerSeniorityItem(0, addr)
				proverTrieLeaveRequests = append(proverTrieLeaveRequests, []byte(addr))
			} else {
				if (*peerSeniority)[addr].GetSeniority() > o.Penalty.Quantity {
					for _, t := range app.Tries {
						if t.Contains([]byte(addr)) {
							v := t.Get([]byte(addr))
							latest := v.LatestFrame
							if frame.FrameNumber-latest > 100 {
								proverTrieLeaveRequests = append(proverTrieLeaveRequests, []byte(addr))
							}
							break
						}
					}
					(*peerSeniority)[addr] = token.NewPeerSeniorityItem(
						(*peerSeniority)[addr].GetSeniority()-o.Penalty.Quantity,
						addr,
					)
				} else {
					(*peerSeniority)[addr] = token.NewPeerSeniorityItem(0, addr)
					proverTrieLeaveRequests = append(proverTrieLeaveRequests, []byte(addr))
				}
			}
		}
	}

	joinAddrs := tries.NewMinHeap[token.PeerSeniorityItem]()
	leaveAddrs := tries.NewMinHeap[token.PeerSeniorityItem]()
	for _, addr := range proverTrieJoinRequests {
		if _, ok := (*peerSeniority)[string(addr)]; !ok {
			joinAddrs.Push(token.NewPeerSeniorityItem(0, string(addr)))
		} else {
			joinAddrs.Push((*peerSeniority)[string(addr)])
		}
	}
	for _, addr := range proverTrieLeaveRequests {
		if _, ok := (*peerSeniority)[string(addr)]; !ok {
			leaveAddrs.Push(token.NewPeerSeniorityItem(0, string(addr)))
		} else {
			leaveAddrs.Push((*peerSeniority)[string(addr)])
		}
	}

	joinReqs := make([]token.PeerSeniorityItem, len(joinAddrs.All()))
	copy(joinReqs, joinAddrs.All())
	slices.Reverse(joinReqs)
	leaveReqs := make([]token.PeerSeniorityItem, len(leaveAddrs.All()))
	copy(leaveReqs, leaveAddrs.All())
	slices.Reverse(leaveReqs)

	token.ProcessJoinsAndLeaves(joinReqs, leaveReqs, app, peerSeniority, frame)

	err = clockStore.PutPeerSeniorityMap(
		txn,
		frame.Filter,
		token.ToSerializedMap(peerSeniority),
	)
	if err != nil {
		txn.Abort()
		return nil, errors.Wrap(err, "process frame")
	}

	err = coinStore.SetLatestFrameProcessed(txn, frame.FrameNumber)
	if err != nil {
		txn.Abort()
		return nil, errors.Wrap(err, "process frame")
	}

	return app.Tries, nil
}

func getPeerIdFromSignature(
	sig *protobufs.Ed448Signature,
) (peer.ID, error) {
	if sig.PublicKey == nil || sig.PublicKey.KeyValue == nil {
		return "", errors.New("invalid data")
	}

	pk, err := crypto.UnmarshalEd448PublicKey(
		sig.PublicKey.KeyValue,
	)
	if err != nil {
		return "", errors.Wrap(err, "get address from signature")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return "", errors.Wrap(err, "get address from signature")
	}

	return peerId, nil
}

func getAddressFromSignature(
	sig *protobufs.Ed448Signature,
) ([]byte, error) {
	if sig.PublicKey == nil || sig.PublicKey.KeyValue == nil {
		return nil, errors.New("invalid data")
	}

	pk, err := crypto.UnmarshalEd448PublicKey(
		sig.PublicKey.KeyValue,
	)
	if err != nil {
		return nil, errors.Wrap(err, "get address from signature")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return nil, errors.Wrap(err, "get address from signature")
	}

	altAddr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		return nil, errors.Wrap(err, "get address from signature")
	}

	return altAddr.FillBytes(make([]byte, 32)), nil
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
	printBalance(cfg)
}
