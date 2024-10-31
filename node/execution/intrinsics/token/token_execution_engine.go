package token

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"strings"
	"sync"
	gotime "time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/data"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

type TokenExecutionEngine struct {
	logger                *zap.Logger
	clock                 *data.DataClockConsensusEngine
	clockStore            store.ClockStore
	coinStore             store.CoinStore
	keyStore              store.KeyStore
	keyManager            keys.KeyManager
	engineConfig          *config.EngineConfig
	pubSub                p2p.PubSub
	peerIdHash            []byte
	provingKey            crypto.Signer
	proverPublicKey       []byte
	provingKeyAddress     []byte
	inclusionProver       qcrypto.InclusionProver
	participantMx         sync.Mutex
	peerChannels          map[string]*p2p.PublicP2PChannel
	activeClockFrame      *protobufs.ClockFrame
	alreadyPublishedShare bool
	intrinsicFilter       []byte
	frameProver           qcrypto.FrameProver
	peerSeniority         map[string]uint64
}

func NewTokenExecutionEngine(
	logger *zap.Logger,
	cfg *config.Config,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
	frameProver qcrypto.FrameProver,
	inclusionProver qcrypto.InclusionProver,
	clockStore store.ClockStore,
	dataProofStore store.DataProofStore,
	coinStore store.CoinStore,
	masterTimeReel *time.MasterTimeReel,
	peerInfoManager p2p.PeerInfoManager,
	keyStore store.KeyStore,
	report *protobufs.SelfTestReport,
) *TokenExecutionEngine {
	if logger == nil {
		panic(errors.New("logger is nil"))
	}

	seed, err := hex.DecodeString(cfg.Engine.GenesisSeed)
	if err != nil {
		panic(err)
	}

	intrinsicFilter := p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3)

	_, _, err = clockStore.GetDataClockFrame(intrinsicFilter, 0, false)
	var origin []byte
	var inclusionProof *qcrypto.InclusionAggregateProof
	var proverKeys [][]byte
	var peerSeniority map[string]uint64
	genesisCreated := false

	if err != nil && errors.Is(err, store.ErrNotFound) {
		origin, inclusionProof, proverKeys, peerSeniority = CreateGenesisState(
			logger,
			cfg.Engine,
			nil,
			inclusionProver,
			coinStore,
			uint(cfg.P2P.Network),
		)
		if err := coinStore.SetMigrationVersion(
			config.GetGenesis().GenesisSeedHex,
		); err != nil {
			panic(err)
		}
		genesisCreated = true
	} else if err != nil {
		panic(err)
	} else {
		err := coinStore.Migrate(
			intrinsicFilter,
			config.GetGenesis().GenesisSeedHex,
		)
		if err != nil {
			panic(err)
		}
		_, err = clockStore.GetEarliestDataClockFrame(intrinsicFilter)
		if err != nil && errors.Is(err, store.ErrNotFound) {
			origin, inclusionProof, proverKeys, peerSeniority = CreateGenesisState(
				logger,
				cfg.Engine,
				nil,
				inclusionProver,
				coinStore,
				uint(cfg.P2P.Network),
			)
			genesisCreated = true
		}
	}

	e := &TokenExecutionEngine{
		logger:                logger,
		engineConfig:          cfg.Engine,
		keyManager:            keyManager,
		clockStore:            clockStore,
		coinStore:             coinStore,
		keyStore:              keyStore,
		pubSub:                pubSub,
		inclusionProver:       inclusionProver,
		frameProver:           frameProver,
		participantMx:         sync.Mutex{},
		peerChannels:          map[string]*p2p.PublicP2PChannel{},
		alreadyPublishedShare: false,
		intrinsicFilter:       intrinsicFilter,
		peerSeniority:         peerSeniority,
	}

	dataTimeReel := time.NewDataTimeReel(
		intrinsicFilter,
		logger,
		clockStore,
		cfg.Engine,
		frameProver,
		func(txn store.Transaction, frame *protobufs.ClockFrame) error {
			if err := e.VerifyExecution(frame); err != nil {
				return err
			}
			if err := e.ProcessFrame(txn, frame); err != nil {
				return err
			}

			return nil
		},
		origin,
		inclusionProof,
		proverKeys,
	)

	e.clock = data.NewDataClockConsensusEngine(
		cfg,
		logger,
		keyManager,
		clockStore,
		coinStore,
		dataProofStore,
		keyStore,
		pubSub,
		frameProver,
		inclusionProver,
		masterTimeReel,
		dataTimeReel,
		peerInfoManager,
		report,
		intrinsicFilter,
		seed,
		peerSeniority,
	)

	peerId := e.pubSub.GetPeerID()
	addr, err := poseidon.HashBytes(peerId)
	if err != nil {
		panic(err)
	}

	addrBytes := addr.FillBytes(make([]byte, 32))
	e.peerIdHash = addrBytes
	provingKey, _, publicKeyBytes, provingKeyAddress := e.clock.GetProvingKey(
		cfg.Engine,
	)
	e.provingKey = provingKey
	e.proverPublicKey = publicKeyBytes
	e.provingKeyAddress = provingKeyAddress

	if genesisCreated {
		go func() {
			keys := [][]byte{}
			ksigs := [][]byte{}
			if len(e.engineConfig.MultisigProverEnrollmentPaths) != 0 {
				for _, conf := range e.engineConfig.MultisigProverEnrollmentPaths {
					extraConf, err := config.LoadConfig(conf, "", false)
					if err != nil {
						panic(err)
					}

					peerPrivKey, err := hex.DecodeString(extraConf.P2P.PeerPrivKey)
					if err != nil {
						panic(errors.Wrap(err, "error unmarshaling peerkey"))
					}

					privKey, err := pcrypto.UnmarshalEd448PrivateKey(peerPrivKey)
					if err != nil {
						panic(errors.Wrap(err, "error unmarshaling peerkey"))
					}

					pub := privKey.GetPublic()
					pubBytes, err := pub.Raw()
					if err != nil {
						panic(errors.Wrap(err, "error unmarshaling peerkey"))
					}

					keys = append(keys, pubBytes)
					sig, err := privKey.Sign(e.pubSub.GetPublicKey())
					if err != nil {
						panic(errors.Wrap(err, "error unmarshaling peerkey"))
					}
					ksigs = append(ksigs, sig)
				}
			}

			keyjoin := []byte{}
			for _, k := range keys {
				keyjoin = append(keyjoin, k...)
			}

			mainsig, err := e.pubSub.SignMessage(keyjoin)
			if err != nil {
				panic(err)
			}

			announce := &protobufs.TokenRequest_Announce{
				Announce: &protobufs.AnnounceProverRequest{
					PublicKeySignaturesEd448: []*protobufs.Ed448Signature{},
				},
			}

			announce.Announce.PublicKeySignaturesEd448 = append(
				announce.Announce.PublicKeySignaturesEd448,
				&protobufs.Ed448Signature{
					PublicKey: &protobufs.Ed448PublicKey{
						KeyValue: e.pubSub.GetPublicKey(),
					},
					Signature: mainsig,
				},
			)

			for i := range keys {
				announce.Announce.PublicKeySignaturesEd448 = append(
					announce.Announce.PublicKeySignaturesEd448,
					&protobufs.Ed448Signature{
						PublicKey: &protobufs.Ed448PublicKey{
							KeyValue: keys[i],
						},
						Signature: ksigs[i],
					},
				)
			}

			req := &protobufs.TokenRequest{
				Request: announce,
			}

			// need to wait for peering
			gotime.Sleep(30 * gotime.Second)
			e.publishMessage(intrinsicFilter, req)
		}()
	} else {
		f, _, err := e.clockStore.GetLatestDataClockFrame(e.intrinsicFilter)
		fn, err := coinStore.GetLatestFrameProcessed()
		if err != nil {
			panic(err)
		}

		if f.FrameNumber != fn && fn == 0 {
			txn, err := coinStore.NewTransaction()
			if err != nil {
				panic(err)
			}

			err = coinStore.SetLatestFrameProcessed(txn, f.FrameNumber)
			if err != nil {
				txn.Abort()
				panic(err)
			}

			if err = txn.Commit(); err != nil {
				panic(err)
			}
		} else if f.FrameNumber-fn == 1 && f.FrameNumber > fn {
			txn, err := coinStore.NewTransaction()
			if err != nil {
				panic(err)
			}
			e.logger.Info(
				"replaying last data frame",
				zap.Uint64("frame_number", f.FrameNumber),
			)
			e.ProcessFrame(txn, f)
			if err = txn.Commit(); err != nil {
				panic(err)
			}
		}

		if err == nil {
			// msg := []byte("resume")
			// msg = binary.BigEndian.AppendUint64(msg, f.FrameNumber)
			// msg = append(msg, e.intrinsicFilter...)
			// sig, err := e.pubSub.SignMessage(msg)
			// if err != nil {
			// 	panic(err)
			// }

			// // need to wait for peering
			// gotime.Sleep(30 * gotime.Second)
			// e.publishMessage(e.intrinsicFilter, &protobufs.AnnounceProverResume{
			// 	Filter:      e.intrinsicFilter,
			// 	FrameNumber: f.FrameNumber,
			// 	PublicKeySignatureEd448: &protobufs.Ed448Signature{
			// 		PublicKey: &protobufs.Ed448PublicKey{
			// 			KeyValue: e.pubSub.GetPublicKey(),
			// 		},
			// 		Signature: sig,
			// 	},
			// })
		}
	}

	return e
}

var _ execution.ExecutionEngine = (*TokenExecutionEngine)(nil)

// GetName implements ExecutionEngine
func (*TokenExecutionEngine) GetName() string {
	return "Token"
}

// GetSupportedApplications implements ExecutionEngine
func (
	*TokenExecutionEngine,
) GetSupportedApplications() []*protobufs.Application {
	return []*protobufs.Application{
		{
			Address:          application.TOKEN_ADDRESS,
			ExecutionContext: protobufs.ExecutionContext_EXECUTION_CONTEXT_INTRINSIC,
		},
	}
}

// Start implements ExecutionEngine
func (e *TokenExecutionEngine) Start() <-chan error {
	errChan := make(chan error)

	go func() {
		err := <-e.clock.Start()
		if err != nil {
			panic(err)
		}

		err = <-e.clock.RegisterExecutor(e, 0)
		if err != nil {
			panic(err)
		}

		errChan <- nil
	}()

	return errChan
}

// Stop implements ExecutionEngine
func (e *TokenExecutionEngine) Stop(force bool) <-chan error {
	errChan := make(chan error)

	go func() {
		errChan <- <-e.clock.Stop(force)
	}()

	return errChan
}

// ProcessMessage implements ExecutionEngine
func (e *TokenExecutionEngine) ProcessMessage(
	address []byte,
	message *protobufs.Message,
) ([]*protobufs.Message, error) {
	if bytes.Equal(address, e.GetSupportedApplications()[0].Address) {
		any := &anypb.Any{}
		if err := proto.Unmarshal(message.Payload, any); err != nil {
			return nil, errors.Wrap(err, "process message")
		}

		e.logger.Debug(
			"processing execution message",
			zap.String("type", any.TypeUrl),
		)

		switch any.TypeUrl {
		case protobufs.TokenRequestType:
			if e.clock.IsInProverTrie(e.proverPublicKey) {
				payload, err := proto.Marshal(any)
				if err != nil {
					return nil, errors.Wrap(err, "process message")
				}

				h, err := poseidon.HashBytes(payload)
				if err != nil {
					return nil, errors.Wrap(err, "process message")
				}

				msg := &protobufs.Message{
					Hash:    h.Bytes(),
					Address: application.TOKEN_ADDRESS,
					Payload: payload,
				}
				return []*protobufs.Message{
					msg,
				}, nil
			}
		}
	}

	return nil, nil
}

func (e *TokenExecutionEngine) ProcessFrame(
	txn store.Transaction,
	frame *protobufs.ClockFrame,
) error {
	f, err := e.coinStore.GetLatestFrameProcessed()
	if err != nil || f == frame.FrameNumber {
		return errors.Wrap(err, "process frame")
	}

	e.activeClockFrame = frame
	e.logger.Info(
		"evaluating next frame",
		zap.Uint64(
			"frame_number",
			frame.FrameNumber,
		),
	)
	app, err := application.MaterializeApplicationFromFrame(
		e.provingKey,
		frame,
		e.clock.GetFrameProverTries(),
		e.coinStore,
		e.logger,
	)
	if err != nil {
		e.logger.Error(
			"error while materializing application from frame",
			zap.Error(err),
		)
		return errors.Wrap(err, "process frame")
	}

	e.logger.Debug(
		"app outputs",
		zap.Int("outputs", len(app.TokenOutputs.Outputs)),
	)

	for i, output := range app.TokenOutputs.Outputs {
		switch o := output.Output.(type) {
		case *protobufs.TokenOutput_Coin:
			address, err := GetAddressOfCoin(o.Coin, frame.FrameNumber, uint64(i))
			if err != nil {
				txn.Abort()
				return errors.Wrap(err, "process frame")
			}
			err = e.coinStore.PutCoin(
				txn,
				frame.FrameNumber,
				address,
				o.Coin,
			)
			if err != nil {
				txn.Abort()
				return errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_DeletedCoin:
			coin, err := e.coinStore.GetCoinByAddress(txn, o.DeletedCoin.Address)
			if err != nil {
				txn.Abort()
				return errors.Wrap(err, "process frame")
			}
			err = e.coinStore.DeleteCoin(
				txn,
				o.DeletedCoin.Address,
				coin,
			)
			if err != nil {
				txn.Abort()
				return errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_Proof:
			address, err := GetAddressOfPreCoinProof(o.Proof)
			if err != nil {
				txn.Abort()
				return errors.Wrap(err, "process frame")
			}
			err = e.coinStore.PutPreCoinProof(
				txn,
				frame.FrameNumber,
				address,
				o.Proof,
			)
			if err != nil {
				txn.Abort()
				return errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_DeletedProof:
			address, err := GetAddressOfPreCoinProof(o.DeletedProof)
			if err != nil {
				txn.Abort()
				return errors.Wrap(err, "process frame")
			}
			err = e.coinStore.DeletePreCoinProof(
				txn,
				address,
				o.DeletedProof,
			)
			if err != nil {
				txn.Abort()
				return errors.Wrap(err, "process frame")
			}
		}
	}

	err = e.coinStore.SetLatestFrameProcessed(txn, frame.FrameNumber)
	if err != nil {
		txn.Abort()
		return errors.Wrap(err, "process frame")
	}

	return nil
}

func (e *TokenExecutionEngine) publishMessage(
	filter []byte,
	message proto.Message,
) error {
	any := &anypb.Any{}
	if err := any.MarshalFrom(message); err != nil {
		return errors.Wrap(err, "publish message")
	}

	any.TypeUrl = strings.Replace(
		any.TypeUrl,
		"type.googleapis.com",
		"types.quilibrium.com",
		1,
	)

	payload, err := proto.Marshal(any)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	h, err := poseidon.HashBytes(payload)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	msg := &protobufs.Message{
		Hash:    h.Bytes(),
		Address: application.TOKEN_ADDRESS,
		Payload: payload,
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}
	return e.pubSub.PublishToBitmask(filter, data)
}

func (e *TokenExecutionEngine) VerifyExecution(
	frame *protobufs.ClockFrame,
) error {
	if len(frame.AggregateProofs) > 0 {
		for _, proofs := range frame.AggregateProofs {
			for _, inclusion := range proofs.InclusionCommitments {
				if inclusion.TypeUrl == protobufs.IntrinsicExecutionOutputType {
					transition, _, err := application.GetOutputsFromClockFrame(frame)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					parent, tries, err := e.clockStore.GetDataClockFrame(
						append(
							p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3),
						),
						frame.FrameNumber-1,
						false,
					)
					if err != nil && !errors.Is(err, store.ErrNotFound) {
						return errors.Wrap(err, "verify execution")
					}

					if parent == nil && frame.FrameNumber != 0 {
						return errors.Wrap(
							errors.New("missing parent frame"),
							"verify execution",
						)
					}

					a, err := application.MaterializeApplicationFromFrame(
						e.provingKey,
						parent,
						tries,
						e.coinStore,
						e.logger,
					)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					a, _, _, err = a.ApplyTransitions(
						frame.FrameNumber,
						transition,
						false,
					)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					a2, err := application.MaterializeApplicationFromFrame(
						e.provingKey,
						frame,
						tries,
						e.coinStore,
						e.logger,
					)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					if len(a.TokenOutputs.Outputs) != len(a2.TokenOutputs.Outputs) {
						return errors.Wrap(
							errors.New("mismatched outputs"),
							"verify execution",
						)
					}

					for i := range a.TokenOutputs.Outputs {
						o1 := a.TokenOutputs.Outputs[i]
						o2 := a2.TokenOutputs.Outputs[i]
						if !proto.Equal(o1, o2) {
							return errors.Wrap(
								errors.New("mismatched messages"),
								"verify execution",
							)
						}
					}

					return nil
				}
			}
		}
	}

	return nil
}

func (e *TokenExecutionEngine) GetPeerInfo() *protobufs.PeerInfoResponse {
	return e.clock.GetPeerInfo()
}

func (e *TokenExecutionEngine) GetFrame() *protobufs.ClockFrame {
	return e.clock.GetFrame()
}
