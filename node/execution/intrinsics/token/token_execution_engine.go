package token

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"sync"
	gotime "time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
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
	"source.quilibrium.com/quilibrium/monorepo/node/internal/frametime"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

type PeerSeniorityItem struct {
	seniority uint64
	addr      string
}

func NewPeerSeniorityItem(seniority uint64, addr string) PeerSeniorityItem {
	return PeerSeniorityItem{
		seniority: seniority,
		addr:      addr,
	}
}

func (p PeerSeniorityItem) GetSeniority() uint64 {
	return p.seniority
}

func (p PeerSeniorityItem) GetAddr() string {
	return p.addr
}

type PeerSeniority map[string]PeerSeniorityItem

func NewFromMap(m map[string]uint64) *PeerSeniority {
	s := &PeerSeniority{}
	for k, v := range m {
		(*s)[k] = PeerSeniorityItem{
			seniority: v,
			addr:      k,
		}
	}
	return s
}

func ToSerializedMap(m *PeerSeniority) map[string]uint64 {
	s := map[string]uint64{}
	for k, v := range *m {
		s[k] = v.seniority
	}
	return s
}

func (p PeerSeniorityItem) Priority() uint64 {
	return p.seniority
}

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
	peerSeniority         *PeerSeniority
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

	if err != nil && errors.Is(err, store.ErrNotFound) {
		origin, inclusionProof, proverKeys, peerSeniority = CreateGenesisState(
			logger,
			cfg.Engine,
			nil,
			inclusionProver,
			clockStore,
			coinStore,
			uint(cfg.P2P.Network),
		)
		if err := coinStore.SetMigrationVersion(
			config.GetGenesis().GenesisSeedHex,
		); err != nil {
			panic(err)
		}
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
				clockStore,
				coinStore,
				uint(cfg.P2P.Network),
			)
		}
	}

	if len(peerSeniority) == 0 {
		peerSeniority, err = clockStore.GetPeerSeniorityMap(intrinsicFilter)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			panic(err)
		}

		if len(peerSeniority) == 0 {
			peerSeniority, err = RebuildPeerSeniority(uint(cfg.P2P.Network))
			if err != nil {
				panic(err)
			}

			txn, err := clockStore.NewTransaction()
			if err != nil {
				panic(err)
			}

			err = clockStore.PutPeerSeniorityMap(txn, intrinsicFilter, peerSeniority)
			if err != nil {
				txn.Abort()
				panic(err)
			}

			if err = txn.Commit(); err != nil {
				txn.Abort()
				panic(err)
			}
		}
	} else {
		LoadAggregatedSeniorityMap(uint(cfg.P2P.Network))
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
		peerSeniority:         NewFromMap(peerSeniority),
	}

	alwaysSend := false
	if bytes.Equal(config.GetGenesis().Beacon, pubSub.GetPublicKey()) {
		alwaysSend = true
	}

	restore := func() []*tries.RollingFrecencyCritbitTrie {
		frame, _, err := clockStore.GetLatestDataClockFrame(intrinsicFilter)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			panic(err)
		}

		tries := []*tries.RollingFrecencyCritbitTrie{
			&tries.RollingFrecencyCritbitTrie{},
		}
		proverKeys = [][]byte{config.GetGenesis().Beacon}
		for _, key := range proverKeys {
			addr, _ := poseidon.HashBytes(key)
			tries[0].Add(addr.FillBytes(make([]byte, 32)), 0)
			if err = clockStore.SetProverTriesForFrame(frame, tries); err != nil {
				panic(err)
			}
		}
		peerSeniority, err = RebuildPeerSeniority(uint(cfg.P2P.Network))
		if err != nil {
			panic(err)
		}

		txn, err := clockStore.NewTransaction()
		if err != nil {
			panic(err)
		}

		err = clockStore.PutPeerSeniorityMap(txn, intrinsicFilter, peerSeniority)
		if err != nil {
			txn.Abort()
			panic(err)
		}

		if err = txn.Commit(); err != nil {
			txn.Abort()
			panic(err)
		}

		return tries
	}

	dataTimeReel := time.NewDataTimeReel(
		intrinsicFilter,
		logger,
		clockStore,
		cfg.Engine,
		frameProver,
		func(
			txn store.Transaction,
			frame *protobufs.ClockFrame,
			triesAtFrame []*tries.RollingFrecencyCritbitTrie,
		) (
			[]*tries.RollingFrecencyCritbitTrie,
			error,
		) {
			if e.engineConfig.FullProver {
				if err := e.VerifyExecution(frame, triesAtFrame); err != nil {
					return nil, err
				}
			}
			var tries []*tries.RollingFrecencyCritbitTrie
			if tries, err = e.ProcessFrame(txn, frame, triesAtFrame); err != nil {
				return nil, err
			}

			return tries, nil
		},
		origin,
		inclusionProof,
		proverKeys,
		alwaysSend,
		restore,
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

	go func() {
		f, tries, err := e.clockStore.GetLatestDataClockFrame(e.intrinsicFilter)
		if err != nil {
			return
		}

		shouldResume := false
		for _, trie := range tries[1:] {
			altAddr, err := poseidon.HashBytes(e.pubSub.GetPeerID())
			if err != nil {
				break
			}

			if trie.Contains(altAddr.FillBytes(make([]byte, 32))) {
				shouldResume = true
				break
			}
		}

		if shouldResume {
			msg := []byte("resume")
			msg = binary.BigEndian.AppendUint64(msg, f.FrameNumber)
			msg = append(msg, e.intrinsicFilter...)
			sig, err := e.pubSub.SignMessage(msg)
			if err != nil {
				panic(err)
			}

			// need to wait for peering
			for {
				gotime.Sleep(30 * gotime.Second)
				peerMap := e.pubSub.GetBitmaskPeers()
				if peers, ok := peerMap[string(
					append([]byte{0x00}, e.intrinsicFilter...),
				)]; ok {
					if len(peers) >= 3 {
						break
					}
				}
			}
			e.publishMessage(
				append([]byte{0x00}, e.intrinsicFilter...),
				&protobufs.TokenRequest{
					Request: &protobufs.TokenRequest_Resume{
						Resume: &protobufs.AnnounceProverResume{
							Filter:      e.intrinsicFilter,
							FrameNumber: f.FrameNumber,
							PublicKeySignatureEd448: &protobufs.Ed448Signature{
								PublicKey: &protobufs.Ed448PublicKey{
									KeyValue: e.pubSub.GetPublicKey(),
								},
								Signature: sig,
							},
						},
					},
					Timestamp: gotime.Now().UnixMilli(),
				},
			)
		}
	}()

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
	triesAtFrame []*tries.RollingFrecencyCritbitTrie,
) ([]*tries.RollingFrecencyCritbitTrie, error) {
	f, err := e.coinStore.GetLatestFrameProcessed()
	if err != nil || f == frame.FrameNumber {
		return nil, errors.Wrap(err, "process frame")
	}

	e.activeClockFrame = frame
	e.logger.Info(
		"evaluating next frame",
		zap.Uint64(
			"frame_number",
			frame.FrameNumber,
		),
		zap.Duration("frame_age", frametime.Since(frame)),
	)
	app, err := application.MaterializeApplicationFromFrame(
		e.provingKey,
		frame,
		triesAtFrame,
		e.coinStore,
		e.clockStore,
		e.pubSub,
		e.logger,
	)
	if err != nil {
		e.logger.Error(
			"error while materializing application from frame",
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "process frame")
	}

	e.logger.Debug(
		"app outputs",
		zap.Int("outputs", len(app.TokenOutputs.Outputs)),
	)

	proverTrieJoinRequests := [][]byte{}
	proverTrieLeaveRequests := [][]byte{}

	for i, output := range app.TokenOutputs.Outputs {
		switch o := output.Output.(type) {
		case *protobufs.TokenOutput_Coin:
			address, err := GetAddressOfCoin(o.Coin, frame.FrameNumber, uint64(i))
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			err = e.coinStore.PutCoin(
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
			coin, err := e.coinStore.GetCoinByAddress(txn, o.DeletedCoin.Address)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			err = e.coinStore.DeleteCoin(
				txn,
				o.DeletedCoin.Address,
				coin,
			)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_Proof:
			address, err := GetAddressOfPreCoinProof(o.Proof)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			err = e.coinStore.PutPreCoinProof(
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
				if _, ok := (*e.peerSeniority)[addr]; !ok {
					(*e.peerSeniority)[addr] = PeerSeniorityItem{
						seniority: 10,
						addr:      addr,
					}
				} else {
					(*e.peerSeniority)[addr] = PeerSeniorityItem{
						seniority: (*e.peerSeniority)[addr].seniority + 10,
						addr:      addr,
					}
				}
			}
		case *protobufs.TokenOutput_DeletedProof:
			address, err := GetAddressOfPreCoinProof(o.DeletedProof)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			err = e.coinStore.DeletePreCoinProof(
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
				peerId, err := e.getPeerIdFromSignature(sig)
				if err != nil {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				peerIds = append(peerIds, peerId.String())
			}

			logger := e.logger.Debug
			if peerIds[0] == peer.ID(e.pubSub.GetPeerID()).String() {
				logger = e.logger.Info
			}
			mergeable := true
			for i, peerId := range peerIds {
				addr, err := e.getAddressFromSignature(
					o.Announce.PublicKeySignaturesEd448[i],
				)
				if err != nil {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				sen, ok := (*e.peerSeniority)[string(addr)]
				if !ok {
					logger(
						"peer announced with no seniority",
						zap.String("peer_id", peerId),
					)
					continue
				}

				peer := new(big.Int).SetUint64(sen.seniority)
				if peer.Cmp(GetAggregatedSeniority([]string{peerId})) != 0 {
					logger(
						"peer announced but has already been announced",
						zap.String("peer_id", peerId),
						zap.Uint64("seniority", sen.seniority),
					)
					mergeable = false
					break
				}
			}

			if mergeable {
				addr, err := e.getAddressFromSignature(
					o.Announce.PublicKeySignaturesEd448[0],
				)
				if err != nil {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				additional := uint64(0)
				_, prfs, err := e.coinStore.GetPreCoinProofsForOwner(addr)
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				aggregated := GetAggregatedSeniority(peerIds).Uint64()
				logger("peer has merge, aggregated seniority", zap.Uint64("seniority", aggregated))

				for _, pr := range prfs {
					if pr.IndexProof == nil && pr.Difficulty == 0 && pr.Commitment == nil {
						// approximate average per interval:
						add := new(big.Int).SetBytes(pr.Amount)
						add.Quo(add, big.NewInt(58800000))
						if add.Cmp(big.NewInt(4000000)) > 0 {
							add = big.NewInt(4000000)
						}
						additional = add.Uint64()
						logger("1.4.19-21 seniority", zap.Uint64("seniority", additional))
					}
				}

				total := aggregated + additional

				logger("combined aggregate and 1.4.19-21 seniority", zap.Uint64("seniority", total))

				(*e.peerSeniority)[string(addr)] = PeerSeniorityItem{
					seniority: aggregated + additional,
					addr:      string(addr),
				}

				for _, sig := range o.Announce.PublicKeySignaturesEd448[1:] {
					addr, err := e.getAddressFromSignature(
						sig,
					)
					if err != nil {
						txn.Abort()
						return nil, errors.Wrap(err, "process frame")
					}

					(*e.peerSeniority)[string(addr)] = PeerSeniorityItem{
						seniority: 0,
						addr:      string(addr),
					}
				}
			} else {
				addr, err := e.getAddressFromSignature(
					o.Announce.PublicKeySignaturesEd448[0],
				)
				if err != nil {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				sen, ok := (*e.peerSeniority)[string(addr)]
				if !ok {
					logger(
						"peer announced with no seniority",
						zap.String("peer_id", peerIds[0]),
					)
					continue
				}

				peer := new(big.Int).SetUint64(sen.seniority)
				if peer.Cmp(GetAggregatedSeniority([]string{peerIds[0]})) != 0 {
					logger(
						"peer announced but has already been announced",
						zap.String("peer_id", peerIds[0]),
						zap.Uint64("seniority", sen.seniority),
					)
					continue
				}

				additional := uint64(0)
				_, prfs, err := e.coinStore.GetPreCoinProofsForOwner(addr)
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					txn.Abort()
					return nil, errors.Wrap(err, "process frame")
				}

				aggregated := GetAggregatedSeniority(peerIds).Uint64()
				logger("peer does not have merge, pre-1.4.19 seniority", zap.Uint64("seniority", aggregated))

				for _, pr := range prfs {
					if pr.IndexProof == nil && pr.Difficulty == 0 && pr.Commitment == nil {
						// approximate average per interval:
						add := new(big.Int).SetBytes(pr.Amount)
						add.Quo(add, big.NewInt(58800000))
						if add.Cmp(big.NewInt(4000000)) > 0 {
							add = big.NewInt(4000000)
						}
						additional = add.Uint64()
						logger("1.4.19-21 seniority", zap.Uint64("seniority", additional))
					}
				}
				total := GetAggregatedSeniority([]string{peerIds[0]}).Uint64() + additional
				logger("combined aggregate and 1.4.19-21 seniority", zap.Uint64("seniority", total))
				(*e.peerSeniority)[string(addr)] = PeerSeniorityItem{
					seniority: total,
					addr:      string(addr),
				}
			}
		case *protobufs.TokenOutput_Join:
			addr, err := e.getAddressFromSignature(o.Join.PublicKeySignatureEd448)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}

			if _, ok := (*e.peerSeniority)[string(addr)]; !ok {
				(*e.peerSeniority)[string(addr)] = PeerSeniorityItem{
					seniority: 20,
					addr:      string(addr),
				}
			} else {
				(*e.peerSeniority)[string(addr)] = PeerSeniorityItem{
					seniority: (*e.peerSeniority)[string(addr)].seniority + 20,
					addr:      string(addr),
				}
			}
			proverTrieJoinRequests = append(proverTrieJoinRequests, addr)
		case *protobufs.TokenOutput_Leave:
			addr, err := e.getAddressFromSignature(o.Leave.PublicKeySignatureEd448)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
			proverTrieLeaveRequests = append(proverTrieLeaveRequests, addr)
		case *protobufs.TokenOutput_Pause:
			_, err := e.getAddressFromSignature(o.Pause.PublicKeySignatureEd448)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_Resume:
			_, err := e.getAddressFromSignature(o.Resume.PublicKeySignatureEd448)
			if err != nil {
				txn.Abort()
				return nil, errors.Wrap(err, "process frame")
			}
		case *protobufs.TokenOutput_Penalty:
			addr := string(o.Penalty.Account.GetImplicitAccount().Address)
			if _, ok := (*e.peerSeniority)[addr]; !ok {
				(*e.peerSeniority)[addr] = PeerSeniorityItem{
					seniority: 0,
					addr:      addr,
				}
				proverTrieLeaveRequests = append(proverTrieLeaveRequests, []byte(addr))
			} else {
				if (*e.peerSeniority)[addr].seniority > o.Penalty.Quantity {
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
					(*e.peerSeniority)[addr] = PeerSeniorityItem{
						seniority: (*e.peerSeniority)[addr].seniority - o.Penalty.Quantity,
						addr:      addr,
					}
				} else {
					(*e.peerSeniority)[addr] = PeerSeniorityItem{
						seniority: 0,
						addr:      addr,
					}
					proverTrieLeaveRequests = append(proverTrieLeaveRequests, []byte(addr))
				}
			}
		}
	}

	joinAddrs := tries.NewMinHeap[PeerSeniorityItem]()
	leaveAddrs := tries.NewMinHeap[PeerSeniorityItem]()
	for _, addr := range proverTrieJoinRequests {
		if _, ok := (*e.peerSeniority)[string(addr)]; !ok {
			joinAddrs.Push(PeerSeniorityItem{
				addr:      string(addr),
				seniority: 0,
			})
		} else {
			joinAddrs.Push((*e.peerSeniority)[string(addr)])
		}
	}
	for _, addr := range proverTrieLeaveRequests {
		if _, ok := (*e.peerSeniority)[string(addr)]; !ok {
			leaveAddrs.Push(PeerSeniorityItem{
				addr:      string(addr),
				seniority: 0,
			})
		} else {
			leaveAddrs.Push((*e.peerSeniority)[string(addr)])
		}
	}

	joinReqs := make([]PeerSeniorityItem, len(joinAddrs.All()))
	copy(joinReqs, joinAddrs.All())
	slices.Reverse(joinReqs)
	leaveReqs := make([]PeerSeniorityItem, len(leaveAddrs.All()))
	copy(leaveReqs, leaveAddrs.All())
	slices.Reverse(leaveReqs)

	ProcessJoinsAndLeaves(joinReqs, leaveReqs, app, e.peerSeniority, frame)

	err = e.clockStore.PutPeerSeniorityMap(
		txn,
		e.intrinsicFilter,
		ToSerializedMap(e.peerSeniority),
	)
	if err != nil {
		txn.Abort()
		return nil, errors.Wrap(err, "process frame")
	}

	err = e.coinStore.SetLatestFrameProcessed(txn, frame.FrameNumber)
	if err != nil {
		txn.Abort()
		return nil, errors.Wrap(err, "process frame")
	}

	if frame.FrameNumber == application.PROOF_FRAME_RING_RESET ||
		frame.FrameNumber == application.PROOF_FRAME_RING_RESET_2 ||
		frame.FrameNumber == application.PROOF_FRAME_RING_RESET_3 {
		e.logger.Info("performing ring reset")
		seniorityMap, err := RebuildPeerSeniority(e.pubSub.GetNetwork())
		if err != nil {
			return nil, errors.Wrap(err, "process frame")
		}
		e.peerSeniority = NewFromMap(seniorityMap)

		app.Tries = []*tries.RollingFrecencyCritbitTrie{
			app.Tries[0],
		}

		err = e.clockStore.PutPeerSeniorityMap(
			txn,
			e.intrinsicFilter,
			ToSerializedMap(e.peerSeniority),
		)
		if err != nil {
			txn.Abort()
			return nil, errors.Wrap(err, "process frame")
		}
	}

	return app.Tries, nil
}

func ProcessJoinsAndLeaves(
	joinReqs []PeerSeniorityItem,
	leaveReqs []PeerSeniorityItem,
	app *application.TokenApplication,
	seniority *PeerSeniority,
	frame *protobufs.ClockFrame,
) {
	for _, addr := range joinReqs {
		rings := len(app.Tries)
		last := app.Tries[rings-1]
		set := last.FindNearestAndApproximateNeighbors(make([]byte, 32))
		if len(set) == 2048 || rings == 1 {
			app.Tries = append(
				app.Tries,
				&tries.RollingFrecencyCritbitTrie{},
			)
			last = app.Tries[rings]
		}
		if !last.Contains([]byte(addr.addr)) {
			last.Add([]byte(addr.addr), frame.FrameNumber)
		}
	}
	for _, addr := range leaveReqs {
		for _, t := range app.Tries[1:] {
			if t.Contains([]byte(addr.addr)) {
				t.Remove([]byte(addr.addr))
				break
			}
		}
	}

	if frame.FrameNumber > application.PROOF_FRAME_RING_RESET {
		if len(app.Tries) >= 2 {
			for _, t := range app.Tries[1:] {
				nodes := t.FindNearestAndApproximateNeighbors(make([]byte, 32))
				for _, n := range nodes {
					if n.LatestFrame < frame.FrameNumber-1000 {
						t.Remove(n.Key)
					}
				}
			}
		}
	}

	if len(app.Tries) > 2 {
		for i, t := range app.Tries[2:] {
			setSize := len(app.Tries[1+i].FindNearestAndApproximateNeighbors(make([]byte, 32)))
			if setSize < 2048 {
				nextSet := t.FindNearestAndApproximateNeighbors(make([]byte, 32))
				eligibilityOrder := tries.NewMinHeap[PeerSeniorityItem]()
				for _, n := range nextSet {
					eligibilityOrder.Push((*seniority)[string(n.Key)])
				}
				process := eligibilityOrder.All()
				slices.Reverse(process)
				for s := 0; s < len(process) && s+setSize < 2048; s++ {
					app.Tries[1+i].Add([]byte(process[s].addr), frame.FrameNumber)
					app.Tries[2+i].Remove([]byte(process[s].addr))
				}
			}
		}
	}
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
	triesAtFrame []*tries.RollingFrecencyCritbitTrie,
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
						e.clockStore,
						e.pubSub,
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
						triesAtFrame,
						e.coinStore,
						e.clockStore,
						e.pubSub,
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

func (e *TokenExecutionEngine) GetSeniority() *big.Int {
	altAddr, err := poseidon.HashBytes(e.pubSub.GetPeerID())
	if err != nil {
		return nil
	}

	sen, ok := (*e.peerSeniority)[string(
		altAddr.FillBytes(make([]byte, 32)),
	)]

	if !ok {
		return big.NewInt(0)
	}

	return new(big.Int).SetUint64(sen.Priority())
}

func GetAggregatedSeniority(peerIds []string) *big.Int {
	highestFirst := uint64(0)
	highestSecond := uint64(0)
	highestThird := uint64(0)
	highestFourth := uint64(0)

	for _, f := range firstRetro {
		found := false
		for _, p := range peerIds {
			if p != f.PeerId {
				continue
			}
			found = true
		}
		if !found {
			continue
		}
		// these don't have decimals so we can shortcut
		max := 157208
		actual, err := strconv.Atoi(f.Reward)
		if err != nil {
			panic(err)
		}

		s := uint64(10 * 6 * 60 * 24 * 92 / (max / actual))
		if s > uint64(highestFirst) {
			highestFirst = s
		}
	}

	for _, f := range secondRetro {
		found := false
		for _, p := range peerIds {
			if p != f.PeerId {
				continue
			}
			found = true
		}
		if !found {
			continue
		}

		amt := uint64(0)
		if f.JanPresence {
			amt += (10 * 6 * 60 * 24 * 31)
		}

		if f.FebPresence {
			amt += (10 * 6 * 60 * 24 * 29)
		}

		if f.MarPresence {
			amt += (10 * 6 * 60 * 24 * 31)
		}

		if f.AprPresence {
			amt += (10 * 6 * 60 * 24 * 30)
		}

		if f.MayPresence {
			amt += (10 * 6 * 60 * 24 * 31)
		}

		if amt > uint64(highestSecond) {
			highestSecond = amt
		}
	}

	for _, f := range thirdRetro {
		found := false
		for _, p := range peerIds {
			if p != f.PeerId {
				continue
			}
			found = true
		}
		if !found {
			continue
		}

		s := uint64(10 * 6 * 60 * 24 * 30)
		if s > uint64(highestThird) {
			highestThird = s
		}
	}

	for _, f := range fourthRetro {
		found := false
		for _, p := range peerIds {
			if p != f.PeerId {
				continue
			}
			found = true
		}
		if !found {
			continue
		}

		s := uint64(10 * 6 * 60 * 24 * 31)
		if s > uint64(highestFourth) {
			highestFourth = s
		}
	}
	return new(big.Int).SetUint64(
		highestFirst + highestSecond + highestThird + highestFourth,
	)
}

func (e *TokenExecutionEngine) AnnounceProverMerge() *protobufs.AnnounceProverRequest {
	currentHead := e.GetFrame()
	if currentHead == nil ||
		currentHead.FrameNumber < application.PROOF_FRAME_CUTOFF {
		return nil
	}
	keys := [][]byte{}
	ksigs := [][]byte{}
	if len(e.engineConfig.MultisigProverEnrollmentPaths) != 0 &&
		e.GetSeniority().Cmp(GetAggregatedSeniority(
			[]string{peer.ID(e.pubSub.GetPeerID()).String()},
		)) == 0 {
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

	announce := &protobufs.AnnounceProverRequest{
		PublicKeySignaturesEd448: []*protobufs.Ed448Signature{},
	}

	announce.PublicKeySignaturesEd448 = append(
		announce.PublicKeySignaturesEd448,
		&protobufs.Ed448Signature{
			PublicKey: &protobufs.Ed448PublicKey{
				KeyValue: e.pubSub.GetPublicKey(),
			},
			Signature: mainsig,
		},
	)

	for i := range keys {
		announce.PublicKeySignaturesEd448 = append(
			announce.PublicKeySignaturesEd448,
			&protobufs.Ed448Signature{
				PublicKey: &protobufs.Ed448PublicKey{
					KeyValue: keys[i],
				},
				Signature: ksigs[i],
			},
		)
	}

	return announce
}

func (e *TokenExecutionEngine) AnnounceProverJoin() {
	msg := []byte("join")
	head := e.GetFrame()
	if head == nil ||
		head.FrameNumber < application.PROOF_FRAME_CUTOFF {
		return
	}
	msg = binary.BigEndian.AppendUint64(msg, head.FrameNumber)
	msg = append(msg, bytes.Repeat([]byte{0xff}, 32)...)
	sig, err := e.pubSub.SignMessage(msg)
	if err != nil {
		panic(err)
	}

	e.publishMessage(
		append([]byte{0x00}, e.intrinsicFilter...),
		&protobufs.TokenRequest{
			Request: &protobufs.TokenRequest_Join{
				Join: &protobufs.AnnounceProverJoin{
					Filter:      bytes.Repeat([]byte{0xff}, 32),
					FrameNumber: head.FrameNumber,
					PublicKeySignatureEd448: &protobufs.Ed448Signature{
						Signature: sig,
						PublicKey: &protobufs.Ed448PublicKey{
							KeyValue: e.pubSub.GetPublicKey(),
						},
					},
					Announce: e.AnnounceProverMerge(),
				},
			},
			Timestamp: gotime.Now().UnixMilli(),
		},
	)
}

func (e *TokenExecutionEngine) GetRingPosition() int {
	altAddr, err := poseidon.HashBytes(e.pubSub.GetPeerID())
	if err != nil {
		return -1
	}

	tries := e.clock.GetFrameProverTries()
	if len(tries) <= 1 {
		return -1
	}

	for i, trie := range tries[1:] {
		if trie.Contains(altAddr.FillBytes(make([]byte, 32))) {
			return i
		}
	}

	return -1
}

func (e *TokenExecutionEngine) getPeerIdFromSignature(
	sig *protobufs.Ed448Signature,
) (peer.ID, error) {
	if sig.PublicKey == nil || sig.PublicKey.KeyValue == nil {
		return "", errors.New("invalid data")
	}

	pk, err := pcrypto.UnmarshalEd448PublicKey(
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

func (e *TokenExecutionEngine) getAddressFromSignature(
	sig *protobufs.Ed448Signature,
) ([]byte, error) {
	if sig.PublicKey == nil || sig.PublicKey.KeyValue == nil {
		return nil, errors.New("invalid data")
	}

	pk, err := pcrypto.UnmarshalEd448PublicKey(
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
