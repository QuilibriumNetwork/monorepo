package application

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"sync"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	qruntime "source.quilibrium.com/quilibrium/monorepo/node/internal/runtime"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

var ErrInvalidStateTransition = errors.New("invalid state transition")

var TOKEN_ADDRESS = []byte{
	// poseidon("q_mainnet_token")
	0x11, 0x55, 0x85, 0x84, 0xaf, 0x70, 0x17, 0xa9,
	0xbf, 0xd1, 0xff, 0x18, 0x64, 0x30, 0x2d, 0x64,
	0x3f, 0xbe, 0x58, 0xc6, 0x2d, 0xcf, 0x90, 0xcb,
	0xcd, 0x8f, 0xde, 0x74, 0xa2, 0x67, 0x94, 0xd9,
}

type TokenApplication struct {
	Beacon       []byte
	TokenOutputs *protobufs.TokenOutputs
	Tries        []*tries.RollingFrecencyCritbitTrie
	CoinStore    store.CoinStore
	ClockStore   store.ClockStore
	PubSub       p2p.PubSub
	Logger       *zap.Logger
	Difficulty   uint32
}

func GetOutputsFromClockFrame(
	frame *protobufs.ClockFrame,
) (
	*protobufs.TokenRequests,
	*protobufs.TokenOutputs,
	error,
) {
	var associatedProof []byte
	var tokenOutputs *protobufs.TokenOutputs
	if len(frame.AggregateProofs) > 0 {
		for _, proofs := range frame.AggregateProofs {
			for _, inclusion := range proofs.InclusionCommitments {
				if inclusion.TypeUrl == protobufs.IntrinsicExecutionOutputType {
					output := protobufs.IntrinsicExecutionOutput{}
					if err := proto.Unmarshal(inclusion.Data, &output); err != nil {
						return nil, nil, errors.Wrap(err, "get outputs from clock frame")
					}

					tokenOutputs = &protobufs.TokenOutputs{}
					if err := proto.Unmarshal(output.Output, tokenOutputs); err != nil {
						return nil, nil, errors.Wrap(err, "get outputs from clock frame")
					}

					associatedProof = output.Proof
				}
			}
		}
	}

	transition := &protobufs.TokenRequests{}
	if frame.FrameNumber != 0 {
		if err := proto.Unmarshal(associatedProof, transition); err != nil {
			return nil, nil, errors.Wrap(err, "get outputs from clock frame")
		}
	}

	return transition, tokenOutputs, nil
}

func MaterializeApplicationFromFrame(
	privKey crypto.Signer,
	frame *protobufs.ClockFrame,
	tries []*tries.RollingFrecencyCritbitTrie,
	coinStore store.CoinStore,
	clockStore store.ClockStore,
	pubSub p2p.PubSub,
	logger *zap.Logger,
) (*TokenApplication, error) {
	_, tokenOutputs, err := GetOutputsFromClockFrame(frame)
	if err != nil {
		return nil, errors.Wrap(err, "materialize application from frame")
	}

	genesis := config.GetGenesis()

	return &TokenApplication{
		Beacon:       genesis.Beacon,
		TokenOutputs: tokenOutputs,
		Tries:        tries,
		CoinStore:    coinStore,
		ClockStore:   clockStore,
		Logger:       logger,
		PubSub:       pubSub,
		Difficulty:   frame.Difficulty,
	}, nil
}

func (a *TokenApplication) ApplyTransitions(
	currentFrameNumber uint64,
	transitions *protobufs.TokenRequests,
	skipFailures bool,
) (
	*TokenApplication,
	*protobufs.TokenRequests,
	*protobufs.TokenRequests,
	error,
) {
	finalizedTransitions := &protobufs.TokenRequests{}
	failedTransitions := &protobufs.TokenRequests{}
	outputs := &protobufs.TokenOutputs{}
	lockMap := map[string]struct{}{}

	frame, _, err := a.ClockStore.GetDataClockFrame(
		p2p.GetBloomFilter(TOKEN_ADDRESS, 256, 3),
		currentFrameNumber-1,
		false,
	)
	if err != nil {
		return nil, nil, nil, errors.Wrap(
			ErrInvalidStateTransition,
			"apply transitions")
	}

	requests := []*protobufs.TokenRequest{}
	if skipFailures {
		mints := tries.NewMinHeap[*protobufs.TokenRequest]()
		for _, req := range transitions.Requests {
			mints.Push(req)
		}

		requests = mints.All()
	} else {
		requests = transitions.Requests
	}

	parallelismMap := map[int]uint64{}
	if len(a.Tries) > 1 {
		for i := range a.Tries[1:] {
			parallelismMap[i] = 0
		}
	}

	seen := map[string]struct{}{}

	set := make([]*protobufs.TokenRequest, len(requests))
	fails := make([]*protobufs.TokenRequest, len(set))
	outputsSet := make([][]*protobufs.TokenOutput, len(set))

	for i, transition := range requests {
		i := i
		switch t := transition.Request.(type) {
		case *protobufs.TokenRequest_Mint:
			if t == nil || t.Mint.Proofs == nil || t.Mint.Signature == nil {
				continue
			}

			payload := []byte("mint")
			for _, p := range t.Mint.Proofs {
				payload = append(payload, p...)
			}
			if err := t.Mint.Signature.Verify(payload); err != nil {
				continue
			}

			addr, err := poseidon.HashBytes(
				t.Mint.Signature.PublicKey.KeyValue,
			)
			if err != nil {
				continue
			}

			if len(t.Mint.Proofs) == 1 && a.Tries[0].Contains(
				addr.FillBytes(make([]byte, 32)),
			) && bytes.Equal(t.Mint.Signature.PublicKey.KeyValue, a.Beacon) {
				if _, ok := seen[string(t.Mint.Proofs[0][32:])]; !ok {
					set[i] = transition
					seen[string(t.Mint.Proofs[0][32:])] = struct{}{}
				}
			} else if len(t.Mint.Proofs) >= 3 && currentFrameNumber > PROOF_FRAME_CUTOFF {
				frameNumber := binary.BigEndian.Uint64(t.Mint.Proofs[2])
				if frameNumber < currentFrameNumber-2 {
					fails[i] = transition
					continue
				}
				ring, parallelism, err := t.Mint.RingAndParallelism(
					func(addr []byte) int {
						if _, ok := seen[string(addr)]; ok {
							return -1
						}

						ring := -1
						for i, t := range a.Tries[1:] {
							if t.Contains(addr) {
								ring = i
								seen[string(addr)] = struct{}{}
							}
						}

						return ring
					},
				)
				if err == nil {
					// fmt.Println(i, "checked ring test")
					set[i] = transition
					parallelismMap[ring] = parallelismMap[ring] + uint64(parallelism)
				} else {
					// fmt.Println(i, "failed ring test", err)
					fails[i] = transition
				}
			}
		default:
			set[i] = transition
		}
	}

	successes := make([]*protobufs.TokenRequest, len(set))
	for i, transition := range set {
		if transition == nil {
			continue
		}
	req:
		switch t := transition.Request.(type) {
		case *protobufs.TokenRequest_Announce:
			success, err := a.handleAnnounce(currentFrameNumber, lockMap, t.Announce)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						err,
						"apply transitions",
					)
				}
				failedTransitions.Requests = append(
					failedTransitions.Requests,
					transition,
				)
				break req
			}
			outputsSet[i] = success
			successes[i] = transition
		case *protobufs.TokenRequest_Join:
			success, err := a.handleDataAnnounceProverJoin(
				currentFrameNumber,
				lockMap,
				t.Join,
			)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						err,
						"apply transitions",
					)
				}
				fails[i] = transition
				break req
			}
			outputsSet[i] = success
			successes[i] = transition
		case *protobufs.TokenRequest_Leave:
			success, err := a.handleDataAnnounceProverLeave(
				currentFrameNumber,
				lockMap,
				t.Leave,
			)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						err,
						"apply transitions",
					)
				}
				fails[i] = transition
				break req
			}
			outputsSet[i] = success
			successes[i] = transition
		case *protobufs.TokenRequest_Resume:
			success, err := a.handleDataAnnounceProverResume(
				currentFrameNumber,
				lockMap,
				t.Resume,
			)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						err,
						"apply transitions",
					)
				}
				fails[i] = transition
				break req
			}
			outputsSet[i] = success
			successes[i] = transition
		case *protobufs.TokenRequest_Pause:
			success, err := a.handleDataAnnounceProverPause(
				currentFrameNumber,
				lockMap,
				t.Pause,
			)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						err,
						"apply transitions",
					)
				}
				fails[i] = transition
				break req
			}
			outputsSet[i] = success
			successes[i] = transition
		case *protobufs.TokenRequest_Merge:
			success, err := a.handleMerge(currentFrameNumber, lockMap, t.Merge)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						err,
						"apply transitions",
					)
				}
				fails[i] = transition
				break req
			}
			outputsSet[i] = success
			successes[i] = transition
		case *protobufs.TokenRequest_Split:
			success, err := a.handleSplit(currentFrameNumber, lockMap, t.Split)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						err,
						"apply transitions",
					)
				}
				fails[i] = transition
				break req
			}
			outputsSet[i] = success
			successes[i] = transition
		case *protobufs.TokenRequest_Transfer:
			success, err := a.handleTransfer(currentFrameNumber, lockMap, t.Transfer)
			if err != nil {
				if !skipFailures {
					return nil, nil, nil, errors.Wrap(
						err,
						"apply transitions",
					)
				}
				fails[i] = transition
				break req
			}
			outputsSet[i] = success
			successes[i] = transition
		}
	}

	wg := sync.WaitGroup{}
	throttle := make(chan struct{}, qruntime.WorkerCount(0, false))
	for i, transition := range set {
		if transition == nil {
			continue
		}
		i, transition := i, transition
		switch t := transition.Request.(type) {
		case *protobufs.TokenRequest_Mint:
			throttle <- struct{}{}
			wg.Add(1)
			go func() {
				defer func() { <-throttle }()
				defer wg.Done()
				success, err := a.handleMint(
					currentFrameNumber,
					t.Mint,
					frame,
					parallelismMap,
				)
				if err != nil {
					fails[i] = transition
					return
				}
				outputsSet[i] = success
				successes[i] = transition
			}()
		}
	}
	wg.Wait()

	finalFails := []*protobufs.TokenRequest{}
	for _, fail := range fails {
		if fail != nil {
			finalFails = append(finalFails, fail)
		}
	}
	if len(finalFails) != 0 && !skipFailures {
		return nil, nil, nil, errors.Wrap(
			err,
			"apply transitions",
		)
	}
	finalSuccesses := []*protobufs.TokenRequest{}
	for _, success := range successes {
		if success != nil {
			finalSuccesses = append(finalSuccesses, success)
		}
	}

	outputs.Outputs = []*protobufs.TokenOutput{}
	for _, out := range outputsSet {
		if out != nil {
			for _, o := range out {
				outputs.Outputs = append(outputs.Outputs, o)
			}
		}
	}

	a.TokenOutputs = outputs

	finalizedTransitions.Requests = finalSuccesses
	failedTransitions.Requests = finalFails

	return a, finalizedTransitions, failedTransitions, nil
}

func (a *TokenApplication) MaterializeStateFromApplication() (
	*protobufs.TokenOutputs,
	error,
) {
	return a.TokenOutputs, nil
}
