package global

import (
	"bytes"
	"context"
	"math/big"
	"slices"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// GlobalLivenessProvider implements LivenessProvider
type GlobalLivenessProvider struct {
	engine *GlobalConsensusEngine
}

func (p *GlobalLivenessProvider) Collect(
	ctx context.Context,
) (GlobalCollectedCommitments, error) {
	timer := prometheus.NewTimer(shardCommitmentCollectionDuration)
	defer timer.ObserveDuration()

	mixnetMessages := []*protobufs.Message{}
	currentSet, _ := p.engine.proverRegistry.GetActiveProvers(nil)
	if len(currentSet) >= 9 {
		err := p.engine.mixnet.PrepareMixnet()
		if err != nil {
			p.engine.logger.Error(
				"error preparing mixnet",
				zap.Error(err),
			)
		}

		// Get messages from mixnet
		mixnetMessages = p.engine.mixnet.GetMessages()
	}

	// Get and clear pending prover messages
	p.engine.pendingMessagesMu.Lock()
	pendingMessages := p.engine.pendingMessages
	p.engine.pendingMessages = [][]byte{}
	p.engine.pendingMessagesMu.Unlock()

	// Convert pending messages to protobuf.Message format
	globalAddress := make([]byte, 32)
	for i := range globalAddress {
		globalAddress[i] = 0xff
	}

	messages := make(
		[]*protobufs.Message,
		0,
		len(mixnetMessages)+len(pendingMessages),
	)
	messages = append(messages, mixnetMessages...)

	for _, msgData := range pendingMessages {
		messages = append(messages, &protobufs.Message{
			Address: globalAddress,
			Payload: msgData,
		})
	}

	acceptedMessages := []*protobufs.Message{}

	frameNumber := uint64(0)
	currentFrame, _ := p.engine.globalTimeReel.GetHead()
	if currentFrame != nil && currentFrame.Header != nil {
		frameNumber = currentFrame.Header.FrameNumber
	}

	frameNumber++

	p.engine.logger.Debug(
		"collected messages, validating",
		zap.Int("message_count", len(messages)),
	)

	for i, message := range messages {
		err := p.validateAndLockMessage(frameNumber, i, message)
		if err != nil {
			continue
		}

		acceptedMessages = append(acceptedMessages, message)
	}

	err := p.engine.executionManager.Unlock()
	if err != nil {
		p.engine.logger.Error(
			"unable to unlock",
			zap.Error(err),
		)
	}

	commitments := make([]*tries.VectorCommitmentTree, 256)
	for i := range 256 {
		commitments[i] = &tries.VectorCommitmentTree{}
	}

	proverRoot := make([]byte, 64)

	// TODO(2.1.1+): Refactor this with caching
	commitSet, err := p.engine.hypergraph.Commit(frameNumber)
	if err != nil {
		p.engine.logger.Error(
			"could not commit",
			zap.Error(err),
		)
		return GlobalCollectedCommitments{}, errors.Wrap(err, "collect")
	}
	collected := 0

	// The poseidon hash's field is < 0x3fff...ffff, so we use the upper two bits
	// to fold the four hypergraph phase/sets into the three different tree
	// partitions the L1 key designates
	for sk, s := range commitSet {
		if !bytes.Equal(sk.L1[:], []byte{0x00, 0x00, 0x00}) {
			collected++

			for phaseSet := 0; phaseSet < 4; phaseSet++ {
				commit := s[phaseSet]
				foldedShardKey := make([]byte, 32)
				copy(foldedShardKey, sk.L2[:])

				// 0 -> 0b00 -> 0b00000000 -> 0x00
				// 1 -> 0b01 -> 0b01000000 -> 0x40
				// 2 -> 0b10 -> 0b10000000 -> 0x80
				// 3 -> 0b11 -> 0b11000000 -> 0xC0
				foldedShardKey[0] |= byte(phaseSet << 6)
				for l1Idx := 0; l1Idx < 3; l1Idx++ {
					err := commitments[sk.L1[l1Idx]].Insert(
						foldedShardKey,
						commit,
						nil,
						big.NewInt(int64(len(commit))),
					)
					if err != nil {
						return GlobalCollectedCommitments{}, errors.Wrap(err, "collect")
					}
				}
			}
		} else {
			// Prover set is strictly vertex adds, so we simply take the first.
			proverRoot = s[0]
		}
	}

	shardCommitments := make([][]byte, 256)

	for i := 0; i < 256; i++ {
		shardCommitments[i] = commitments[i].Commit(p.engine.inclusionProver, false)
	}

	preimage := slices.Concat(
		slices.Concat(shardCommitments...),
		proverRoot,
	)

	commitmentHash := sha3.Sum256(preimage)

	p.engine.shardCommitments = shardCommitments
	p.engine.proverRoot = proverRoot
	p.engine.commitmentHash = commitmentHash[:]

	// Store the accepted messages as canonical bytes for inclusion in the frame
	collectedMsgs := make([][]byte, 0, len(acceptedMessages))
	for _, msg := range acceptedMessages {
		collectedMsgs = append(collectedMsgs, msg.Payload)
	}
	p.engine.collectedMessages = collectedMsgs

	// Update metrics
	shardCommitmentsCollected.Set(float64(collected))

	return GlobalCollectedCommitments{
		frameNumber:    frameNumber,
		commitmentHash: commitmentHash[:],
		prover:         p.engine.getProverAddress(),
	}, nil
}

func (p *GlobalLivenessProvider) SendLiveness(
	prior **protobufs.GlobalFrame,
	collected GlobalCollectedCommitments,
	ctx context.Context,
) error {
	// Get prover key
	signer, _, publicKey, _ := p.engine.GetProvingKey(p.engine.config.Engine)
	if publicKey == nil {
		return errors.Wrap(
			errors.New("no proving key available for liveness check"),
			"send liveness",
		)
	}

	// Create liveness check message
	livenessCheck := &protobufs.ProverLivenessCheck{
		FrameNumber:    collected.frameNumber,
		Timestamp:      time.Now().UnixMilli(),
		CommitmentHash: collected.commitmentHash,
	}

	// Sign the message
	signatureData, err := livenessCheck.ConstructSignaturePayload()
	if err != nil {
		return errors.Wrap(err, "send liveness")
	}

	sig, err := signer.SignWithDomain(
		signatureData,
		livenessCheck.GetSignatureDomain(),
	)
	if err != nil {
		return errors.Wrap(err, "send liveness")
	}

	proverAddress := p.engine.getAddressFromPublicKey(publicKey)
	livenessCheck.PublicKeySignatureBls48581 = &protobufs.BLS48581AddressedSignature{
		Address:   proverAddress,
		Signature: sig,
	}

	data, err := livenessCheck.ToCanonicalBytes()
	if err != nil {
		return errors.Wrap(err, "send liveness")
	}

	if err := p.engine.pubsub.PublishToBitmask(
		GLOBAL_CONSENSUS_BITMASK,
		data,
	); err != nil {
		p.engine.logger.Error("could not publish", zap.Error(err))
		return errors.Wrap(err, "send liveness")
	}

	p.engine.logger.Info(
		"sent liveness check",
		zap.Uint64("frame_number", collected.frameNumber),
	)

	return nil
}

func (p *GlobalLivenessProvider) validateAndLockMessage(
	frameNumber uint64,
	i int,
	message *protobufs.Message,
) (err error) {
	defer func() {
		if r := recover(); r != nil {
			p.engine.logger.Error(
				"panic recovered from message",
				zap.Any("panic", r),
				zap.Stack("stacktrace"),
			)
			err = errors.New("panicked processing message")
		}
	}()

	err = p.engine.executionManager.ValidateMessage(
		frameNumber,
		message.Address,
		message.Payload,
	)
	if err != nil {
		p.engine.logger.Debug(
			"invalid message",
			zap.Int("message_index", i),
			zap.Error(err),
		)
		return err
	}

	_, err = p.engine.executionManager.Lock(
		frameNumber,
		message.Address,
		message.Payload,
	)
	if err != nil {
		p.engine.logger.Debug(
			"message failed lock",
			zap.Int("message_index", i),
			zap.Error(err),
		)
		return err
	}

	return nil
}
