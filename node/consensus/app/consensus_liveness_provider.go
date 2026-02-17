package app

import (
	"context"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	keyedaggregator "source.quilibrium.com/quilibrium/monorepo/node/keyedaggregator"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// AppLivenessProvider implements LivenessProvider
type AppLivenessProvider struct {
	engine *AppConsensusEngine
}

func (p *AppLivenessProvider) Collect(
	ctx context.Context,
	frameNumber uint64,
	rank uint64,
) (CollectedCommitments, error) {
	if p.engine.GetFrame() == nil {
		return CollectedCommitments{}, errors.Wrap(
			errors.New("no frame found"),
			"collect",
		)
	}

	mixnetMessages := []*protobufs.Message{}
	currentSet, _ := p.engine.proverRegistry.GetActiveProvers(p.engine.appAddress)
	if len(currentSet) >= 9 {
		// Prepare mixnet for collecting messages
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

	var collectorRecords []*sequencedAppMessage
	var collector keyedaggregator.Collector[sequencedAppMessage]
	alreadyCollected := false
	if p.engine.messageCollectors != nil {
		var err error
		var found bool
		collector, found, err = p.engine.getAppMessageCollector(rank)
		if err != nil && errors.Is(err, keyedaggregator.ErrSequenceBelowRetention) {
			// Collector was already pruned by a prior Collect call for this
			// rank. We must not overwrite collectedMessages with an empty
			// slice or the previously-collected messages will be lost.
			alreadyCollected = true
		} else if err != nil {
			p.engine.logger.Warn(
				"could not fetch collector for rank",
				zap.Uint64("rank", rank),
				zap.Error(err),
			)
		} else if found {
			collectorRecords = collector.Records()
		}
	}

	txMap := map[string][][]byte{}
	finalizedMessages := make(
		[]*protobufs.Message,
		0,
		len(collectorRecords)+len(mixnetMessages),
	)

	for _, record := range collectorRecords {
		if record == nil || record.message == nil {
			continue
		}
		lockedAddrs, err := p.engine.executionManager.Lock(
			record.frameNumber,
			record.message.Address,
			record.message.Payload,
		)
		if err != nil {
			p.engine.logger.Debug(
				"message failed lock",
				zap.Uint64("rank", rank),
				zap.Error(err),
			)
			if collector != nil {
				collector.Remove(record)
			}
			continue
		}

		txMap[string(record.message.Hash)] = lockedAddrs
		finalizedMessages = append(finalizedMessages, record.message)
	}

	for i, message := range mixnetMessages {
		lockedAddrs, err := p.validateAndLockMessage(frameNumber, i, message)
		if err != nil {
			continue
		}

		txMap[string(message.Hash)] = lockedAddrs
		finalizedMessages = append(finalizedMessages, message)
	}

	err := p.engine.executionManager.Unlock()
	if err != nil {
		p.engine.logger.Error("could not unlock", zap.Error(err))
	}

	p.engine.logger.Info(
		"collected messages",
		zap.Int(
			"total_message_count",
			len(mixnetMessages)+len(collectorRecords),
		),
		zap.Int("valid_message_count", len(finalizedMessages)),
		zap.Uint64(
			"current_frame",
			p.engine.GetFrame().GetRank(),
		),
	)
	transactionsCollectedTotal.WithLabelValues(p.engine.appAddressHex).Add(
		float64(len(finalizedMessages)),
	)

	// Calculate commitment root
	commitment, err := p.engine.calculateRequestsRoot(finalizedMessages, txMap)
	if err != nil {
		return CollectedCommitments{}, errors.Wrap(err, "collect")
	}

	if p.engine.messageAggregator != nil {
		p.engine.messageAggregator.OnSequenceChange(rank, rank+1)
	}
	pendingMessagesCount.WithLabelValues(p.engine.appAddressHex).Set(0)

	// If we already collected for this rank (collector was pruned) and found no
	// new messages, preserve the previously-collected messages rather than
	// overwriting them with an empty slice.
	if !alreadyCollected || len(finalizedMessages) > 0 {
		p.engine.collectedMessagesMu.Lock()
		p.engine.collectedMessages = finalizedMessages
		p.engine.collectedMessagesMu.Unlock()
	}

	return CollectedCommitments{
		frameNumber:    frameNumber,
		commitmentHash: commitment,
		prover:         p.engine.getProverAddress(),
	}, nil
}

func (p *AppLivenessProvider) validateAndLockMessage(
	frameNumber uint64,
	i int,
	message *protobufs.Message,
) (lockedAddrs [][]byte, err error) {
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
		return nil, err
	}

	lockedAddrs, err = p.engine.executionManager.Lock(
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
		return nil, err
	}

	return lockedAddrs, nil
}
