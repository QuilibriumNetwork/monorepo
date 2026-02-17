package global

import (
	"context"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	keyedaggregator "source.quilibrium.com/quilibrium/monorepo/node/keyedaggregator"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

// GlobalLivenessProvider implements LivenessProvider
type GlobalLivenessProvider struct {
	engine *GlobalConsensusEngine
}

func (p *GlobalLivenessProvider) Collect(
	ctx context.Context,
	frameNumber uint64,
	rank uint64,
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

	var collector keyedaggregator.Collector[sequencedGlobalMessage]
	var collectorRecords []*sequencedGlobalMessage
	alreadyCollected := false
	if p.engine.messageCollectors != nil {
		var err error
		var found bool
		collector, found, err = p.engine.getMessageCollector(rank)
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
		p.engine.logger.Debug(
			"collector lookup for rank",
			zap.Uint64("rank", rank),
			zap.Uint64("frame_number", frameNumber),
			zap.Bool("found", found),
			zap.Bool("already_collected", alreadyCollected),
			zap.Int("records", len(collectorRecords)),
			zap.Uint64("current_rank", p.engine.currentRank),
		)
	}

	acceptedMessages := make(
		[]*protobufs.Message,
		0,
		len(collectorRecords)+len(mixnetMessages),
	)

	if collector != nil {
		nilMsgCount := 0
		for _, record := range collectorRecords {
			if record == nil || record.message == nil {
				nilMsgCount++
				continue
			}
			if err := p.lockCollectorMessage(
				frameNumber,
				record.message,
			); err != nil {
				p.engine.logger.Debug(
					"message failed lock",
					zap.Uint64("frame_number", frameNumber),
					zap.Error(err),
				)
				collector.Remove(record)
				continue
			}
			acceptedMessages = append(acceptedMessages, record.message)
		}
		if nilMsgCount > 0 {
			p.engine.logger.Debug(
				"collector records with nil message (failed validation)",
				zap.Int("nil_msg_count", nilMsgCount),
				zap.Int("total_records", len(collectorRecords)),
			)
		}
	}

	messages := append([]*protobufs.Message{}, mixnetMessages...)

	p.engine.logger.Debug(
		"collected messages, validating",
		zap.Int("message_count", len(messages)+len(collectorRecords)),
	)

	for i, message := range messages {
		err := p.validateAndLockMessage(frameNumber, i, message)
		if err != nil {
			continue
		}

		acceptedMessages = append(acceptedMessages, message)
	}

	if p.engine.messageAggregator != nil {
		p.engine.messageAggregator.OnSequenceChange(rank, rank+1)
	}

	err := p.engine.executionManager.Unlock()
	if err != nil {
		p.engine.logger.Error(
			"unable to unlock",
			zap.Error(err),
		)
	}

	commitmentHash, err := p.engine.rebuildShardCommitments(frameNumber, rank)
	if err != nil {
		return GlobalCollectedCommitments{}, errors.Wrap(err, "collect")
	}

	// Store the accepted messages as canonical bytes for inclusion in the frame.
	// If we already collected for this rank (collector was pruned) and found no
	// new messages, preserve the previously-collected messages rather than
	// overwriting them with an empty slice.
	if !alreadyCollected || len(acceptedMessages) > 0 {
		collectedMsgs := make([][]byte, 0, len(acceptedMessages))
		for _, msg := range acceptedMessages {
			collectedMsgs = append(collectedMsgs, msg.Payload)
		}
		p.engine.collectedMessages = collectedMsgs
	}

	return GlobalCollectedCommitments{
		frameNumber:    frameNumber,
		commitmentHash: commitmentHash,
		prover:         p.engine.getProverAddress(),
	}, nil
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

func (p *GlobalLivenessProvider) lockCollectorMessage(
	frameNumber uint64,
	message *protobufs.Message,
) error {
	if message == nil {
		return errors.New("nil message")
	}
	_, err := p.engine.executionManager.Lock(
		frameNumber,
		message.Address,
		message.Payload,
	)
	return err
}
