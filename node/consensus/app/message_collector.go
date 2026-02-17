package app

import (
	"fmt"

	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"

	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/tracing"
	keyedaggregator "source.quilibrium.com/quilibrium/monorepo/node/keyedaggregator"
	keyedcollector "source.quilibrium.com/quilibrium/monorepo/node/keyedcollector"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

const maxAppMessagesPerRank = 100

type sequencedAppMessage struct {
	rank        uint64
	frameNumber uint64
	identity    models.Identity
	message     *protobufs.Message
}

func newSequencedAppMessage(
	rank uint64,
	message *protobufs.Message,
) *sequencedAppMessage {
	if message == nil {
		return nil
	}
	cloned := proto.Clone(message).(*protobufs.Message)
	return &sequencedAppMessage{
		rank:     rank,
		identity: models.Identity(string(cloned.Hash)),
		message:  cloned,
	}
}

var appMessageTraits = keyedcollector.RecordTraits[sequencedAppMessage]{
	Sequence: func(m *sequencedAppMessage) uint64 {
		if m == nil {
			return 0
		}
		return m.rank
	},
	Identity: func(m *sequencedAppMessage) models.Identity {
		if m == nil {
			return ""
		}
		return m.identity
	},
	Equals: func(a, b *sequencedAppMessage) bool {
		if a == nil || b == nil {
			return a == b
		}
		return string(a.identity) == string(b.identity)
	},
}

type appMessageProcessorFactory struct {
	engine *AppConsensusEngine
}

func (f *appMessageProcessorFactory) Create(
	sequence uint64,
) (keyedcollector.Processor[sequencedAppMessage], error) {
	return &appMessageProcessor{
		engine: f.engine,
		rank:   sequence,
	}, nil
}

type appMessageProcessor struct {
	engine *AppConsensusEngine
	rank   uint64
}

func (p *appMessageProcessor) Process(
	record *sequencedAppMessage,
) error {
	if record == nil || record.message == nil {
		return keyedcollector.NewInvalidRecordError(
			record,
			fmt.Errorf("nil app message"),
		)
	}

	if err := p.enforceCollectorLimit(record); err != nil {
		return err
	}

	frameNumber, err := p.frameNumberForRank()
	if err != nil {
		return keyedcollector.NewInvalidRecordError(record, err)
	}

	if err := p.engine.executionManager.ValidateMessage(
		frameNumber,
		record.message.Address,
		record.message.Payload,
	); err != nil {
		return keyedcollector.NewInvalidRecordError(record, err)
	}

	record.frameNumber = frameNumber
	p.engine.updatePendingMessagesGauge(p.rank)

	return nil
}

func (p *appMessageProcessor) frameNumberForRank() (uint64, error) {
	rank := p.rank
	if rank == 0 {
		rank = 1
	}
	qc, err := p.engine.clockStore.GetQuorumCertificate(
		p.engine.appAddress,
		rank-1,
	)
	if err != nil {
		qc, err = p.engine.clockStore.GetLatestQuorumCertificate(
			p.engine.appAddress,
		)
		if err != nil {
			return 0, err
		}
	}

	return qc.GetFrameNumber() + 1, nil
}

func (p *appMessageProcessor) enforceCollectorLimit(
	record *sequencedAppMessage,
) error {
	collector, found, err := p.engine.getAppMessageCollector(p.rank)
	if err != nil || !found {
		return nil
	}

	if len(collector.Records()) >= maxAppMessagesPerRank {
		collector.Remove(record)
		p.engine.deferAppMessage(p.rank+1, record.message)
		return keyedcollector.NewInvalidRecordError(
			record,
			fmt.Errorf("message limit reached for rank %d", p.rank),
		)
	}

	return nil
}

func (e *AppConsensusEngine) initAppMessageAggregator() error {
	tracer := tracing.NewZapTracer(e.logger.Named("app_message_collector"))
	processorFactory := &appMessageProcessorFactory{engine: e}
	collectorFactory, err := keyedcollector.NewFactory(
		tracer,
		appMessageTraits,
		nil,
		processorFactory,
	)
	if err != nil {
		return err
	}

	e.messageCollectors = keyedaggregator.NewSequencedCollectors(
		tracer,
		0,
		collectorFactory,
	)

	aggregator, err := keyedaggregator.NewSequencedAggregator(
		tracer,
		0,
		e.messageCollectors,
		func(m *sequencedAppMessage) uint64 {
			if m == nil {
				return 0
			}
			return m.rank
		},
	)
	if err != nil {
		return err
	}

	e.messageAggregator = aggregator
	return nil
}

func (e *AppConsensusEngine) startAppMessageAggregator(
	ctx lifecycle.SignalerContext,
	ready lifecycle.ReadyFunc,
) {
	if e.messageAggregator == nil {
		ready()
		<-ctx.Done()
		return
	}

	go func() {
		if err := e.messageAggregator.ComponentManager.Start(ctx); err != nil {
			ctx.Throw(err)
		}
	}()

	<-e.messageAggregator.ComponentManager.Ready()
	ready()
	<-e.messageAggregator.ComponentManager.Done()
}

func (e *AppConsensusEngine) addAppMessage(message *protobufs.Message) {
	if e.messageCollectors == nil || message == nil {
		return
	}
	if len(message.Hash) == 0 {
		hash := sha3.Sum256(message.Payload)
		message.Hash = hash[:]
	}
	rank := e.nextRank()
	record := newSequencedAppMessage(rank, message)
	if record == nil {
		return
	}

	// Add directly to the collector synchronously rather than going through
	// the aggregator's async worker queue. The async path loses messages
	// because OnSequenceChange advances the retention window before workers
	// finish processing queued items, causing them to be silently pruned.
	collector, _, err := e.messageCollectors.GetOrCreateCollector(rank)
	if err != nil {
		e.logger.Debug(
			"could not get collector for app message",
			zap.Uint64("rank", rank),
			zap.Error(err),
		)
		return
	}

	if err := collector.Add(record); err != nil {
		e.logger.Debug(
			"could not add app message to collector",
			zap.Uint64("rank", rank),
			zap.Error(err),
		)
		return
	}
}

func (e *AppConsensusEngine) nextRank() uint64 {
	e.lastProposalRankMu.RLock()
	last := e.lastProposalRank
	e.lastProposalRankMu.RUnlock()
	if last > 0 {
		return last + 1
	}
	return e.currentRank + 1
}

func (e *AppConsensusEngine) getAppMessageCollector(
	rank uint64,
) (keyedaggregator.Collector[sequencedAppMessage], bool, error) {
	if e.messageCollectors == nil {
		return nil, false, nil
	}
	return e.messageCollectors.GetCollector(rank)
}

func (e *AppConsensusEngine) recordProposalRank(rank uint64) {
	if rank == 0 {
		return
	}
	e.lastProposalRankMu.Lock()
	if rank > e.lastProposalRank {
		e.lastProposalRank = rank
	}
	e.lastProposalRankMu.Unlock()
}

func (e *AppConsensusEngine) updatePendingMessagesGauge(rank uint64) {
	if e.messageCollectors == nil {
		return
	}
	collector, found, err := e.getAppMessageCollector(rank)
	if err != nil || !found {
		return
	}
	pendingMessagesCount.WithLabelValues(e.appAddressHex).Set(
		float64(len(collector.Records())),
	)
}

func (e *AppConsensusEngine) deferAppMessage(
	targetRank uint64,
	message *protobufs.Message,
) {
	if e == nil || message == nil || targetRank == 0 {
		return
	}

	cloned := proto.Clone(message).(*protobufs.Message)
	e.appSpilloverMu.Lock()
	e.appMessageSpillover[targetRank] = append(
		e.appMessageSpillover[targetRank],
		cloned,
	)
	pending := len(e.appMessageSpillover[targetRank])
	e.appSpilloverMu.Unlock()

	if e.logger != nil {
		e.logger.Debug(
			"deferred app message due to collector limit",
			zap.String("app_address", e.appAddressHex),
			zap.Uint64("target_rank", targetRank),
			zap.Int("pending", pending),
		)
	}
}

func (e *AppConsensusEngine) flushDeferredAppMessages(targetRank uint64) {
	if e == nil || e.messageCollectors == nil || targetRank == 0 {
		return
	}

	e.appSpilloverMu.Lock()
	messages := e.appMessageSpillover[targetRank]
	if len(messages) > 0 {
		delete(e.appMessageSpillover, targetRank)
	}
	e.appSpilloverMu.Unlock()

	if len(messages) == 0 {
		return
	}

	collector, _, err := e.messageCollectors.GetOrCreateCollector(targetRank)
	if err != nil {
		if e.logger != nil {
			e.logger.Debug(
				"could not get collector for deferred app messages",
				zap.String("app_address", e.appAddressHex),
				zap.Uint64("target_rank", targetRank),
				zap.Error(err),
			)
		}
		return
	}

	added := 0
	for _, msg := range messages {
		record := newSequencedAppMessage(targetRank, msg)
		if record == nil {
			continue
		}
		if err := collector.Add(record); err != nil {
			if e.logger != nil {
				e.logger.Debug(
					"could not add deferred app message to collector",
					zap.Uint64("target_rank", targetRank),
					zap.Error(err),
				)
			}
			continue
		}
		added++
	}

	if e.logger != nil {
		e.logger.Debug(
			"replayed deferred app messages",
			zap.String("app_address", e.appAddressHex),
			zap.Uint64("target_rank", targetRank),
			zap.Int("count", added),
		)
	}
}
