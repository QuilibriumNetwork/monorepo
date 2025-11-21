package global

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"golang.org/x/crypto/sha3"

	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/lifecycle"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/tracing"
	keyedaggregator "source.quilibrium.com/quilibrium/monorepo/node/keyedaggregator"
	keyedcollector "source.quilibrium.com/quilibrium/monorepo/node/keyedcollector"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

const maxGlobalMessagesPerFrame = 100

var globalMessageAddress = bytes.Repeat([]byte{0xff}, 32)

type sequencedGlobalMessage struct {
	sequence uint64
	identity models.Identity
	payload  []byte
	message  *protobufs.Message
}

func newSequencedGlobalMessage(
	sequence uint64,
	payload []byte,
) *sequencedGlobalMessage {
	copyPayload := slices.Clone(payload)
	hash := sha3.Sum256(copyPayload)
	return &sequencedGlobalMessage{
		sequence: sequence,
		identity: models.Identity(string(hash[:])),
		payload:  copyPayload,
	}
}

var globalMessageTraits = keyedcollector.RecordTraits[sequencedGlobalMessage]{
	Sequence: func(m *sequencedGlobalMessage) uint64 {
		if m == nil {
			return 0
		}
		return m.sequence
	},
	Identity: func(m *sequencedGlobalMessage) models.Identity {
		if m == nil {
			return ""
		}
		return m.identity
	},
	Equals: func(a, b *sequencedGlobalMessage) bool {
		if a == nil || b == nil {
			return a == b
		}
		return slices.Equal(a.payload, b.payload)
	},
}

type globalMessageProcessorFactory struct {
	engine *GlobalConsensusEngine
}

func (f *globalMessageProcessorFactory) Create(
	sequence uint64,
) (keyedcollector.Processor[sequencedGlobalMessage], error) {
	return &globalMessageProcessor{
		engine:   f.engine,
		sequence: sequence,
	}, nil
}

type globalMessageProcessor struct {
	engine   *GlobalConsensusEngine
	sequence uint64
}

func (p *globalMessageProcessor) Process(
	record *sequencedGlobalMessage,
) error {
	if record == nil {
		return keyedcollector.NewInvalidRecordError(
			record,
			errors.New("nil global message"),
		)
	}

	if len(record.payload) < 4 {
		return keyedcollector.NewInvalidRecordError(
			record,
			errors.New("global message payload too short"),
		)
	}

	typePrefix := binary.BigEndian.Uint32(record.payload[:4])
	if typePrefix != protobufs.MessageBundleType {
		return keyedcollector.NewInvalidRecordError(
			record,
			fmt.Errorf("unexpected message type: %d", typePrefix),
		)
	}

	message := &protobufs.Message{
		Address: globalMessageAddress,
		Payload: record.payload,
	}

	if err := p.enforceCollectorLimit(record); err != nil {
		return err
	}

	qc, err := p.engine.clockStore.GetQuorumCertificate(nil, record.sequence-1)
	if err != nil {
		qc, err = p.engine.clockStore.GetLatestQuorumCertificate(nil)
	}
	if err != nil {
		return keyedcollector.NewInvalidRecordError(record, err)
	}

	if err := p.engine.executionManager.ValidateMessage(
		qc.FrameNumber+1,
		message.Address,
		message.Payload,
	); err != nil {
		return keyedcollector.NewInvalidRecordError(record, err)
	}

	record.message = message
	return nil
}

func (p *globalMessageProcessor) enforceCollectorLimit(
	record *sequencedGlobalMessage,
) error {
	collector, found, err := p.engine.getMessageCollector(p.sequence)
	if err != nil || !found {
		return nil
	}

	if len(collector.Records()) >= maxGlobalMessagesPerFrame {
		collector.Remove(record)
		return keyedcollector.NewInvalidRecordError(
			record,
			fmt.Errorf("message limit reached for frame %d", p.sequence),
		)
	}

	return nil
}

func (e *GlobalConsensusEngine) initGlobalMessageAggregator() error {
	tracer := tracing.NewZapTracer(e.logger.Named("global_message_collector"))
	processorFactory := &globalMessageProcessorFactory{engine: e}
	collectorFactory, err := keyedcollector.NewFactory(
		tracer,
		globalMessageTraits,
		nil,
		processorFactory,
	)
	if err != nil {
		return fmt.Errorf("global message collector factory: %w", err)
	}

	e.messageCollectors = keyedaggregator.NewSequencedCollectors[sequencedGlobalMessage](
		tracer,
		0,
		collectorFactory,
	)

	aggregator, err := keyedaggregator.NewSequencedAggregator[sequencedGlobalMessage](
		tracer,
		0,
		e.messageCollectors,
		func(m *sequencedGlobalMessage) uint64 {
			if m == nil {
				return 0
			}
			return m.sequence
		},
	)
	if err != nil {
		return fmt.Errorf("global message aggregator: %w", err)
	}

	e.messageAggregator = aggregator
	return nil
}

func (e *GlobalConsensusEngine) startGlobalMessageAggregator(
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

func (e *GlobalConsensusEngine) addGlobalMessage(data []byte) {
	if e.messageAggregator == nil {
		return
	}
	record := newSequencedGlobalMessage(e.currentRank+1, data)
	e.messageAggregator.Add(record)
}

func (e *GlobalConsensusEngine) getMessageCollector(
	rank uint64,
) (keyedaggregator.Collector[sequencedGlobalMessage], bool, error) {
	if e.messageCollectors == nil {
		return nil, false, nil
	}
	return e.messageCollectors.GetCollector(rank)
}
