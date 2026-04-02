package global

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"go.uber.org/zap"
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
		// p.engine.deferGlobalMessage(record.sequence+1, record.payload)
		return keyedcollector.NewInvalidRecordError(
			record,
			fmt.Errorf("message limit reached for frame %d", p.sequence),
		)
	}

	return nil
}

func (e *GlobalConsensusEngine) initGlobalMessageAggregator() error {
	tracer := tracing.NewZapTracer(e.logger.Named("globalMessageCollector"))
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

	e.messageCollectors = keyedaggregator.NewSequencedCollectors(
		tracer,
		0,
		collectorFactory,
	)

	aggregator, err := keyedaggregator.NewSequencedAggregator(
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

func (e *GlobalConsensusEngine) addGlobalMessage(data []byte) error {
	if e.messageCollectors == nil || len(data) == 0 {
		return nil
	}

	payload := data // buildutils:allow-slice-alias slice is static
	if len(data) >= 4 {
		typePrefix := binary.BigEndian.Uint32(data[:4])
		if typePrefix == protobufs.MessageBundleType {
			bundle := &protobufs.MessageBundle{}
			if err := bundle.FromCanonicalBytes(data); err != nil {
				if e.logger != nil {
					e.logger.Debug(
						"failed to decode message bundle for collector",
						zap.Error(err),
					)
				}
				return err
			}

			// In prover-only mode, filter out non-prover messages
			if e.proverOnlyMode.Load() {
				bundle.Requests = e.filterProverOnlyRequests(bundle.Requests)
				if len(bundle.Requests) == 0 {
					// All requests were filtered out
					return nil
				}
			}

			// Dedup shard frames: only accept strictly increasing frame numbers
			// per shard address. Different delivery paths (pubsub vs gRPC)
			// produce different serializations of the same shard frame, so we
			// dedup by (shard address, frame number) rather than by hash.
			for _, req := range bundle.Requests {
				if shard := req.GetShard(); shard != nil {
					shardAddr := string(shard.Address)
					shardFrame := shard.FrameNumber

					e.shardFrameDedupMu.Lock()
					lastSeen, exists := e.shardFrameDedup[shardAddr]
					if exists && shardFrame <= lastSeen {
						e.shardFrameDedupMu.Unlock()
						if e.logger != nil {
							e.logger.Debug(
								"dropping duplicate/stale shard frame",
								zap.Uint64("shard_frame", shardFrame),
								zap.Uint64("last_seen", lastSeen),
							)
						}
						return nil
					}
					e.shardFrameDedup[shardAddr] = shardFrame
					e.shardFrameDedupMu.Unlock()
				}
			}

			if len(bundle.Requests) > maxGlobalMessagesPerFrame {
				if e.logger != nil {
					e.logger.Debug(
						"truncating message bundle requests for collector",
						zap.Int("original", len(bundle.Requests)),
						zap.Int("limit", maxGlobalMessagesPerFrame),
					)
				}
				bundle.Requests = bundle.Requests[:maxGlobalMessagesPerFrame]
			}

			e.logBundleRequestTypes(bundle)

			encoded, err := bundle.ToCanonicalBytes()
			if err != nil {
				if e.logger != nil {
					e.logger.Debug(
						"failed to re-encode message bundle for collector",
						zap.Error(err),
					)
				}
				return err
			}
			payload = encoded
		}
	}

	seq := e.currentRank + 1
	record := newSequencedGlobalMessage(seq, payload)

	// Add directly to the collector synchronously rather than going through
	// the aggregator's async worker queue. The async path loses messages
	// because OnSequenceChange advances the retention window before workers
	// finish processing queued items, causing them to be silently pruned.
	collector, _, err := e.messageCollectors.GetOrCreateCollector(seq)
	if err != nil {
		e.logger.Debug(
			"could not get collector for global message",
			zap.Uint64("sequence", seq),
			zap.Uint64("current_rank", e.currentRank),
			zap.Error(err),
		)
		return err
	}

	if err := collector.Add(record); err != nil {
		e.logger.Debug(
			"could not add global message to collector",
			zap.Uint64("sequence", seq),
			zap.Error(err),
		)
		return err
	}

	e.logger.Debug(
		"added global message to collector",
		zap.Uint64("sequence", seq),
		zap.Uint64("current_rank", e.currentRank),
		zap.Int("payload_len", len(payload)),
	)
	return nil
}

// filterProverOnlyRequests filters a list of message requests to only include
// prover-related messages. This is used when in prover-only mode due to
// insufficient coverage.
func (e *GlobalConsensusEngine) filterProverOnlyRequests(
	requests []*protobufs.MessageRequest,
) []*protobufs.MessageRequest {
	filtered := make([]*protobufs.MessageRequest, 0, len(requests))
	droppedCount := 0

	for _, req := range requests {
		if req == nil || req.GetRequest() == nil {
			continue
		}

		// Only allow prover-related message types
		switch req.GetRequest().(type) {
		case *protobufs.MessageRequest_Join,
			*protobufs.MessageRequest_Leave,
			*protobufs.MessageRequest_Pause,
			*protobufs.MessageRequest_Resume,
			*protobufs.MessageRequest_Confirm,
			*protobufs.MessageRequest_Reject,
			*protobufs.MessageRequest_Kick,
			*protobufs.MessageRequest_Update,
			*protobufs.MessageRequest_SeniorityMerge:
			// Prover messages are allowed
			filtered = append(filtered, req)
		default:
			// All other messages are dropped in prover-only mode
			droppedCount++
		}
	}

	if droppedCount > 0 && e.logger != nil {
		e.logger.Debug(
			"dropped non-prover messages in prover-only mode",
			zap.Int("dropped_count", droppedCount),
			zap.Int("allowed_count", len(filtered)),
		)
	}

	return filtered
}

func (e *GlobalConsensusEngine) logBundleRequestTypes(
	bundle *protobufs.MessageBundle,
) {
	requestTypes := make([]string, 0, len(bundle.Requests))
	detailFields := make([]zap.Field, 0)
	for idx, request := range bundle.Requests {
		typeName, detailField, hasDetail := requestTypeNameAndDetail(idx, request)
		requestTypes = append(requestTypes, typeName)
		if hasDetail {
			detailFields = append(detailFields, detailField)
		}
	}

	fields := []zap.Field{
		zap.Int("request_count", len(bundle.Requests)),
		zap.Strings("request_types", requestTypes),
		zap.Int64("bundle_timestamp", bundle.Timestamp),
	}
	fields = append(fields, detailFields...)

	e.logger.Debug("collected global request bundle", fields...)
}

func requestTypeNameAndDetail(
	idx int,
	req *protobufs.MessageRequest,
) (string, zap.Field, bool) {
	if req == nil || req.GetRequest() == nil {
		return "nil_request", zap.Field{}, false
	}

	switch actual := req.GetRequest().(type) {
	case *protobufs.MessageRequest_Join:
		return "ProverJoin", zap.Field{}, false
	case *protobufs.MessageRequest_Leave:
		return "ProverLeave", zap.Field{}, false
	case *protobufs.MessageRequest_Pause:
		return "ProverPause", zap.Field{}, false
	case *protobufs.MessageRequest_Resume:
		return "ProverResume", zap.Field{}, false
	case *protobufs.MessageRequest_Confirm:
		return "ProverConfirm", zap.Field{}, false
	case *protobufs.MessageRequest_Reject:
		return "ProverReject", zap.Field{}, false
	case *protobufs.MessageRequest_Kick:
		return "ProverKick", zap.Field{}, false
	case *protobufs.MessageRequest_Update:
		return "ProverUpdate",
			zap.Any(fmt.Sprintf("request_%d_prover_update", idx), actual.Update),
			true
	case *protobufs.MessageRequest_SeniorityMerge:
		return "ProverSeniorityMerge",
			zap.Any(fmt.Sprintf("request_%d_seniority_merge", idx), actual.SeniorityMerge),
			true
	case *protobufs.MessageRequest_TokenDeploy:
		return "TokenDeploy",
			zap.Any(fmt.Sprintf("request_%d_token_deploy", idx), actual.TokenDeploy),
			true
	case *protobufs.MessageRequest_TokenUpdate:
		return "TokenUpdate",
			zap.Any(fmt.Sprintf("request_%d_token_update", idx), actual.TokenUpdate),
			true
	case *protobufs.MessageRequest_Transaction:
		return "Transaction",
			zap.Any(fmt.Sprintf("request_%d_transaction", idx), actual.Transaction),
			true
	case *protobufs.MessageRequest_PendingTransaction:
		return "PendingTransaction",
			zap.Any(
				fmt.Sprintf("request_%d_pending_transaction", idx),
				actual.PendingTransaction,
			),
			true
	case *protobufs.MessageRequest_MintTransaction:
		return "MintTransaction",
			zap.Any(fmt.Sprintf("request_%d_mint_transaction", idx), actual.MintTransaction),
			true
	case *protobufs.MessageRequest_HypergraphDeploy:
		return "HypergraphDeploy",
			zap.Any(fmt.Sprintf("request_%d_hypergraph_deploy", idx), actual.HypergraphDeploy),
			true
	case *protobufs.MessageRequest_HypergraphUpdate:
		return "HypergraphUpdate",
			zap.Any(fmt.Sprintf("request_%d_hypergraph_update", idx), actual.HypergraphUpdate),
			true
	case *protobufs.MessageRequest_VertexAdd:
		return "VertexAdd",
			zap.Any(fmt.Sprintf("request_%d_vertex_add", idx), actual.VertexAdd),
			true
	case *protobufs.MessageRequest_VertexRemove:
		return "VertexRemove",
			zap.Any(fmt.Sprintf("request_%d_vertex_remove", idx), actual.VertexRemove),
			true
	case *protobufs.MessageRequest_HyperedgeAdd:
		return "HyperedgeAdd",
			zap.Any(fmt.Sprintf("request_%d_hyperedge_add", idx), actual.HyperedgeAdd),
			true
	case *protobufs.MessageRequest_HyperedgeRemove:
		return "HyperedgeRemove",
			zap.Any(fmt.Sprintf("request_%d_hyperedge_remove", idx), actual.HyperedgeRemove),
			true
	case *protobufs.MessageRequest_ComputeDeploy:
		return "ComputeDeploy",
			zap.Any(fmt.Sprintf("request_%d_compute_deploy", idx), actual.ComputeDeploy),
			true
	case *protobufs.MessageRequest_ComputeUpdate:
		return "ComputeUpdate",
			zap.Any(fmt.Sprintf("request_%d_compute_update", idx), actual.ComputeUpdate),
			true
	case *protobufs.MessageRequest_CodeDeploy:
		return "CodeDeploy",
			zap.Any(fmt.Sprintf("request_%d_code_deploy", idx), actual.CodeDeploy),
			true
	case *protobufs.MessageRequest_CodeExecute:
		return "CodeExecute",
			zap.Any(fmt.Sprintf("request_%d_code_execute", idx), actual.CodeExecute),
			true
	case *protobufs.MessageRequest_CodeFinalize:
		return "CodeFinalize",
			zap.Any(fmt.Sprintf("request_%d_code_finalize", idx), actual.CodeFinalize),
			true
	case *protobufs.MessageRequest_Shard:
		return "ShardFrame",
			zap.Any(fmt.Sprintf("request_%d_shard_frame", idx), actual.Shard),
			true
	default:
		return "unknown_request", zap.Field{}, false
	}
}

func (e *GlobalConsensusEngine) getMessageCollector(
	rank uint64,
) (keyedaggregator.Collector[sequencedGlobalMessage], bool, error) {
	if e.messageCollectors == nil {
		return nil, false, nil
	}
	return e.messageCollectors.GetCollector(rank)
}

func (e *GlobalConsensusEngine) deferGlobalMessage(
	targetRank uint64,
	payload []byte,
) {
	if e == nil || len(payload) == 0 || targetRank == 0 {
		return
	}

	cloned := slices.Clone(payload)
	e.globalSpilloverMu.Lock()
	e.globalMessageSpillover[targetRank] = append(
		e.globalMessageSpillover[targetRank],
		cloned,
	)
	pending := len(e.globalMessageSpillover[targetRank])
	e.globalSpilloverMu.Unlock()

	if e.logger != nil {
		e.logger.Debug(
			"deferred global message due to collector limit",
			zap.Uint64("target_rank", targetRank),
			zap.Int("pending", pending),
		)
	}
}

func (e *GlobalConsensusEngine) flushDeferredGlobalMessages(targetRank uint64) {
	if e == nil || e.messageAggregator == nil || targetRank == 0 {
		return
	}

	e.globalSpilloverMu.Lock()
	payloads := e.globalMessageSpillover[targetRank]
	if len(payloads) > 0 {
		delete(e.globalMessageSpillover, targetRank)
	}
	e.globalSpilloverMu.Unlock()

	if len(payloads) == 0 {
		return
	}

	for _, payload := range payloads {
		e.messageAggregator.Add(
			newSequencedGlobalMessage(targetRank, payload),
		)
	}

	if e.logger != nil {
		e.logger.Debug(
			"replayed deferred global messages",
			zap.Uint64("target_rank", targetRank),
			zap.Int("count", len(payloads)),
		)
	}
}
