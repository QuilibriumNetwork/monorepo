package prover

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	tea "charm.land/bubbletea/v2"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

var globalDomain = bytes.Repeat([]byte{0xff}, 32)

// rpcTimeout is the per-call deadline applied to every NodeService RPC
// initiated by the TUI. Without this, a hung node would block the
// corresponding tea command forever and the user would see no
// feedback at all. Set generously — VDF-bearing operations like
// RequestJoin can legitimately take a while on the server side.
const rpcTimeout = 15 * time.Second

// joinRpcTimeout is the longer ceiling specifically for RequestJoin,
// which includes VDF computation on the node side.
const joinRpcTimeout = 90 * time.Second

// withTimeout returns a context with `rpcTimeout` plus its cancel fn.
// Callers must defer the cancel fn.
func withTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), rpcTimeout)
}

func withTimeoutD(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// doJoin sends a RequestJoin RPC with one or more filters.
// VDF computation happens on the node side and may take a long time,
// so a longer dedicated timeout applies (vs the default `rpcTimeout`).
//
// The returned `actionResultMsg` carries the raw filters so the
// caller can hook the await-confirm loop just like Leave/Confirm/etc.
// — RPC ack means "node accepted the request," not "alloc landed
// on chain," and the await loop is what observes the latter.
func doJoin(client protobufs.NodeServiceClient, filters [][]byte) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := withTimeoutD(joinRpcTimeout)
		defer cancel()
		_, err := client.RequestJoin(
			ctx,
			&protobufs.RequestJoinRequest{
				Filters: filters,
			},
		)
		return actionResultMsg{
			action:     "Join",
			filter:     fmt.Sprintf("%d filter(s)", len(filters)),
			filtersRaw: filters,
			err:        err,
		}
	}
}

// doLeave creates a prover leave message with one or more filters.
func doLeave(client protobufs.NodeServiceClient, filters [][]byte, originalStatus uint32) tea.Cmd {
	return func() tea.Msg {
		label := filtersLabel(filters)

		frameNumber, err := getFrameNumber(client)
		if err != nil {
			return actionPreparedMsg{action: "Leave", filter: label, err: err}
		}

		initKeyManager()
		if KeyManager == nil {
			return actionPreparedMsg{action: "Leave", filter: label, err: fmt.Errorf("key manager not available")}
		}

		leave, err := global.NewProverLeave(
			filters,
			frameNumber,
			KeyManager,
			nil,
			nil,
		)
		if err != nil {
			return actionPreparedMsg{action: "Leave", filter: label, err: err}
		}

		if err := leave.Prove(frameNumber); err != nil {
			return actionPreparedMsg{action: "Leave", filter: label, err: err}
		}

		return actionPreparedMsg{
			action:         "Leave",
			filter:         label,
			filtersRaw:     filters,
			sendFrame:      frameNumber,
			originalStatus: originalStatus,
			request: &protobufs.MessageRequest{
				Request: &protobufs.MessageRequest_Leave{
					Leave: leave.ToProtobuf(),
				},
			},
		}
	}
}

// doConfirm creates a prover confirm message with one or more filters.
func doConfirm(client protobufs.NodeServiceClient, filters [][]byte, originalStatus uint32) tea.Cmd {
	return func() tea.Msg {
		label := filtersLabel(filters)

		frameNumber, err := getFrameNumber(client)
		if err != nil {
			return actionPreparedMsg{action: "Confirm", filter: label, err: err}
		}

		initKeyManager()
		if KeyManager == nil {
			return actionPreparedMsg{action: "Confirm", filter: label, err: fmt.Errorf("key manager not available")}
		}

		confirm, err := global.NewProverConfirm(
			filters,
			frameNumber,
			KeyManager,
			nil,
			nil,
		)
		if err != nil {
			return actionPreparedMsg{action: "Confirm", filter: label, err: err}
		}

		if err := confirm.Prove(frameNumber); err != nil {
			return actionPreparedMsg{action: "Confirm", filter: label, err: err}
		}

		return actionPreparedMsg{
			action:         "Confirm",
			filter:         label,
			filtersRaw:     filters,
			sendFrame:      frameNumber,
			originalStatus: originalStatus,
			request: &protobufs.MessageRequest{
				Request: &protobufs.MessageRequest_Confirm{
					Confirm: confirm.ToProtobuf(),
				},
			},
		}
	}
}

// doReject creates a prover reject message with one or more filters.
func doReject(client protobufs.NodeServiceClient, filters [][]byte, originalStatus uint32) tea.Cmd {
	return func() tea.Msg {
		label := filtersLabel(filters)

		frameNumber, err := getFrameNumber(client)
		if err != nil {
			return actionPreparedMsg{action: "Reject", filter: label, err: err}
		}

		initKeyManager()
		if KeyManager == nil {
			return actionPreparedMsg{action: "Reject", filter: label, err: fmt.Errorf("key manager not available")}
		}

		reject, err := global.NewProverReject(
			filters,
			frameNumber,
			KeyManager,
			nil,
			nil,
		)
		if err != nil {
			return actionPreparedMsg{action: "Reject", filter: label, err: err}
		}

		if err := reject.Prove(frameNumber); err != nil {
			return actionPreparedMsg{action: "Reject", filter: label, err: err}
		}

		return actionPreparedMsg{
			action:         "Reject",
			filter:         label,
			filtersRaw:     filters,
			sendFrame:      frameNumber,
			originalStatus: originalStatus,
			request: &protobufs.MessageRequest{
				Request: &protobufs.MessageRequest_Reject{
					Reject: reject.ToProtobuf(),
				},
			},
		}
	}
}

// doPause creates a prover pause message (single filter only).
func doPause(client protobufs.NodeServiceClient, filter []byte, originalStatus uint32) tea.Cmd {
	return func() tea.Msg {
		filterHex := truncHex(hex.EncodeToString(filter))

		frameNumber, err := getFrameNumber(client)
		if err != nil {
			return actionPreparedMsg{action: "Pause", filter: filterHex, err: err}
		}

		initKeyManager()
		if KeyManager == nil {
			return actionPreparedMsg{action: "Pause", filter: filterHex, err: fmt.Errorf("key manager not available")}
		}

		pause, err := global.NewProverPause(
			filter,
			frameNumber,
			KeyManager,
			nil,
			nil,
		)
		if err != nil {
			return actionPreparedMsg{action: "Pause", filter: filterHex, err: err}
		}

		if err := pause.Prove(frameNumber); err != nil {
			return actionPreparedMsg{action: "Pause", filter: filterHex, err: err}
		}

		return actionPreparedMsg{
			action:         "Pause",
			filter:         filterHex,
			filtersRaw:     [][]byte{filter},
			sendFrame:      frameNumber,
			originalStatus: originalStatus,
			request: &protobufs.MessageRequest{
				Request: &protobufs.MessageRequest_Pause{
					Pause: pause.ToProtobuf(),
				},
			},
		}
	}
}

// doResume creates a prover resume message (single filter only).
func doResume(client protobufs.NodeServiceClient, filter []byte, originalStatus uint32) tea.Cmd {
	return func() tea.Msg {
		filterHex := truncHex(hex.EncodeToString(filter))

		frameNumber, err := getFrameNumber(client)
		if err != nil {
			return actionPreparedMsg{action: "Resume", filter: filterHex, err: err}
		}

		initKeyManager()
		if KeyManager == nil {
			return actionPreparedMsg{action: "Resume", filter: filterHex, err: fmt.Errorf("key manager not available")}
		}

		resume, err := global.NewProverResume(
			filter,
			frameNumber,
			KeyManager,
			nil,
			nil,
		)
		if err != nil {
			return actionPreparedMsg{action: "Resume", filter: filterHex, err: err}
		}

		if err := resume.Prove(frameNumber); err != nil {
			return actionPreparedMsg{action: "Resume", filter: filterHex, err: err}
		}

		return actionPreparedMsg{
			action:         "Resume",
			filter:         filterHex,
			filtersRaw:     [][]byte{filter},
			sendFrame:      frameNumber,
			originalStatus: originalStatus,
			request: &protobufs.MessageRequest{
				Request: &protobufs.MessageRequest_Resume{
					Resume: resume.ToProtobuf(),
				},
			},
		}
	}
}

// doToggleManual sends a SetManuallyManaged RPC for the given worker.
func doToggleManual(client protobufs.NodeServiceClient, coreId uint32, manual bool) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := withTimeout()
		defer cancel()
		_, err := client.SetManuallyManaged(
			ctx,
			&protobufs.SetManuallyManagedRequest{
				CoreId:          coreId,
				ManuallyManaged: manual,
			},
		)
		return toggleManualMsg{coreId: coreId, newState: manual, err: err}
	}
}

// doMarkWorkersManual marks one or more workers as manually managed.
//
// Parallelized — each worker gets its own goroutine with a bounded
// context, so a single hung RPC doesn't serialize the batch. Returns
// a per-worker failure list so the Update layer can surface partial
// failures rather than just "first error" (which was lossy and gave
// the user no idea which workers actually changed).
func doMarkWorkersManual(client protobufs.NodeServiceClient, workerIDs []uint32) tea.Cmd {
	return func() tea.Msg {
		type result struct {
			id  uint32
			err error
		}
		ch := make(chan result, len(workerIDs))
		var wg sync.WaitGroup
		for _, id := range workerIDs {
			wg.Add(1)
			go func(id uint32) {
				defer wg.Done()
				ctx, cancel := withTimeout()
				defer cancel()
				_, err := client.SetManuallyManaged(
					ctx,
					&protobufs.SetManuallyManagedRequest{
						CoreId:          id,
						ManuallyManaged: true,
					},
				)
				ch <- result{id: id, err: err}
			}(id)
		}
		wg.Wait()
		close(ch)

		var failed []uint32
		var firstErr error
		for r := range ch {
			if r.err != nil {
				failed = append(failed, r.id)
				if firstErr == nil {
					firstErr = r.err
				}
			}
		}
		return markManualMsg{
			workerIDs: workerIDs,
			failedIDs: failed,
			err:       firstErr,
		}
	}
}

// sendAction broadcasts a prepared message to the network.
func sendAction(client protobufs.NodeServiceClient, prepared actionPreparedMsg) tea.Cmd {
	return func() tea.Msg {
		err := sendProverMessage(client, globalDomain, prepared.request)
		return actionBroadcastMsg{
			action:         prepared.action,
			filter:         prepared.filter,
			filtersRaw:     prepared.filtersRaw,
			sendFrame:      prepared.sendFrame,
			originalStatus: prepared.originalStatus,
			err:            err,
		}
	}
}

// checkAllocationStatus polls the node and returns a per-filter
// outcome for every awaited filter. The caller (Update) aggregates
// these across retries and decides when to surface
// `actionConfirmedMsg`.
//
// Outcome rules per filter:
//   - status == originalStatus → unsettled (will retry)
//   - status != originalStatus → settled, outcome = status name
//   - filter absent from allocations → settled, outcome = "Removed"
//
// On RPC error, returns `awaitResultMsg{err}` with no per-filter
// data; the caller decides whether to retry or surface.
func checkAllocationStatus(
	client protobufs.NodeServiceClient,
	action string,
	entries []awaitFilterEntry,
) tea.Cmd {
	return func() tea.Msg {
		nodeInfo, shardInfo, _, err := fetchRPCData(client)
		if err != nil {
			return awaitResultMsg{action: action, err: err}
		}

		var currentFrame uint64
		if shardInfo != nil {
			currentFrame = shardInfo.GetFrameNumber()
		}

		// Index current allocations by filter for O(N) per-filter
		// resolution rather than the prior O(N*M) nested loop.
		byFilter := make(
			map[string]*protobufs.ShardAllocationInfo, len(nodeInfo.GetShardAllocations()),
		)
		for _, alloc := range nodeInfo.GetShardAllocations() {
			byFilter[hex.EncodeToString(alloc.GetFilter())] = alloc
		}

		outcomes := make([]filterOutcome, 0, len(entries))
		for _, e := range entries {
			key := hex.EncodeToString(e.filter)
			alloc, present := byFilter[key]
			switch {
			case !present:
				outcomes = append(outcomes, filterOutcome{
					filter:  e.filter,
					outcome: "Removed",
					settled: true,
				})
			case alloc.GetStatus() != e.originalStatus:
				name, ok := allocationStatusNames[alloc.GetStatus()]
				if !ok {
					name = fmt.Sprintf("Unknown(%d)", alloc.GetStatus())
				}
				outcomes = append(outcomes, filterOutcome{
					filter:  e.filter,
					outcome: name,
					settled: true,
				})
			default:
				outcomes = append(outcomes, filterOutcome{
					filter:  e.filter,
					settled: false,
				})
			}
		}
		return awaitResultMsg{
			action:    action,
			frame:     currentFrame,
			perFilter: outcomes,
		}
	}
}

// getFrameNumber fetches the current frame number from the node.
// Uses a bounded context so a hung node fails fast instead of
// freezing the dispatching tea command.
func getFrameNumber(client protobufs.NodeServiceClient) (uint64, error) {
	ctx, cancel := withTimeout()
	defer cancel()
	info, err := client.GetShardInfo(
		ctx,
		&protobufs.GetShardInfoRequest{},
	)
	if err != nil {
		return 0, fmt.Errorf("get frame number: %w", err)
	}
	return info.GetFrameNumber(), nil
}

// filtersLabel returns a display label for one or more filters.
func filtersLabel(filters [][]byte) string {
	if len(filters) == 1 {
		return truncHex(hex.EncodeToString(filters[0]))
	}
	return fmt.Sprintf("%d filters", len(filters))
}
