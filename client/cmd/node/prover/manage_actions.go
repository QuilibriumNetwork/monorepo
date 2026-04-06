package prover

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	tea "charm.land/bubbletea/v2"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/global"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
)

var globalDomain = bytes.Repeat([]byte{0xff}, 32)

// doJoin sends a RequestJoin RPC with one or more filters.
// VDF computation happens on the node side and may take a long time.
func doJoin(client protobufs.NodeServiceClient, filters [][]byte) tea.Cmd {
	return func() tea.Msg {
		_, err := client.RequestJoin(
			context.Background(),
			&protobufs.RequestJoinRequest{
				Filters: filters,
			},
		)
		return actionResultMsg{
			action: "Join",
			filter: fmt.Sprintf("%d filter(s)", len(filters)),
			err:    err,
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
		_, err := client.SetManuallyManaged(
			context.Background(),
			&protobufs.SetManuallyManagedRequest{
				CoreId:          coreId,
				ManuallyManaged: manual,
			},
		)
		return toggleManualMsg{coreId: coreId, newState: manual, err: err}
	}
}

// doMarkWorkersManual marks one or more workers as manually managed.
// Fire-and-forget: the result message is handled silently.
func doMarkWorkersManual(client protobufs.NodeServiceClient, workerIDs []uint32) tea.Cmd {
	return func() tea.Msg {
		var firstErr error
		for _, id := range workerIDs {
			_, err := client.SetManuallyManaged(
				context.Background(),
				&protobufs.SetManuallyManagedRequest{
					CoreId:          id,
					ManuallyManaged: true,
				},
			)
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return markManualMsg{workerIDs: workerIDs, err: firstErr}
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

// checkAllocationStatus polls the node to see if ANY of the given filters
// have changed from originalStatus.
func checkAllocationStatus(
	client protobufs.NodeServiceClient,
	action string,
	filters [][]byte,
	originalStatus uint32,
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

		// Check if at least one filter has changed status.
		for _, filter := range filters {
			for _, alloc := range nodeInfo.GetShardAllocations() {
				if !bytes.Equal(alloc.GetFilter(), filter) {
					continue
				}
				if alloc.GetStatus() != originalStatus {
					newName, ok := allocationStatusNames[alloc.GetStatus()]
					if !ok {
						newName = fmt.Sprintf("Unknown(%d)", alloc.GetStatus())
					}
					return actionConfirmedMsg{
						action:    action,
						filter:    truncHex(hex.EncodeToString(filter)),
						newStatus: newName,
						frame:     currentFrame,
					}
				}
			}
		}

		// All filters still have original status (or were removed).
		// Check if any were removed entirely.
		allocByFilter := make(map[string]bool)
		for _, alloc := range nodeInfo.GetShardAllocations() {
			allocByFilter[hex.EncodeToString(alloc.GetFilter())] = true
		}
		for _, filter := range filters {
			if !allocByFilter[hex.EncodeToString(filter)] {
				return actionConfirmedMsg{
					action:    action,
					filter:    truncHex(hex.EncodeToString(filter)),
					newStatus: "Removed",
					frame:     currentFrame,
				}
			}
		}

		return awaitResultMsg{
			action:    action,
			unchanged: true,
			frame:     currentFrame,
		}
	}
}

// getFrameNumber fetches the current frame number from the node.
func getFrameNumber(client protobufs.NodeServiceClient) (uint64, error) {
	info, err := client.GetShardInfo(
		context.Background(),
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
