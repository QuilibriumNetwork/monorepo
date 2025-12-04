package global

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

func TestFrameChainChecker_CanProcessSequentialChain(t *testing.T) {
	store := newMockFrameChainStore()
	checker := NewFrameChainChecker(store, zap.NewNop())

	finalized := newTestFrame(10, nil)
	store.addSealed(finalized)
	finalizedState := &models.State[*protobufs.GlobalFrame]{
		Rank:       finalized.Header.Rank,
		Identifier: finalized.Identity(),
		State:      &finalized,
	}

	candidate := newTestFrame(
		11,
		[]byte(finalized.Identity()),
	)
	store.addCandidate(candidate)

	proposalFrame := newTestFrame(
		12,
		[]byte(candidate.Identity()),
	)
	proposal := &protobufs.GlobalProposal{
		State: proposalFrame,
	}

	require.True(
		t,
		checker.CanProcessSequentialChain(finalizedState, proposal),
	)
}

func TestFrameChainChecker_CanProcessSequentialChainMultipleCandidates(
	t *testing.T,
) {
	store := newMockFrameChainStore()
	checker := NewFrameChainChecker(store, zap.NewNop())

	finalized := newTestFrame(20, nil)
	store.addSealed(finalized)
	finalizedState := &models.State[*protobufs.GlobalFrame]{
		Rank:       finalized.Header.Rank,
		Identifier: finalized.Identity(),
		State:      &finalized,
	}

	candidate21 := newTestFrame(
		21,
		[]byte(finalized.Identity()),
	)
	store.addCandidate(candidate21)

	candidate22 := newTestFrame(
		22,
		[]byte(candidate21.Identity()),
	)
	store.addCandidate(candidate22)

	proposal := &protobufs.GlobalProposal{
		State: newTestFrame(
			23,
			[]byte(candidate22.Identity()),
		),
	}

	require.True(
		t,
		checker.CanProcessSequentialChain(finalizedState, proposal),
	)
}

func TestFrameChainChecker_CanProcessSequentialChainMissingParent(
	t *testing.T,
) {
	store := newMockFrameChainStore()
	checker := NewFrameChainChecker(store, zap.NewNop())

	finalized := newTestFrame(5, nil)
	store.addSealed(finalized)
	finalizedState := &models.State[*protobufs.GlobalFrame]{
		Rank:       finalized.Header.Rank,
		Identifier: finalized.Identity(),
		State:      &finalized,
	}

	// Proposal references a parent that does not exist
	proposal := &protobufs.GlobalProposal{
		State: newTestFrame(
			6,
			[]byte("missing-parent"),
		),
	}

	require.False(
		t,
		checker.CanProcessSequentialChain(finalizedState, proposal),
	)
}

type mockFrameChainStore struct {
	sealed     map[uint64]*protobufs.GlobalFrame
	candidates map[uint64]map[string]*protobufs.GlobalFrame
}

func newMockFrameChainStore() *mockFrameChainStore {
	return &mockFrameChainStore{
		sealed:     make(map[uint64]*protobufs.GlobalFrame),
		candidates: make(map[uint64]map[string]*protobufs.GlobalFrame),
	}
}

func (m *mockFrameChainStore) addSealed(frame *protobufs.GlobalFrame) {
	if frame == nil || frame.Header == nil {
		return
	}
	m.sealed[frame.Header.FrameNumber] = frame
}

func (m *mockFrameChainStore) addCandidate(frame *protobufs.GlobalFrame) {
	if frame == nil || frame.Header == nil {
		return
	}
	key := frame.Header.FrameNumber
	if _, ok := m.candidates[key]; !ok {
		m.candidates[key] = make(map[string]*protobufs.GlobalFrame)
	}
	m.candidates[key][string(frame.Identity())] = frame
}

func (m *mockFrameChainStore) GetGlobalClockFrame(
	frameNumber uint64,
) (*protobufs.GlobalFrame, error) {
	frame, ok := m.sealed[frameNumber]
	if !ok {
		return nil, store.ErrNotFound
	}
	return frame, nil
}

func (m *mockFrameChainStore) GetGlobalClockFrameCandidate(
	frameNumber uint64,
	selector []byte,
) (*protobufs.GlobalFrame, error) {
	candidates := m.candidates[frameNumber]
	if candidates == nil {
		return nil, store.ErrNotFound
	}
	frame, ok := candidates[string(selector)]
	if !ok {
		return nil, store.ErrNotFound
	}
	return frame, nil
}

func newTestFrame(
	frameNumber uint64,
	parentSelector []byte,
) *protobufs.GlobalFrame {
	header := &protobufs.GlobalFrameHeader{
		FrameNumber:    frameNumber,
		ParentSelector: parentSelector,
		Output:         []byte{byte(frameNumber)},
		Rank:           frameNumber,
	}
	return &protobufs.GlobalFrame{
		Header: header,
	}
}
