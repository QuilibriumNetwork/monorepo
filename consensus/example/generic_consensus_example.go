package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
)

// Example using the generic state machine from the consensus package

// ConsensusData represents the state data
type ConsensusData struct {
	Round      uint64
	Hash       string
	Votes      map[string]interface{}
	Proof      interface{}
	IsProver   bool
	Timestamp  time.Time
	ProposerID string
}

// Identity implements Unique interface
func (c ConsensusData) Identity() consensus.Identity {
	return fmt.Sprintf("%s-%d", c.Hash, c.Round)
}

func (c ConsensusData) Rank() uint64 {
	return c.Round
}

func (c ConsensusData) Clone() consensus.Unique {
	return ConsensusData{
		Round:      c.Round,
		Hash:       c.Hash,
		Votes:      c.Votes,
		Proof:      c.Proof,
		IsProver:   c.IsProver,
		Timestamp:  c.Timestamp,
		ProposerID: c.ProposerID,
	}
}

// Vote represents a vote in the consensus
type Vote struct {
	NodeID     string
	Round      uint64
	VoteValue  string
	Timestamp  time.Time
	ProposerID string
}

// Identity implements Unique interface
func (v Vote) Identity() consensus.Identity {
	return fmt.Sprintf("%s-%d-%s", v.ProposerID, v.Round, v.VoteValue)
}

func (v Vote) Rank() uint64 {
	return v.Round
}

func (v Vote) Clone() consensus.Unique {
	return Vote{
		NodeID:     v.NodeID,
		Round:      v.Round,
		VoteValue:  v.VoteValue,
		Timestamp:  v.Timestamp,
		ProposerID: v.ProposerID,
	}
}

// PeerID represents a peer identifier
type PeerID struct {
	ID string
}

// Identity implements Unique interface
func (p PeerID) Identity() consensus.Identity {
	return p.ID
}

func (p PeerID) Rank() uint64 {
	return 0
}

func (p PeerID) Clone() consensus.Unique {
	return p
}

// CollectedData represents collected mutations
type CollectedData struct {
	Round     uint64
	Mutations []string
	Timestamp time.Time
}

// Identity implements Unique interface
func (c CollectedData) Identity() consensus.Identity {
	return fmt.Sprintf("collected-%d", c.Timestamp.Unix())
}

func (c CollectedData) Rank() uint64 {
	return c.Round
}

func (c CollectedData) Clone() consensus.Unique {
	return CollectedData{
		Mutations: slices.Clone(c.Mutations),
		Timestamp: c.Timestamp,
	}
}

// MockSyncProvider implements SyncProvider
type MockSyncProvider struct {
	logger *zap.Logger
}

func (m *MockSyncProvider) Synchronize(
	existing *ConsensusData,
	ctx context.Context,
) (<-chan *ConsensusData, <-chan error) {
	dataCh := make(chan *ConsensusData, 1)
	errCh := make(chan error, 1)

	go func() {
		defer close(dataCh)
		defer close(errCh)

		m.logger.Info("synchronizing...")
		select {
		case <-time.After(10 * time.Millisecond):
			m.logger.Info("sync complete")
			if existing != nil {
				dataCh <- existing
			} else {
				dataCh <- &ConsensusData{
					Round:     0,
					Hash:      "genesis",
					Votes:     make(map[string]interface{}),
					Timestamp: time.Now(),
				}
			}
			errCh <- nil
		case <-ctx.Done():
			errCh <- ctx.Err()
		}
	}()

	return dataCh, errCh
}

// MockVotingProvider implements VotingProvider
type MockVotingProvider struct {
	logger       *zap.Logger
	votes        map[string]*Vote
	currentRound uint64
	voteTarget   int
	mu           sync.Mutex
	isMalicious  bool
	nodeID       string
	messageBus   *MessageBus
}

func NewMockVotingProvider(
	logger *zap.Logger,
	voteTarget int,
	nodeID string,
) *MockVotingProvider {
	return &MockVotingProvider{
		logger:     logger,
		votes:      make(map[string]*Vote),
		voteTarget: voteTarget,
		nodeID:     nodeID,
	}
}

func NewMaliciousVotingProvider(
	logger *zap.Logger,
	voteTarget int,
	nodeID string,
) *MockVotingProvider {
	return &MockVotingProvider{
		logger:      logger,
		votes:       make(map[string]*Vote),
		voteTarget:  voteTarget,
		isMalicious: true,
		nodeID:      nodeID,
	}
}

func (m *MockVotingProvider) SendProposal(
	proposal *ConsensusData,
	ctx context.Context,
) error {
	m.logger.Info("sending proposal",
		zap.Uint64("round", proposal.Round),
		zap.String("hash", proposal.Hash))

	if m.messageBus != nil {
		// Make a copy to avoid sharing pointers between nodes
		proposalCopy := &ConsensusData{
			Round:      proposal.Round,
			Hash:       proposal.Hash,
			Votes:      make(map[string]interface{}),
			Proof:      proposal.Proof,
			IsProver:   proposal.IsProver,
			Timestamp:  proposal.Timestamp,
			ProposerID: proposal.ProposerID,
		}
		// Copy votes map
		for k, v := range proposal.Votes {
			proposalCopy.Votes[k] = v
		}

		m.messageBus.Broadcast(Message{
			Type:   "proposal",
			Sender: m.nodeID,
			Data:   proposalCopy,
		})
	}

	return nil
}

func (m *MockVotingProvider) DecideAndSendVote(
	proposals map[consensus.Identity]*ConsensusData,
	ctx context.Context,
) (PeerID, *Vote, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Log available proposals
	m.logger.Info("deciding vote",
		zap.Int("proposal_count", len(proposals)),
		zap.String("node_id", m.nodeID))

	nodes := []string{
		"prover-node-1",
		"validator-node-1",
		"validator-node-2",
		"validator-node-3",
	}

	var chosenProposal *ConsensusData
	var chosenID consensus.Identity
	if len(proposals) > 3 {
		leaderIdx := int(proposals[nodes[0]].Round % uint64(len(nodes)))

		chosenProposal = proposals[nodes[leaderIdx]]
		chosenID = nodes[leaderIdx]
		if chosenProposal == nil {
			chosenProposal = proposals[nodes[(leaderIdx+1)%len(nodes)]]
			chosenID = nodes[(leaderIdx+1)%len(nodes)]
		}
		m.logger.Info("found proposal",
			zap.String("from", chosenID),
			zap.Uint64("round", chosenProposal.Round))
	}
	if chosenProposal == nil {
		return PeerID{}, nil, fmt.Errorf("no proposals to vote on")
	}

	vote := &Vote{
		NodeID:     m.nodeID,
		Round:      chosenProposal.Round,
		VoteValue:  "approve",
		Timestamp:  time.Now(),
		ProposerID: chosenID,
	}

	m.votes[vote.NodeID] = vote
	m.logger.Info("decided and sent vote",
		zap.String("node_id", vote.NodeID),
		zap.String("vote", vote.VoteValue),
		zap.Uint64("round", vote.Round),
		zap.String("for_proposal", chosenID))

	if m.messageBus != nil {
		// Make a copy to avoid sharing pointers
		voteCopy := &Vote{
			NodeID:     vote.NodeID,
			Round:      vote.Round,
			VoteValue:  vote.VoteValue,
			Timestamp:  vote.Timestamp,
			ProposerID: vote.ProposerID,
		}
		m.messageBus.Broadcast(Message{
			Type:   "vote",
			Sender: m.nodeID,
			Data:   voteCopy,
		})
	}

	return PeerID{ID: chosenID}, vote, nil
}

func (m *MockVotingProvider) IsQuorum(
	proposalVotes map[consensus.Identity]*Vote,
	ctx context.Context,
) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("checking quorum",
		zap.Int("target", m.voteTarget))
	totalVotes := 0
	fmt.Printf("%s %+v\n", m.nodeID, proposalVotes)
	voteCount := map[string]int{}
	for _, votes := range proposalVotes {
		count, ok := voteCount[votes.ProposerID]
		if !ok {
			voteCount[votes.ProposerID] = 1
		} else {
			voteCount[votes.ProposerID] = count + 1
		}
		totalVotes += 1

		if count >= m.voteTarget {
			return true, nil
		}
	}
	if totalVotes >= m.voteTarget {
		return false, errors.New("split quorum")
	}

	return false, nil
}

func (m *MockVotingProvider) FinalizeVotes(
	proposals map[consensus.Identity]*ConsensusData,
	proposalVotes map[consensus.Identity]*Vote,
	ctx context.Context,
) (*ConsensusData, PeerID, error) {
	// Count approvals
	m.logger.Info("finalizing votes",
		zap.Int("total_proposals", len(proposals)))
	winnerCount := 0
	var winnerProposal *ConsensusData = nil
	var winnerProposer PeerID
	voteCount := map[string]int{}
	for _, votes := range proposalVotes {
		count, ok := voteCount[votes.ProposerID]
		if !ok {
			voteCount[votes.ProposerID] = 1
		} else {
			voteCount[votes.ProposerID] = count + 1
		}
	}
	for peerID, proposal := range proposals {
		if proposal == nil {
			continue
		}
		voteCount := voteCount[proposal.ProposerID]
		if voteCount > winnerCount {
			winnerCount = voteCount
			winnerProposal = proposal
			winnerProposer = PeerID{ID: peerID}
		}
	}

	m.logger.Info("vote summary",
		zap.Int("approvals", winnerCount),
		zap.Int("required", m.voteTarget))

	if winnerCount < m.voteTarget {
		return nil, PeerID{}, fmt.Errorf(
			"not enough approvals: %d < %d",
			winnerCount,
			m.voteTarget,
		)
	}

	if winnerProposal != nil {
		return winnerProposal, winnerProposer, nil
	}

	// Pick the first proposal
	for id, prop := range proposals {
		// Create a new finalized state based on the chosen proposal
		finalizedState := &ConsensusData{
			Round:      prop.Round,
			Hash:       prop.Hash,
			Votes:      make(map[string]interface{}),
			Proof:      prop.Proof,
			IsProver:   prop.IsProver,
			Timestamp:  time.Now(),
			ProposerID: id,
		}
		// Copy votes to avoid pointer sharing
		for k, v := range prop.Votes {
			finalizedState.Votes[k] = v
		}

		m.logger.Info("finalized state",
			zap.Uint64("round", finalizedState.Round),
			zap.String("hash", finalizedState.Hash),
			zap.String("proposer", id))
		return finalizedState, PeerID{ID: id}, nil
	}

	return nil, PeerID{}, fmt.Errorf("no proposals to finalize")
}

func (m *MockVotingProvider) SendConfirmation(
	finalized *ConsensusData,
	ctx context.Context,
) error {
	if finalized == nil {
		m.logger.Warn("cannot send confirmation for nil state")
		return fmt.Errorf("cannot send confirmation for nil state")
	}

	m.logger.Info("sending confirmation",
		zap.Uint64("round", finalized.Round),
		zap.String("hash", finalized.Hash))

	if m.messageBus != nil {
		// Make a copy to avoid sharing pointers
		confirmationCopy := &ConsensusData{
			Round:      finalized.Round,
			Hash:       finalized.Hash,
			Votes:      make(map[string]interface{}),
			Proof:      finalized.Proof,
			IsProver:   finalized.IsProver,
			Timestamp:  finalized.Timestamp,
			ProposerID: finalized.ProposerID,
		}
		// Copy votes map
		for k, v := range finalized.Votes {
			confirmationCopy.Votes[k] = v
		}

		m.messageBus.Broadcast(Message{
			Type:   "confirmation",
			Sender: m.nodeID,
			Data:   confirmationCopy,
		})
	}

	return nil
}

func (m *MockVotingProvider) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.votes = make(map[string]*Vote)
	m.logger.Info(
		"reset voting provider",
		zap.Uint64("current_round", m.currentRound),
	)
}

func (m *MockVotingProvider) SetRound(round uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentRound = round
	m.logger.Info("voting provider round updated", zap.Uint64("round", round))
}

// MockLeaderProvider implements LeaderProvider
type MockLeaderProvider struct {
	logger   *zap.Logger
	isProver bool
	nodeID   string
}

func (m *MockLeaderProvider) GetNextLeaders(
	prior *ConsensusData,
	ctx context.Context,
) ([]PeerID, error) {
	// Simple round-robin leader selection
	round := uint64(0)
	if prior != nil {
		round = prior.Round
	}

	nodes := []string{
		"prover-node-1",
		"validator-node-1",
		"validator-node-2",
		"validator-node-3",
	}

	// Select leader based on round
	leaderIdx := int(round % uint64(len(nodes)))
	leaders := []PeerID{
		{ID: nodes[leaderIdx]},
		{ID: nodes[uint64(leaderIdx+1)%uint64(len(nodes))]},
		{ID: nodes[uint64(leaderIdx+2)%uint64(len(nodes))]},
		{ID: nodes[uint64(leaderIdx+3)%uint64(len(nodes))]},
	}

	m.logger.Info("selected next leaders",
		zap.Uint64("round", round),
		zap.String("leader", leaders[0].ID))

	return leaders, nil
}

func (m *MockLeaderProvider) ProveNextState(
	prior *ConsensusData,
	collected CollectedData,
	ctx context.Context,
) (*ConsensusData, error) {
	priorRound := uint64(0)
	priorHash := "genesis"
	if prior != nil {
		priorRound = prior.Round
		priorHash = prior.Hash
	}

	m.logger.Info("generating proof",
		zap.Uint64("prior_round", priorRound),
		zap.String("prior_hash", priorHash),
		zap.Int("mutations", len(collected.Mutations)))

	select {
	case <-time.After(500 * time.Millisecond):
		proof := map[string]interface{}{
			"proof":     "mock_proof_data",
			"timestamp": time.Now(),
			"prover":    m.nodeID,
		}

		newState := &ConsensusData{
			Round:      priorRound + 1,
			Hash:       fmt.Sprintf("block_%d", priorRound+1),
			Votes:      make(map[string]interface{}),
			Proof:      proof,
			IsProver:   true,
			Timestamp:  time.Now(),
			ProposerID: m.nodeID,
		}

		return newState, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// MockLivenessProvider implements LivenessProvider
type MockLivenessProvider struct {
	logger     *zap.Logger
	round      uint64
	nodeID     string
	messageBus *MessageBus
}

func (m *MockLivenessProvider) Collect(
	ctx context.Context,
) (CollectedData, error) {
	m.logger.Info("collecting mutations")

	// Simulate collecting some mutations
	mutations := []string{
		"mutation_1",
		"mutation_2",
		"mutation_3",
	}

	return CollectedData{
		Round:     m.round,
		Mutations: mutations,
		Timestamp: time.Now(),
	}, nil
}

func (m *MockLivenessProvider) SendLiveness(
	prior *ConsensusData,
	collected CollectedData,
	ctx context.Context,
) error {
	round := uint64(0)
	if prior != nil {
		round = prior.Round
	}

	m.logger.Info("sending liveness signal",
		zap.Uint64("round", round),
		zap.Int("mutations", len(collected.Mutations)))

	if m.messageBus != nil {
		// Make a copy to avoid sharing pointers
		collectedCopy := CollectedData{
			Round:     round + 1,
			Mutations: make([]string, len(collected.Mutations)),
			Timestamp: collected.Timestamp,
		}
		copy(collectedCopy.Mutations, collected.Mutations)

		m.messageBus.Broadcast(Message{
			Type:   "liveness_check",
			Sender: m.nodeID,
			Data:   collectedCopy,
		})
	}

	return nil
}

// ConsensusNode represents a node using the generic state machine
type ConsensusNode struct {
	sm *consensus.StateMachine[
		ConsensusData,
		Vote,
		PeerID,
		CollectedData,
	]
	logger           *zap.Logger
	nodeID           string
	ctx              context.Context
	cancel           context.CancelFunc
	messageBus       *MessageBus
	msgChan          chan Message
	votingProvider   *MockVotingProvider
	livenessProvider *MockLivenessProvider
	isMalicious      bool
}

// NewConsensusNode creates a new consensus node
func NewConsensusNode(
	nodeID string,
	isProver bool,
	voteTarget int,
	logger *zap.Logger,
) *ConsensusNode {
	return newConsensusNodeWithBehavior(
		nodeID,
		isProver,
		voteTarget,
		logger,
		false,
	)
}

// NewMaliciousNode creates a new malicious consensus node
func NewMaliciousNode(
	nodeID string,
	isProver bool,
	voteTarget int,
	logger *zap.Logger,
) *ConsensusNode {
	return newConsensusNodeWithBehavior(
		nodeID,
		isProver,
		voteTarget,
		logger,
		true,
	)
}

func newConsensusNodeWithBehavior(
	nodeID string,
	isProver bool,
	voteTarget int,
	logger *zap.Logger,
	isMalicious bool,
) *ConsensusNode {
	// Create initial consensus data
	initialData := &ConsensusData{
		Round:      0,
		Hash:       "genesis",
		Votes:      make(map[string]interface{}),
		IsProver:   isProver,
		Timestamp:  time.Now(),
		ProposerID: "genesis",
	}

	// Create mock implementations
	syncProvider := &MockSyncProvider{logger: logger}

	var votingProvider *MockVotingProvider
	if isMalicious {
		votingProvider = NewMaliciousVotingProvider(logger, voteTarget, nodeID)
	} else {
		votingProvider = NewMockVotingProvider(logger, voteTarget, nodeID)
	}

	leaderProvider := &MockLeaderProvider{
		logger:   logger,
		isProver: isProver,
		nodeID:   nodeID,
	}

	livenessProvider := &MockLivenessProvider{
		logger: logger,
		nodeID: nodeID,
	}

	// Create the state machine
	sm := consensus.NewStateMachine(
		PeerID{ID: nodeID},
		initialData,
		true,
		func() uint64 { return uint64(3) },
		syncProvider,
		votingProvider,
		leaderProvider,
		livenessProvider,
		tracer{logger: logger},
	)

	ctx, cancel := context.WithCancel(context.Background())

	node := &ConsensusNode{
		sm:               sm,
		logger:           logger,
		nodeID:           nodeID,
		ctx:              ctx,
		cancel:           cancel,
		votingProvider:   votingProvider,
		livenessProvider: livenessProvider,
		isMalicious:      isMalicious,
	}

	// Add transition listener
	sm.AddListener(&NodeTransitionListener{
		logger: logger,
		node:   node,
	})

	return node
}

type tracer struct {
	logger *zap.Logger
}

// Error implements consensus.TraceLogger.
func (t tracer) Error(message string, err error) {
	t.logger.Error(message, zap.Error(err))
}

// Trace implements consensus.TraceLogger.
func (t tracer) Trace(message string) {
	t.logger.Debug(message)
}

// Start begins the consensus node
func (n *ConsensusNode) Start() error {
	n.logger.Info("starting consensus node", zap.String("node_id", n.nodeID))

	// Start monitoring for messages
	go n.monitor()

	return n.sm.Start()
}

// Stop halts the consensus node
func (n *ConsensusNode) Stop() error {
	n.logger.Info("stopping consensus node", zap.String("node_id", n.nodeID))
	n.cancel()
	return n.sm.Stop()
}

// SetMessageBus connects the node to the message bus
func (n *ConsensusNode) SetMessageBus(mb *MessageBus) {
	n.messageBus = mb
	n.msgChan = mb.Subscribe(n.nodeID)

	// Also set message bus on providers
	if n.votingProvider != nil {
		n.votingProvider.messageBus = mb
	}
	if n.livenessProvider != nil {
		n.livenessProvider.messageBus = mb
	}
}

// monitor handles incoming messages
func (n *ConsensusNode) monitor() {
	for {
		select {
		case <-n.ctx.Done():
			return
		case msg := <-n.msgChan:
			n.handleMessage(msg)
		}
	}
}

// handleMessage processes messages from other nodes
func (n *ConsensusNode) handleMessage(msg Message) {
	n.logger.Debug("received message",
		zap.String("type", msg.Type),
		zap.String("from", msg.Sender))

	switch msg.Type {
	case "proposal":
		if proposal, ok := msg.Data.(*ConsensusData); ok {
			n.sm.ReceiveProposal(PeerID{ID: msg.Sender}, proposal)
		}
	case "vote":
		if vote, ok := msg.Data.(*Vote); ok {
			n.sm.ReceiveVote(
				PeerID{ID: vote.ProposerID},
				PeerID{ID: msg.Sender},
				vote,
			)
		}
	case "liveness_check":
		if collected, ok := msg.Data.(CollectedData); ok {
			n.sm.ReceiveLivenessCheck(PeerID{ID: msg.Sender}, collected)
		}
	case "confirmation":
		if confirmation, ok := msg.Data.(*ConsensusData); ok {
			n.sm.ReceiveConfirmation(PeerID{ID: msg.Sender}, confirmation)
		}
	}
}

// NodeTransitionListener handles state transitions
type NodeTransitionListener struct {
	logger *zap.Logger
	node   *ConsensusNode
}

func (l *NodeTransitionListener) OnTransition(
	from consensus.State,
	to consensus.State,
	event consensus.Event,
) {
	l.logger.Info("state transition",
		zap.String("node_id", l.node.nodeID),
		zap.String("from", string(from)),
		zap.String("to", string(to)),
		zap.String("event", string(event)))

	// Handle state-specific actions
	switch to {
	case consensus.StateVoting:
		if from != consensus.StateVoting {
			go l.handleEnterVoting()
		}
	case consensus.StateCollecting:
		go l.handleEnterCollecting()
	case consensus.StatePublishing:
		go l.handleEnterPublishing()
	}
}

func (l *NodeTransitionListener) handleEnterVoting() {
	// Wait a bit to ensure we're in voting state
	time.Sleep(50 * time.Millisecond)

	// Malicious nodes exhibit Byzantine behavior
	if l.node.isMalicious {
		l.logger.Warn(
			"MALICIOUS NODE: Executing Byzantine behavior",
			zap.String("node_id", l.node.nodeID),
		)

		// Byzantine behavior: Send different votes to different nodes
		nodes := []string{
			"prover-node-1",
			"validator-node-1",
			"validator-node-2",
			"validator-node-3",
		}
		voteValues := []string{"reject", "reject", "approve", "reject"}

		for i, targetNode := range nodes {
			if targetNode == l.node.nodeID {
				continue
			}

			// Create conflicting vote
			vote := &Vote{
				NodeID:     l.node.nodeID,
				Round:      0, // Will be updated based on proposals
				VoteValue:  voteValues[i],
				Timestamp:  time.Now(),
				ProposerID: targetNode,
			}

			l.logger.Warn(
				"MALICIOUS: Sending conflicting vote",
				zap.String("node_id", l.node.nodeID),
				zap.String("target", targetNode),
				zap.String("vote", voteValues[i]),
			)

			if i == 0 && l.node.messageBus != nil {
				// Make a copy to avoid sharing pointers
				voteCopy := &Vote{
					NodeID:     vote.NodeID,
					Round:      vote.Round,
					VoteValue:  vote.VoteValue,
					Timestamp:  vote.Timestamp,
					ProposerID: vote.ProposerID,
				}
				l.node.messageBus.Broadcast(Message{
					Type:   "vote",
					Sender: l.node.nodeID,
					Data:   voteCopy,
				})
			}
		}

		// Also try to vote multiple times with same value
		time.Sleep(100 * time.Millisecond)
		doubleVote := &Vote{
			NodeID:     l.node.nodeID,
			Round:      0,
			VoteValue:  "approve",
			Timestamp:  time.Now(),
			ProposerID: nodes[0],
		}

		l.logger.Warn(
			"MALICIOUS: Attempting double vote",
			zap.String("node_id", l.node.nodeID),
		)

		l.node.sm.ReceiveVote(
			PeerID{ID: nodes[0]},
			PeerID{ID: l.node.nodeID},
			doubleVote,
		)

		if l.node.messageBus != nil {
			// Make a copy to avoid sharing pointers
			doubleVoteCopy := &Vote{
				NodeID:     doubleVote.NodeID,
				Round:      doubleVote.Round,
				VoteValue:  doubleVote.VoteValue,
				Timestamp:  doubleVote.Timestamp,
				ProposerID: doubleVote.ProposerID,
			}
			l.node.messageBus.Broadcast(Message{
				Type:   "vote",
				Sender: l.node.nodeID,
				Data:   doubleVoteCopy,
			})
		}

		return
	}

	l.logger.Info("entering voting state",
		zap.String("node_id", l.node.nodeID))
}

func (l *NodeTransitionListener) handleEnterCollecting() {
	l.logger.Info("entered collecting state",
		zap.String("node_id", l.node.nodeID))

	// Reset vote handler for new round
	l.node.votingProvider.Reset()
}

func (l *NodeTransitionListener) handleEnterPublishing() {
	l.logger.Info("entered publishing state",
		zap.String("node_id", l.node.nodeID))
}

// MessageBus simulates network communication
type MessageBus struct {
	mu          sync.RWMutex
	subscribers map[string]chan Message
}

type Message struct {
	Type   string
	Sender string
	Data   interface{}
}

func NewMessageBus() *MessageBus {
	return &MessageBus{
		subscribers: make(map[string]chan Message),
	}
}

func (mb *MessageBus) Subscribe(nodeID string) chan Message {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	ch := make(chan Message, 100)
	mb.subscribers[nodeID] = ch
	return ch
}

func (mb *MessageBus) Broadcast(msg Message) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	for nodeID, ch := range mb.subscribers {
		if nodeID != msg.Sender {
			select {
			case ch <- msg:
			default:
			}
		}
	}
}

func main() {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	// Create message bus
	messageBus := NewMessageBus()

	// Create nodes (1 prover, 2 validators, 1 malicious validator)
	// Note: We need 4 nodes total with vote target of 3 to demonstrate Byzantine
	// fault tolerance
	nodes := []*ConsensusNode{
		NewConsensusNode("prover-node-1", true, 3, logger.Named("prover")),
		NewConsensusNode("validator-node-1", true, 3, logger.Named("validator1")),
		NewConsensusNode("validator-node-2", true, 3, logger.Named("validator2")),
		NewMaliciousNode("validator-node-3", false, 3, logger.Named("malicious")),
	}

	// Connect nodes to message bus
	for _, node := range nodes {
		node.SetMessageBus(messageBus)
	}

	// Start all nodes
	logger.Info("=== Starting Consensus Network with Generic State Machine ===")
	logger.Info("Using the generic state machine from consensus package")
	logger.Warn("Network includes 1 MALICIOUS node (validator-node-3) demonstrating Byzantine behavior")

	for _, node := range nodes {
		if err := node.Start(); err != nil {
			logger.Fatal("failed to start node",
				zap.String("node_id", node.nodeID),
				zap.Error(err))
		}
	}

	// Run for a while
	time.Sleep(30 * time.Second)

	// Print statistics
	logger.Info("=== Node Statistics ===")
	for _, node := range nodes {
		viz := consensus.NewStateMachineViz(node.sm)

		logger.Info(fmt.Sprintf("\nStats for %s:\n%s",
			node.nodeID,
			viz.GetStateStats()))

		logger.Info("final state",
			zap.String("node_id", node.nodeID),
			zap.String("current_state", string(node.sm.GetState())),
			zap.Uint64("transition_count", node.sm.GetTransitionCount()),
			zap.Bool("is_malicious", node.isMalicious))
	}

	// Generate visualization
	if len(nodes) > 0 {
		viz := consensus.NewStateMachineViz(nodes[0].sm)
		logger.Info("\nState Machine Diagram:\n" + viz.GenerateMermaidDiagram())
	}

	// Stop all nodes
	logger.Info("=== Stopping Consensus Network ===")
	for _, node := range nodes {
		if err := node.Stop(); err != nil {
			logger.Error("failed to stop node",
				zap.String("node_id", node.nodeID),
				zap.Error(err))
		}
	}

	time.Sleep(2 * time.Second)
}
