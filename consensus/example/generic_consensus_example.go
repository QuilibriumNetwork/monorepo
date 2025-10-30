package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"sync"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/pacemaker"
)

// Example using the generic state machine from the consensus package

// consensusData represents the state data
type consensusData struct {
	Round      uint64
	Hash       string
	Votes      map[string]interface{}
	Proof      interface{}
	IsProver   bool
	Timestamp  time.Time
	ProposerID string
}

// Identity implements Unique interface
func (c consensusData) Identity() models.Identity {
	return fmt.Sprintf("%s-%d", c.Hash, c.Round)
}

func (c consensusData) GetRank() uint64 {
	return c.Round
}

func (c consensusData) Clone() models.Unique {
	return consensusData{
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
type vote struct {
	NodeID     string
	Round      uint64
	VoteValue  string
	Timestamp  time.Time
	ProposerID string
}

// Identity implements Unique interface
func (v vote) Identity() consensus.Identity {
	return fmt.Sprintf("%s-%d-%s", v.ProposerID, v.Round, v.VoteValue)
}

func (v vote) GetRank() uint64 {
	return v.Round
}

func (v vote) Clone() models.Unique {
	return vote{
		NodeID:     v.NodeID,
		Round:      v.Round,
		VoteValue:  v.VoteValue,
		Timestamp:  v.Timestamp,
		ProposerID: v.ProposerID,
	}
}

type aggregateSignature struct {
	Signature []byte
	PublicKey []byte
	Bitmask   []byte
}

// GetBitmask implements models.AggregatedSignature.
func (b *aggregateSignature) GetBitmask() []byte {
	return b.Bitmask
}

// GetPublicKey implements models.AggregatedSignature.
func (b *aggregateSignature) GetPublicKey() []byte {
	return b.PublicKey
}

// GetSignature implements models.AggregatedSignature.
func (b *aggregateSignature) GetSignature() []byte {
	return b.Signature
}

type quorumCertificate struct {
	Filter              []byte
	Rank                uint64
	FrameNumber         uint64
	Selector            []byte
	Timestamp           int64
	AggregatedSignature *aggregateSignature
}

// GetAggregatedSignature implements models.QuorumCertificate.
func (q *quorumCertificate) GetAggregatedSignature() models.AggregatedSignature {
	return q.AggregatedSignature
}

// GetFilter implements models.QuorumCertificate.
func (q *quorumCertificate) GetFilter() []byte {
	return q.Filter
}

// GetFrameNumber implements models.QuorumCertificate.
func (q *quorumCertificate) GetFrameNumber() uint64 {
	return q.FrameNumber
}

// GetRank implements models.QuorumCertificate.
func (q *quorumCertificate) GetRank() uint64 {
	return q.Rank
}

// GetSelector implements models.QuorumCertificate.
func (q *quorumCertificate) GetSelector() []byte {
	return q.Selector
}

// GetTimestamp implements models.QuorumCertificate.
func (q *quorumCertificate) GetTimestamp() int64 {
	return q.Timestamp
}

var _ models.AggregatedSignature = (*aggregateSignature)(nil)
var _ models.QuorumCertificate = (*quorumCertificate)(nil)

type store struct {
	consensusState *models.ConsensusState
	livenessState  *models.LivenessState
}

// GetConsensusState implements consensus.ConsensusStore.
func (s *store) GetConsensusState() (*models.ConsensusState, error) {
	return s.consensusState, nil
}

// GetLivenessState implements consensus.ConsensusStore.
func (s *store) GetLivenessState() (*models.LivenessState, error) {
	return s.livenessState, nil
}

// PutConsensusState implements consensus.ConsensusStore.
func (s *store) PutConsensusState(state *models.ConsensusState) error {
	s.consensusState = state
	return nil
}

// PutLivenessState implements consensus.ConsensusStore.
func (s *store) PutLivenessState(state *models.LivenessState) error {
	s.livenessState = state
	return nil
}

var _ consensus.ConsensusStore = (*store)(nil)

// peerID represents a peer identifier
type peerID struct {
	ID string
}

// Identity implements Unique interface
func (p peerID) Identity() consensus.Identity {
	return p.ID
}

func (p peerID) GetRank() uint64 {
	return 0
}

func (p peerID) Clone() models.Unique {
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

func (c CollectedData) GetRank() uint64 {
	return c.Round
}

func (c CollectedData) Clone() models.Unique {
	return CollectedData{
		Mutations: slices.Clone(c.Mutations),
		Timestamp: c.Timestamp,
	}
}

// MockSyncProvider implements SyncProvider
type MockSyncProvider struct {
}

func (m *MockSyncProvider) Synchronize(
	ctx context.Context,
	existing *consensusData,
) (<-chan *consensusData, <-chan error) {
	dataCh := make(chan *consensusData, 1)
	errCh := make(chan error, 1)

	go func() {
		defer close(dataCh)
		defer close(errCh)

		log.Println("synchronizing...")
		select {
		case <-time.After(10 * time.Millisecond):
			log.Println("sync complete")
			if existing != nil {
				dataCh <- existing
			} else {
				dataCh <- &consensusData{
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
	votes        map[string]*vote
	currentRound uint64
	voteTarget   int
	mu           sync.Mutex
	isMalicious  bool
	nodeID       string
	messageBus   *MessageBus
}

func NewMockVotingProvider(
	voteTarget int,
	nodeID string,
) *MockVotingProvider {
	return &MockVotingProvider{
		votes:      make(map[string]*vote),
		voteTarget: voteTarget,
		nodeID:     nodeID,
	}
}

func NewMaliciousVotingProvider(
	voteTarget int,
	nodeID string,
) *MockVotingProvider {
	return &MockVotingProvider{
		votes:       make(map[string]*vote),
		voteTarget:  voteTarget,
		isMalicious: true,
		nodeID:      nodeID,
	}
}

func (m *MockVotingProvider) SendProposal(
	ctx context.Context,
	proposal *consensusData,
) error {
	log.Printf(
		"sending proposal, round: %d, hash: %s\n",
		proposal.Round,
		proposal.Hash,
	)

	if m.messageBus != nil {
		// Make a copy to avoid sharing pointers between nodes
		proposalCopy := &consensusData{
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
	ctx context.Context,
	proposals map[consensus.Identity]*consensusData,
) (peerID, *vote, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Log available proposals
	log.Printf(
		"deciding vote, proposal count: %d, node id: %s\n",
		len(proposals),
		m.nodeID,
	)

	nodes := []string{
		"prover-node-1",
		"validator-node-1",
		"validator-node-2",
		"validator-node-3",
	}

	var chosenProposal *consensusData
	var chosenID consensus.Identity
	if len(proposals) > 3 {
		leaderIdx := int(proposals[nodes[0]].Round % uint64(len(nodes)))

		chosenProposal = proposals[nodes[leaderIdx]]
		chosenID = nodes[leaderIdx]
		if chosenProposal == nil {
			chosenProposal = proposals[nodes[(leaderIdx+1)%len(nodes)]]
			chosenID = nodes[(leaderIdx+1)%len(nodes)]
		}
		log.Printf(
			"found proposal, from: %s, round: %d\n",
			chosenID,
			chosenProposal.Round,
		)
	}
	if chosenProposal == nil {
		return peerID{}, nil, fmt.Errorf("no proposals to vote on")
	}

	vt := &vote{
		NodeID:     m.nodeID,
		Round:      chosenProposal.Round,
		VoteValue:  "approve",
		Timestamp:  time.Now(),
		ProposerID: chosenID,
	}

	m.votes[vt.NodeID] = vt
	log.Printf(
		"decided and sent vote, node id: %s, vote: %s, round: %d, for proposal: %s\n",
		vt.NodeID,
		vt.VoteValue,
		vt.Round,
		chosenID,
	)

	if m.messageBus != nil {
		// Make a copy to avoid sharing pointers
		voteCopy := &vote{
			NodeID:     vt.NodeID,
			Round:      vt.Round,
			VoteValue:  vt.VoteValue,
			Timestamp:  vt.Timestamp,
			ProposerID: vt.ProposerID,
		}
		m.messageBus.Broadcast(Message{
			Type:   "vote",
			Sender: m.nodeID,
			Data:   voteCopy,
		})
	}

	return peerID{ID: chosenID}, vt, nil
}

func (m *MockVotingProvider) SendVote(ctx context.Context, vt *vote) (
	peerID,
	error,
) {
	log.Printf(
		"re-sent vote, node id: %s, vote: %s, round: %d, for proposal: %s\n",
		vt.NodeID,
		vt.VoteValue,
		vt.Round,
		vt.ProposerID,
	)

	if m.messageBus != nil {
		// Make a copy to avoid sharing pointers
		voteCopy := &vote{
			NodeID:     vt.NodeID,
			Round:      vt.Round,
			VoteValue:  vt.VoteValue,
			Timestamp:  vt.Timestamp,
			ProposerID: vt.ProposerID,
		}
		m.messageBus.Broadcast(Message{
			Type:   "vote",
			Sender: m.nodeID,
			Data:   voteCopy,
		})
	}
	return peerID{ID: vt.ProposerID}, nil
}

func (m *MockVotingProvider) IsQuorum(
	ctx context.Context,
	proposalVotes map[consensus.Identity]*vote,
) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Printf(
		"checking quorum, target: %d\n",
		m.voteTarget,
	)
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
	ctx context.Context,
	proposals map[consensus.Identity]*consensusData,
	proposalVotes map[consensus.Identity]*vote,
) (*consensusData, peerID, error) {
	// Count approvals
	log.Printf(
		"finalizing votes, total proposals: %d\n",
		len(proposals),
	)
	winnerCount := 0
	var winnerProposal *consensusData = nil
	var winnerProposer peerID
	voteCount := map[string]int{}
	for _, votes := range proposalVotes {
		count, ok := voteCount[votes.ProposerID]
		if !ok {
			voteCount[votes.ProposerID] = 1
		} else {
			voteCount[votes.ProposerID] = count + 1
		}
	}
	for pid, proposal := range proposals {
		if proposal == nil {
			continue
		}
		voteCount := voteCount[proposal.ProposerID]
		if voteCount > winnerCount {
			winnerCount = voteCount
			winnerProposal = proposal
			winnerProposer = peerID{ID: pid}
		}
	}

	log.Printf(
		"vote summary, approvals: %d, required: %d\n",
		winnerCount,
		m.voteTarget,
	)

	if winnerCount < m.voteTarget {
		return nil, peerID{}, fmt.Errorf(
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
		finalizedState := &consensusData{
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

		log.Printf(
			"finalized state, round: %d, hash: %s, proposer: %d\n",
			finalizedState.Round,
			finalizedState.Hash,
			id,
		)
		return finalizedState, peerID{ID: id}, nil
	}

	return nil, peerID{}, fmt.Errorf("no proposals to finalize")
}

func (m *MockVotingProvider) SendConfirmation(
	ctx context.Context,
	finalized *consensusData,
) error {
	if finalized == nil {
		log.Println("cannot send confirmation for nil state")
		return fmt.Errorf("cannot send confirmation for nil state")
	}

	log.Printf(
		"sending confirmation, round: %d, hash: %s\n",
		finalized.Round,
		finalized.Hash,
	)

	if m.messageBus != nil {
		// Make a copy to avoid sharing pointers
		confirmationCopy := &consensusData{
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
	m.votes = make(map[string]*vote)
	log.Printf(
		"reset voting provider, current round: %d\n",
		m.currentRound,
	)
}

func (m *MockVotingProvider) SetRound(round uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentRound = round
	log.Printf("voting provider round updated, round: %d\n", round)
}

// MockLeaderProvider implements LeaderProvider
type MockLeaderProvider struct {
	isProver bool
	nodeID   string
}

func (m *MockLeaderProvider) GetNextLeaders(
	ctx context.Context,
	prior *consensusData,
) ([]peerID, error) {
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
	leaders := []peerID{
		{ID: nodes[leaderIdx]},
		{ID: nodes[uint64(leaderIdx+1)%uint64(len(nodes))]},
		{ID: nodes[uint64(leaderIdx+2)%uint64(len(nodes))]},
		{ID: nodes[uint64(leaderIdx+3)%uint64(len(nodes))]},
	}

	fmt.Printf(
		"selected next leaders, round: %d, leader: %s\n",
		round,
		leaders[0].ID,
	)

	return leaders, nil
}

func (m *MockLeaderProvider) ProveNextState(
	ctx context.Context,
	prior *consensusData,
	collected CollectedData,
) (*consensusData, error) {
	priorRound := uint64(0)
	if prior != nil {
		priorRound = prior.Round
	}

	select {
	case <-time.After(500 * time.Millisecond):
		proof := map[string]interface{}{
			"proof":     "mock_proof_data",
			"timestamp": time.Now(),
			"prover":    m.nodeID,
		}

		newState := &consensusData{
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
	round      uint64
	nodeID     string
	messageBus *MessageBus
}

func (m *MockLivenessProvider) Collect(
	ctx context.Context,
) (CollectedData, error) {
	fmt.Println("collecting mutations")

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
	ctx context.Context,
	prior *consensusData,
	collected CollectedData,
) error {
	round := uint64(0)
	if prior != nil {
		round = prior.Round
	}

	fmt.Printf(
		"sending liveness signal, round: %d, mutations: %d\n",
		round,
		len(collected.Mutations),
	)

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
	p *pacemaker.Pacemaker[
		consensusData,
		vote,
		peerID,
		CollectedData,
	]
	sm *consensus.StateMachine[
		consensusData,
		vote,
		peerID,
		CollectedData,
	]
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
) *ConsensusNode {
	return newConsensusNodeWithBehavior(
		nodeID,
		isProver,
		voteTarget,
		false,
	)
}

// NewMaliciousNode creates a new malicious consensus node
func NewMaliciousNode(
	nodeID string,
	isProver bool,
	voteTarget int,
) *ConsensusNode {
	return newConsensusNodeWithBehavior(
		nodeID,
		isProver,
		voteTarget,
		true,
	)
}

func newConsensusNodeWithBehavior(
	nodeID string,
	isProver bool,
	voteTarget int,
	isMalicious bool,
) *ConsensusNode {
	// Create initial consensus data
	initialData := &consensusData{
		Round:      0,
		Hash:       "genesis",
		Votes:      make(map[string]interface{}),
		IsProver:   isProver,
		Timestamp:  time.Now(),
		ProposerID: "genesis",
	}

	// Create mock implementations
	syncProvider := &MockSyncProvider{}

	var votingProvider *MockVotingProvider
	if isMalicious {
		votingProvider = NewMaliciousVotingProvider(voteTarget, nodeID)
	} else {
		votingProvider = NewMockVotingProvider(voteTarget, nodeID)
	}

	leaderProvider := &MockLeaderProvider{
		isProver: isProver,
		nodeID:   nodeID,
	}

	livenessProvider := &MockLivenessProvider{
		nodeID: nodeID,
	}

	// Create the state machine
	sm := consensus.NewStateMachine[consensusData, vote, peerID, CollectedData](
		peerID{ID: nodeID},
		initialData,
		true,
		func() uint64 { return uint64(3) },
		syncProvider,
		votingProvider,
		leaderProvider,
		livenessProvider,
		tracer{},
	)

	p, err := pacemaker.NewPacemaker[consensusData, vote, peerID, CollectedData](
		peerID{ID: nodeID},
		func() *models.LivenessState {
			return &models.LivenessState{
				Filter:                      nil,
				CurrentRank:                 0,
				LatestQuorumCertificate:     &quorumCertificate{},
				PriorRankTimeoutCertificate: nil,
			}
		},
		func() uint64 { return uint64(3) },
		votingProvider,
		leaderProvider,
		livenessProvider,
		sm,
		&store{},
		tracer{},
	)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	node := &ConsensusNode{
		p:                p,
		sm:               sm,
		nodeID:           nodeID,
		ctx:              ctx,
		cancel:           cancel,
		votingProvider:   votingProvider,
		livenessProvider: livenessProvider,
		isMalicious:      isMalicious,
	}

	// Add transition listener
	sm.AddListener(&NodeTransitionListener{
		node: node,
	})

	return node
}

type tracer struct {
}

// Error implements consensus.TraceLogger.
func (t tracer) Error(message string, err error) {
	fmt.Println(message, err)
}

// Trace implements consensus.TraceLogger.
func (t tracer) Trace(message string) {
	fmt.Println(message)
}

// Start begins the consensus node
func (n *ConsensusNode) Start() error {
	fmt.Printf("starting consensus node, node id: %s\n", n.nodeID)

	// Start monitoring for messages
	go n.monitor()

	return n.p.Start(n.ctx)
}

// Stop halts the consensus node
func (n *ConsensusNode) Stop() error {
	fmt.Printf("stopping consensus node, node id: %s\n", n.nodeID)
	n.cancel()
	return nil
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
	fmt.Printf(
		"received message, type: %s, from: %s\n",
		msg.Type,
		msg.Sender,
	)

	switch msg.Type {
	case "proposal":
		if proposal, ok := msg.Data.(*consensusData); ok {
			n.sm.ReceiveProposal(proposal.Round, peerID{ID: msg.Sender}, proposal)
		}
	case "vote":
		if vote, ok := msg.Data.(*vote); ok {
			n.sm.ReceiveVote(
				peerID{ID: vote.ProposerID},
				peerID{ID: msg.Sender},
				vote,
			)
		}
	case "liveness_check":
		if collected, ok := msg.Data.(CollectedData); ok {
			n.sm.ReceiveLivenessCheck(peerID{ID: msg.Sender}, collected)
		}
	case "confirmation":
		if confirmation, ok := msg.Data.(*consensusData); ok {
			n.sm.ReceiveConfirmation(peerID{ID: msg.Sender}, confirmation)
		}
	}
}

// NodeTransitionListener handles state transitions
type NodeTransitionListener struct {
	node *ConsensusNode
}

func (l *NodeTransitionListener) OnTransition(
	from consensus.State,
	to consensus.State,
	event consensus.Event,
) {
	fmt.Printf(
		"state transition, node id: %s, from: %s, to: %s, event: %s\n",
		l.node.nodeID,
		string(from),
		string(to),
		string(event),
	)

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
		fmt.Printf(
			"MALICIOUS NODE: Executing Byzantine behavior, node id: %s\n",
			l.node.nodeID,
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
			vt := &vote{
				NodeID:     l.node.nodeID,
				Round:      0, // Will be updated based on proposals
				VoteValue:  voteValues[i],
				Timestamp:  time.Now(),
				ProposerID: targetNode,
			}

			fmt.Printf(
				"MALICIOUS: Sending conflicting vote, node id: %s, target: %s, vote: %s\n",
				l.node.nodeID,
				targetNode,
				voteValues[i],
			)

			if i == 0 && l.node.messageBus != nil {
				// Make a copy to avoid sharing pointers
				voteCopy := &vote{
					NodeID:     vt.NodeID,
					Round:      vt.Round,
					VoteValue:  vt.VoteValue,
					Timestamp:  vt.Timestamp,
					ProposerID: vt.ProposerID,
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
		doubleVote := &vote{
			NodeID:     l.node.nodeID,
			Round:      0,
			VoteValue:  "approve",
			Timestamp:  time.Now(),
			ProposerID: nodes[0],
		}

		fmt.Printf(
			"MALICIOUS: Attempting double vote, node id: %s\n",
			l.node.nodeID,
		)

		l.node.sm.ReceiveVote(
			peerID{ID: nodes[0]},
			peerID{ID: l.node.nodeID},
			doubleVote,
		)

		if l.node.messageBus != nil {
			// Make a copy to avoid sharing pointers
			doubleVoteCopy := &vote{
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

	fmt.Printf(
		"entering voting state, node id: %s\n",
		l.node.nodeID,
	)
}

func (l *NodeTransitionListener) handleEnterCollecting() {
	fmt.Printf(
		"entered collecting state, node id: %s\n",
		l.node.nodeID,
	)

	// Reset vote handler for new round
	l.node.votingProvider.Reset()
}

func (l *NodeTransitionListener) handleEnterPublishing() {
	fmt.Printf(
		"entered publishing state, node id: %s\n",
		l.node.nodeID,
	)
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
	// Create message bus
	messageBus := NewMessageBus()

	// Create nodes (1 prover, 2 validators, 1 malicious validator)
	// Note: We need 4 nodes total with vote target of 3 to demonstrate Byzantine
	// fault tolerance
	nodes := []*ConsensusNode{
		NewConsensusNode("prover-node-1", true, 3),
		NewConsensusNode("validator-node-1", true, 3),
		NewConsensusNode("validator-node-2", true, 3),
		NewMaliciousNode("validator-node-3", false, 3),
	}

	// Connect nodes to message bus
	for _, node := range nodes {
		node.SetMessageBus(messageBus)
	}

	// Start all nodes
	fmt.Println("=== Starting Consensus Network with Generic State Machine ===")
	fmt.Println("Using the generic state machine from consensus package")
	fmt.Println("Network includes 1 MALICIOUS node (validator-node-3) demonstrating Byzantine behavior")

	for _, node := range nodes {
		if err := node.Start(); err != nil {
			fmt.Printf(
				"failed to start node, node id: %s, %v\n",
				node.nodeID,
				err,
			)
		}
	}

	// Run for a while
	time.Sleep(30 * time.Second)

	// Print statistics
	fmt.Println("=== Node Statistics ===")
	for _, node := range nodes {
		viz := consensus.NewStateMachineViz(node.sm)

		fmt.Printf("\nStats for %s:\n%s",
			node.nodeID,
			viz.GetStateStats())

		fmt.Printf(
			"final state, node id: %s, current state: %s, transition count: %s, malicious: %v\n",
			node.nodeID,
			string(node.sm.GetState()),
			node.sm.GetTransitionCount(),
			node.isMalicious,
		)
	}

	// Generate visualization
	if len(nodes) > 0 {
		viz := consensus.NewStateMachineViz(nodes[0].sm)
		fmt.Println("\nState Machine Diagram:\n" + viz.GenerateMermaidDiagram())
	}

	// Stop all nodes
	fmt.Println("=== Stopping Consensus Network ===")
	for _, node := range nodes {
		if err := node.Stop(); err != nil {
			fmt.Printf(
				"failed to stop node, node id: %s, %v\n",
				node.nodeID,
				err,
			)
		}
	}

	time.Sleep(2 * time.Second)
}
