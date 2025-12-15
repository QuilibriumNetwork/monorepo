package helper

import (
	crand "crypto/rand"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

type TestWeightedIdentity struct {
	ID string
}

// Identity implements models.WeightedIdentity.
func (t *TestWeightedIdentity) Identity() models.Identity {
	return t.ID
}

// PublicKey implements models.WeightedIdentity.
func (t *TestWeightedIdentity) PublicKey() []byte {
	return make([]byte, 585)
}

// Weight implements models.WeightedIdentity.
func (t *TestWeightedIdentity) Weight() uint64 {
	return 1000
}

var _ models.WeightedIdentity = (*TestWeightedIdentity)(nil)

type TestState struct {
	Rank      uint64
	Signature []byte
	Timestamp uint64
	ID        models.Identity
	Prover    models.Identity
}

// Clone implements models.Unique.
func (t *TestState) Clone() models.Unique {
	return &TestState{
		Rank:      t.Rank,
		Signature: slices.Clone(t.Signature),
		Timestamp: t.Timestamp,
		ID:        t.ID,
		Prover:    t.Prover,
	}
}

// GetRank implements models.Unique.
func (t *TestState) GetRank() uint64 {
	return t.Rank
}

// GetSignature implements models.Unique.
func (t *TestState) GetSignature() []byte {
	return t.Signature
}

// GetTimestamp implements models.Unique.
func (t *TestState) GetTimestamp() uint64 {
	return t.Timestamp
}

// Identity implements models.Unique.
func (t *TestState) Identity() models.Identity {
	return t.ID
}

// Source implements models.Unique.
func (t *TestState) Source() models.Identity {
	return t.Prover
}

type TestVote struct {
	Rank      uint64
	Signature []byte
	Timestamp uint64
	ID        models.Identity
	StateID   models.Identity
}

// Clone implements models.Unique.
func (t *TestVote) Clone() models.Unique {
	return &TestVote{
		Rank:      t.Rank,
		Signature: slices.Clone(t.Signature),
		Timestamp: t.Timestamp,
		ID:        t.ID,
		StateID:   t.StateID,
	}
}

// GetRank implements models.Unique.
func (t *TestVote) GetRank() uint64 {
	return t.Rank
}

// GetSignature implements models.Unique.
func (t *TestVote) GetSignature() []byte {
	return t.Signature
}

// GetTimestamp implements models.Unique.
func (t *TestVote) GetTimestamp() uint64 {
	return t.Timestamp
}

// Identity implements models.Unique.
func (t *TestVote) Identity() models.Identity {
	return t.ID
}

// Source implements models.Unique.
func (t *TestVote) Source() models.Identity {
	return t.StateID
}

type TestPeer struct {
	PeerID string
}

// Clone implements models.Unique.
func (t *TestPeer) Clone() models.Unique {
	return &TestPeer{
		PeerID: t.PeerID,
	}
}

// GetRank implements models.Unique.
func (t *TestPeer) GetRank() uint64 {
	return 0
}

// GetSignature implements models.Unique.
func (t *TestPeer) GetSignature() []byte {
	return []byte{}
}

// GetTimestamp implements models.Unique.
func (t *TestPeer) GetTimestamp() uint64 {
	return 0
}

// Identity implements models.Unique.
func (t *TestPeer) Identity() models.Identity {
	return t.PeerID
}

// Source implements models.Unique.
func (t *TestPeer) Source() models.Identity {
	return t.PeerID
}

type TestCollected struct {
	Rank uint64
	TXs  [][]byte
}

// Clone implements models.Unique.
func (t *TestCollected) Clone() models.Unique {
	return &TestCollected{
		Rank: t.Rank,
		TXs:  slices.Clone(t.TXs),
	}
}

// GetRank implements models.Unique.
func (t *TestCollected) GetRank() uint64 {
	return t.Rank
}

// GetSignature implements models.Unique.
func (t *TestCollected) GetSignature() []byte {
	return []byte{}
}

// GetTimestamp implements models.Unique.
func (t *TestCollected) GetTimestamp() uint64 {
	return 0
}

// Identity implements models.Unique.
func (t *TestCollected) Identity() models.Identity {
	return fmt.Sprintf("%d", t.Rank)
}

// Source implements models.Unique.
func (t *TestCollected) Source() models.Identity {
	return ""
}

var _ models.Unique = (*TestState)(nil)
var _ models.Unique = (*TestVote)(nil)
var _ models.Unique = (*TestPeer)(nil)
var _ models.Unique = (*TestCollected)(nil)

func MakeIdentity() models.Identity {
	s := make([]byte, 32)
	crand.Read(s)
	return models.Identity(s)
}

func MakeState[StateT models.Unique](options ...func(*models.State[StateT])) *models.State[StateT] {
	rank := rand.Uint64()

	state := models.State[StateT]{
		Rank:                    rank,
		Identifier:              MakeIdentity(),
		ProposerID:              MakeIdentity(),
		Timestamp:               uint64(time.Now().UnixMilli()),
		ParentQuorumCertificate: MakeQC(WithQCRank(rank - 1)),
	}
	for _, option := range options {
		option(&state)
	}
	return &state
}

func WithStateRank[StateT models.Unique](rank uint64) func(*models.State[StateT]) {
	return func(state *models.State[StateT]) {
		state.Rank = rank
	}
}

func WithStateProposer[StateT models.Unique](proposerID models.Identity) func(*models.State[StateT]) {
	return func(state *models.State[StateT]) {
		state.ProposerID = proposerID
	}
}

func WithParentState[StateT models.Unique](parent *models.State[StateT]) func(*models.State[StateT]) {
	return func(state *models.State[StateT]) {
		state.ParentQuorumCertificate.(*TestQuorumCertificate).Selector = parent.Identifier
		state.ParentQuorumCertificate.(*TestQuorumCertificate).Rank = parent.Rank
	}
}

func WithParentSigners[StateT models.Unique](signerIndices []byte) func(*models.State[StateT]) {
	return func(state *models.State[StateT]) {
		state.ParentQuorumCertificate.(*TestQuorumCertificate).AggregatedSignature.(*TestAggregatedSignature).Bitmask = signerIndices // buildutils:allow-slice-alias
	}
}

func WithStateQC[StateT models.Unique](qc models.QuorumCertificate) func(*models.State[StateT]) {
	return func(state *models.State[StateT]) {
		state.ParentQuorumCertificate = qc
	}
}

func MakeVote[VoteT models.Unique]() *VoteT {
	return new(VoteT)
}

func MakeSignedProposal[StateT models.Unique, VoteT models.Unique](options ...func(*models.SignedProposal[StateT, VoteT])) *models.SignedProposal[StateT, VoteT] {
	proposal := &models.SignedProposal[StateT, VoteT]{
		Proposal: *MakeProposal[StateT](),
		Vote:     MakeVote[VoteT](),
	}
	for _, option := range options {
		option(proposal)
	}
	return proposal
}

func MakeProposal[StateT models.Unique](options ...func(*models.Proposal[StateT])) *models.Proposal[StateT] {
	proposal := &models.Proposal[StateT]{
		State:                          MakeState[StateT](),
		PreviousRankTimeoutCertificate: nil,
	}
	for _, option := range options {
		option(proposal)
	}
	return proposal
}

func WithProposal[StateT models.Unique, VoteT models.Unique](proposal *models.Proposal[StateT]) func(*models.SignedProposal[StateT, VoteT]) {
	return func(signedProposal *models.SignedProposal[StateT, VoteT]) {
		signedProposal.Proposal = *proposal
	}
}

func WithState[StateT models.Unique](state *models.State[StateT]) func(*models.Proposal[StateT]) {
	return func(proposal *models.Proposal[StateT]) {
		proposal.State = state
	}
}

func WithVote[StateT models.Unique, VoteT models.Unique](vote *VoteT) func(*models.SignedProposal[StateT, VoteT]) {
	return func(proposal *models.SignedProposal[StateT, VoteT]) {
		proposal.Vote = vote
	}
}

func WithPreviousRankTimeoutCertificate[StateT models.Unique](previousRankTimeoutCert models.TimeoutCertificate) func(*models.Proposal[StateT]) {
	return func(proposal *models.Proposal[StateT]) {
		proposal.PreviousRankTimeoutCertificate = previousRankTimeoutCert
	}
}

func WithWeightedIdentityList(count int) []models.WeightedIdentity {
	wi := []models.WeightedIdentity{}
	for range count {
		wi = append(wi, &TestWeightedIdentity{
			ID: MakeIdentity(),
		})
	}
	return wi
}

func VoteForStateFixture(state *models.State[*TestState], ops ...func(vote **TestVote)) *TestVote {
	v := &TestVote{
		Rank:      state.Rank,
		ID:        MakeIdentity(),
		StateID:   state.Identifier,
		Signature: make([]byte, 74),
	}
	for _, op := range ops {
		op(&v)
	}
	return v
}

func VoteFixture(op func(vote **TestVote)) *TestVote {
	v := &TestVote{
		Rank:      rand.Uint64(),
		ID:        MakeIdentity(),
		StateID:   MakeIdentity(),
		Signature: make([]byte, 74),
	}
	op(&v)
	return v
}

type FmtLog struct {
	params []consensus.LogParam
}

// Error implements consensus.TraceLogger.
func (n *FmtLog) Error(message string, err error, params ...consensus.LogParam) {
	b := strings.Builder{}
	b.WriteString(fmt.Sprintf("ERROR: %s: %v\n", message, err))
	for _, param := range n.params {
		b.WriteString(fmt.Sprintf(
			"\t%s: %s\n",
			param.GetKey(),
			stringFromValue(param),
		))
	}
	for _, param := range params {
		b.WriteString(fmt.Sprintf(
			"\t%s: %s\n",
			param.GetKey(),
			stringFromValue(param),
		))
	}
	fmt.Println(b.String())
}

// Trace implements consensus.TraceLogger.
func (n *FmtLog) Trace(message string, params ...consensus.LogParam) {
	b := strings.Builder{}
	b.WriteString(fmt.Sprintf("TRACE: %s\n", message))
	b.WriteString(fmt.Sprintf("\t[%s]\n", time.Now().String()))
	for _, param := range n.params {
		b.WriteString(fmt.Sprintf(
			"\t%s: %s\n",
			param.GetKey(),
			stringFromValue(param),
		))
	}
	for _, param := range params {
		b.WriteString(fmt.Sprintf(
			"\t%s: %s\n",
			param.GetKey(),
			stringFromValue(param),
		))
	}
	fmt.Println(b.String())
}

func (n *FmtLog) With(params ...consensus.LogParam) consensus.TraceLogger {
	return &FmtLog{
		params: slices.Concat(n.params, params),
	}
}

func stringFromValue(param consensus.LogParam) string {
	switch param.GetKind() {
	case "string":
		return param.GetValue().(string)
	case "time":
		return param.GetValue().(time.Time).String()
	default:
		return fmt.Sprintf("%v", param.GetValue())
	}
}

func Logger() *FmtLog {
	return &FmtLog{}
}

type BufferLog struct {
	params []consensus.LogParam
	b      *strings.Builder
}

// Error implements consensus.TraceLogger.
func (n *BufferLog) Error(message string, err error, params ...consensus.LogParam) {
	n.b.WriteString(fmt.Sprintf("ERROR: %s: %v\n", message, err))
	for _, param := range n.params {
		n.b.WriteString(fmt.Sprintf(
			"\t%s: %s\n",
			param.GetKey(),
			stringFromValue(param),
		))
	}
	for _, param := range params {
		n.b.WriteString(fmt.Sprintf(
			"\t%s: %s\n",
			param.GetKey(),
			stringFromValue(param),
		))
	}
}

// Trace implements consensus.TraceLogger.
func (n *BufferLog) Trace(message string, params ...consensus.LogParam) {
	n.b.WriteString(fmt.Sprintf("TRACE: %s\n", message))
	n.b.WriteString(fmt.Sprintf("\t[%s]\n", time.Now().String()))
	for _, param := range n.params {
		n.b.WriteString(fmt.Sprintf(
			"\t%s: %s\n",
			param.GetKey(),
			stringFromValue(param),
		))
	}
	for _, param := range params {
		n.b.WriteString(fmt.Sprintf(
			"\t%s: %s\n",
			param.GetKey(),
			stringFromValue(param),
		))
	}
}

func (n *BufferLog) Flush() {
	fmt.Println(n.b.String())
}

func (n *BufferLog) With(params ...consensus.LogParam) consensus.TraceLogger {
	return &BufferLog{
		params: slices.Concat(n.params, params),
		b:      n.b,
	}
}

func BufferLogger() *BufferLog {
	return &BufferLog{
		b: &strings.Builder{},
	}
}
