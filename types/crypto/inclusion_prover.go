package crypto

type InclusionCommitment struct {
	TypeUrl    string
	Data       []byte
	Commitment []byte
}

type InclusionAggregateProof struct {
	InclusionCommitments []*InclusionCommitment
	AggregateCommitment  []byte
	Proof                []byte
}

type Multiproof interface {
	GetMulticommitment() []byte
	GetProof() []byte
	ToBytes() ([]byte, error)
	FromBytes([]byte) error
}

type InclusionProver interface {
	CommitRaw(
		data []byte,
		polySize uint64,
	) ([]byte, error)
	ProveRaw(
		data []byte,
		index int,
		polySize uint64,
	) ([]byte, error)
	VerifyRaw(
		data []byte,
		commit []byte,
		index uint64,
		proof []byte,
		polySize uint64,
	) (bool, error)
	ProveMultiple(
		commitments [][]byte,
		polys [][]byte,
		indices []uint64,
		polySize uint64,
	) Multiproof
	VerifyMultiple(
		commitments [][]byte,
		evaluations [][]byte,
		indices []uint64,
		polySize uint64,
		multiCommitment []byte,
		proof []byte,
	) bool
	NewMultiproof() Multiproof
}
