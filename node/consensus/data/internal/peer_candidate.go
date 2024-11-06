package internal

// PeerCandidate is a candidate for a peer to be used for syncing.
type PeerCandidate struct {
	PeerID   []byte
	MaxFrame uint64
}

// WeightedPeerCandidate is a weighted peer candidate.
type WeightedPeerCandidate struct {
	PeerCandidate
	Weight float64
}

var _ Weighted[PeerCandidate] = (*WeightedPeerCandidate)(nil)

// GetItem implements Weighted[PeerCandidate].
func (p WeightedPeerCandidate) GetItem() PeerCandidate {
	return p.PeerCandidate
}

// GetWeight implements Weighted[PeerCandidate].
func (p WeightedPeerCandidate) GetWeight() float64 {
	return p.Weight
}
