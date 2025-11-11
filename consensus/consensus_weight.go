package consensus

// WeightProvider defines the methods for handling weighted differentiation of
// voters, such as seniority, or stake.
type WeightProvider interface {
	// GetWeightForBitmask returns the total weight of the given bitmask for the
	// prover set under the filter. Bitmask is expected to be in ascending ring
	// order.
	GetWeightForBitmask(filter []byte, bitmask []byte) uint64
}
