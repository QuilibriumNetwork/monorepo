package intrinsics

import (
	"bytes"
	"math/big"

	"source.quilibrium.com/quilibrium/monorepo/types/execution/state"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
)

var GLOBAL_INTRINSIC_ADDRESS = [32]byte(bytes.Repeat([]byte{0xff}, 32))

type Intrinsic interface {
	// Gets the address of the intrinsic, either post-Deploy or if created via
	// the Load*Intrinsic method
	Address() []byte
	// Prepares an instance of the intrinsic to be deployed to the network,
	// returning the settled state to be accepted
	Deploy(
		domain [32]byte,
		provers [][]byte,
		creator []byte,
		fee *big.Int,
		contextData []byte,
		frameNumber uint64,
		state state.State,
	) (state.State, error)
	// Locks addresses for writing or reading
	Lock(writeAddresses [][]byte, readAddresses [][]byte) error
	// Unlocks addresses for writing or reading
	Unlock(writeAddresses [][]byte, readAddresses [][]byte) error
	// Performs strictly the validation of an intrinsic operation, encoded via
	// the ToBytes method of the given operation
	Validate(frameNumber uint64, input []byte) error
	// Performs an invocation of an intrinsic operation, encoded via the ToBytes
	// method of the given operation, and returns the settled state to be
	// accepted
	InvokeStep(
		frameNumber uint64,
		input []byte,
		feePaid *big.Int,
		feeMultiplier *big.Int,
		state state.State,
	) (state.State, error)
	// Performs a sum check (not applicable for this release)
	SumCheck() bool
	// Writes the state
	Commit() (state.State, error)
	// GetRDFSchema retrieves the RDF schema from the loaded intrinsic
	GetRDFSchema() (map[string]map[string]*schema.RDFTag, error)
}

// Describes an operation of an intrinsic
type IntrinsicOperation interface {
	// Retrieves the raw cost basis of the operation, to be scaled by dynamic fees
	GetCost() (*big.Int, error)
	// Performs proving over the operation
	Prove(frameNumber uint64) error
	// Verifies the proofs of the operation
	Verify(frameNumber uint64) (bool, error)
	// Returns the settled state from performing the operation
	Materialize(frameNumber uint64, state state.State) (state.State, error)
}
