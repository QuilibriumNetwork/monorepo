package integration

import (
	"time"

	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

func DefaultRoot() *models.State[*helper.TestState] {
	ts := uint64(time.Now().UnixMilli())
	id := helper.MakeIdentity()
	s := &helper.TestState{
		Rank:      0,
		Signature: make([]byte, 0),
		Timestamp: ts,
		ID:        id,
		Prover:    "",
	}
	header := &models.State[*helper.TestState]{
		Rank:       0,
		State:      &s,
		Identifier: id,
		Timestamp:  ts,
	}
	return header
}
