package time_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

func TestMasterTimeReel(t *testing.T) {
	ctx := context.Background()
	logger, _ := zap.NewProduction()
	db := store.NewInMemKVDB()
	clockStore := store.NewPebbleClockStore(db, logger)
	prover := crypto.NewWesolowskiFrameProver(logger)
	filter := "0000000000000000000000000000000000000000000000000000000000000000"

	m := time.NewMasterTimeReel(
		logger,
		clockStore,
		&config.EngineConfig{
			Filter:      filter,
			GenesisSeed: strings.Repeat("00", 516),
			Difficulty:  10,
		},
		prover,
	)

	err := m.Start()
	assert.NoError(t, err)

	frame, err := m.Head()
	assert.NoError(t, err)

	frames := []*protobufs.ClockFrame{}
	wg := sync.WaitGroup{}
	wg.Add(1)
	frameCh := m.NewFrameCh()
	go func() {
		for i := 0; i < 200; i++ {
			frames = append(frames, <-frameCh)
		}
		wg.Done()
	}()

	// in order
	for i := int64(0); i < 100; i++ {
		frame, err = prover.ProveMasterClockFrame(
			frame,
			i+1,
			10,
			[]*protobufs.InclusionAggregateProof{},
		)
		assert.NoError(t, err)

		_, err := m.Insert(ctx, frame)
		assert.NoError(t, err)
	}

	insertFrames := []*protobufs.ClockFrame{}

	// reverse order
	for i := int64(100); i < 200; i++ {
		frame, err = prover.ProveMasterClockFrame(
			frame,
			i+1,
			10,
			[]*protobufs.InclusionAggregateProof{},
		)
		assert.NoError(t, err)

		insertFrames = append(insertFrames, frame)
	}

	for i := 99; i >= 0; i-- {
		_, err := m.Insert(ctx, insertFrames[i])
		assert.NoError(t, err)
	}

	wg.Wait()

	for i := 0; i < 200; i++ {
		assert.NotNil(t, frames[i])
		assert.Equal(t, frames[i].FrameNumber, uint64(i+1))
	}
}
