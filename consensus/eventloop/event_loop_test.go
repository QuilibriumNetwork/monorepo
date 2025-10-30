package eventloop

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/atomic"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/mocks"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

// TestEventLoop performs unit testing of event loop, checks if submitted events are propagated
// to event handler as well as handling of timeouts.
func TestEventLoop(t *testing.T) {
	suite.Run(t, new(EventLoopTestSuite))
}

type EventLoopTestSuite struct {
	suite.Suite

	eh     *mocks.EventHandler[*helper.TestState, *helper.TestVote]
	cancel context.CancelFunc

	eventLoop *EventLoop[*helper.TestState, *helper.TestVote]
}

func (s *EventLoopTestSuite) SetupTest() {
	s.eh = mocks.NewEventHandler[*helper.TestState, *helper.TestVote](s.T())
	s.eh.On("Start", mock.Anything).Return(nil).Maybe()
	s.eh.On("TimeoutChannel").Return(make(<-chan time.Time, 1)).Maybe()
	s.eh.On("OnLocalTimeout").Return(nil).Maybe()

	eventLoop, err := NewEventLoop(helper.Logger(), s.eh, time.Time{})
	require.NoError(s.T(), err)
	s.eventLoop = eventLoop

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	signalerCtx := ctx

	s.eventLoop.Start(signalerCtx)
}

func (s *EventLoopTestSuite) TearDownTest() {
	s.cancel()
}

// TestReadyDone tests if event loop stops internal worker thread
func (s *EventLoopTestSuite) TestReadyDone() {
	time.Sleep(1 * time.Second)
	go func() {
		s.cancel()
	}()
}

// Test_SubmitQC tests that submitted proposal is eventually sent to event handler for processing
func (s *EventLoopTestSuite) Test_SubmitProposal() {
	proposal := helper.MakeSignedProposal[*helper.TestState, *helper.TestVote]()
	processed := atomic.NewBool(false)
	s.eh.On("OnReceiveProposal", proposal).Run(func(args mock.Arguments) {
		processed.Store(true)
	}).Return(nil).Once()
	s.eventLoop.SubmitProposal(proposal)
	require.Eventually(s.T(), processed.Load, time.Millisecond*100, time.Millisecond*10)
}

// Test_SubmitQC tests that submitted QC is eventually sent to `EventHandler.OnReceiveQuorumCertificate` for processing
func (s *EventLoopTestSuite) Test_SubmitQC() {
	// qcIngestionFunction is the archetype for EventLoop.OnQuorumCertificateConstructedFromVotes and EventLoop.OnNewQuorumCertificateDiscovered
	type qcIngestionFunction func(models.QuorumCertificate)

	testQCIngestionFunction := func(f qcIngestionFunction, qcRank uint64) {
		qc := helper.MakeQC(helper.WithQCRank(qcRank))
		processed := atomic.NewBool(false)
		s.eh.On("OnReceiveQuorumCertificate", qc).Run(func(args mock.Arguments) {
			processed.Store(true)
		}).Return(nil).Once()
		f(qc)
		require.Eventually(s.T(), processed.Load, time.Millisecond*100, time.Millisecond*10)
	}

	s.Run("QCs handed to EventLoop.OnQuorumCertificateConstructedFromVotes are forwarded to EventHandler", func() {
		testQCIngestionFunction(s.eventLoop.OnQuorumCertificateConstructedFromVotes, 100)
	})

	s.Run("QCs handed to EventLoop.OnNewQuorumCertificateDiscovered are forwarded to EventHandler", func() {
		testQCIngestionFunction(s.eventLoop.OnNewQuorumCertificateDiscovered, 101)
	})
}

// Test_SubmitTC tests that submitted TC is eventually sent to `EventHandler.OnReceiveTimeoutCertificate` for processing
func (s *EventLoopTestSuite) Test_SubmitTC() {
	// tcIngestionFunction is the archetype for EventLoop.OnTimeoutCertificateConstructedFromTimeouts and EventLoop.OnNewTimeoutCertificateDiscovered
	type tcIngestionFunction func(models.TimeoutCertificate)

	testTCIngestionFunction := func(f tcIngestionFunction, tcRank uint64) {
		tc := helper.MakeTC(helper.WithTCRank(tcRank))
		processed := atomic.NewBool(false)
		s.eh.On("OnReceiveTimeoutCertificate", tc).Run(func(args mock.Arguments) {
			processed.Store(true)
		}).Return(nil).Once()
		f(tc)
		require.Eventually(s.T(), processed.Load, time.Millisecond*100, time.Millisecond*10)
	}

	s.Run("TCs handed to EventLoop.OnTimeoutCertificateConstructedFromTimeouts are forwarded to EventHandler", func() {
		testTCIngestionFunction(s.eventLoop.OnTimeoutCertificateConstructedFromTimeouts, 100)
	})

	s.Run("TCs handed to EventLoop.OnNewTimeoutCertificateDiscovered are forwarded to EventHandler", func() {
		testTCIngestionFunction(s.eventLoop.OnNewTimeoutCertificateDiscovered, 101)
	})
}

// Test_SubmitTC_IngestNewestQC tests that included QC in TC is eventually sent to `EventHandler.OnReceiveQuorumCertificate` for processing
func (s *EventLoopTestSuite) Test_SubmitTC_IngestNewestQC() {
	// tcIngestionFunction is the archetype for EventLoop.OnTimeoutCertificateConstructedFromTimeouts and EventLoop.OnNewTimeoutCertificateDiscovered
	type tcIngestionFunction func(models.TimeoutCertificate)

	testTCIngestionFunction := func(f tcIngestionFunction, tcRank, qcRank uint64) {
		tc := helper.MakeTC(helper.WithTCRank(tcRank),
			helper.WithTCNewestQC(helper.MakeQC(helper.WithQCRank(qcRank))))
		processed := atomic.NewBool(false)
		s.eh.On("OnReceiveQuorumCertificate", tc.GetLatestQuorumCert()).Run(func(args mock.Arguments) {
			processed.Store(true)
		}).Return(nil).Once()
		f(tc)
		require.Eventually(s.T(), processed.Load, time.Millisecond*100, time.Millisecond*10)
	}

	// process initial TC, this will track the newest TC
	s.eh.On("OnReceiveTimeoutCertificate", mock.Anything).Return(nil).Once()
	s.eventLoop.OnTimeoutCertificateConstructedFromTimeouts(helper.MakeTC(
		helper.WithTCRank(100),
		helper.WithTCNewestQC(
			helper.MakeQC(
				helper.WithQCRank(80),
			),
		),
	))

	s.Run("QCs handed to EventLoop.OnTimeoutCertificateConstructedFromTimeouts are forwarded to EventHandler", func() {
		testTCIngestionFunction(s.eventLoop.OnTimeoutCertificateConstructedFromTimeouts, 100, 99)
	})

	s.Run("QCs handed to EventLoop.OnNewTimeoutCertificateDiscovered are forwarded to EventHandler", func() {
		testTCIngestionFunction(s.eventLoop.OnNewTimeoutCertificateDiscovered, 100, 100)
	})
}

// Test_OnPartialTimeoutCertificateCreated tests that event loop delivers partialTimeoutCertificateCreated events to event handler.
func (s *EventLoopTestSuite) Test_OnPartialTimeoutCertificateCreated() {
	rank := uint64(1000)
	newestQC := helper.MakeQC(helper.WithQCRank(rank - 10))
	previousRankTimeoutCert := helper.MakeTC(helper.WithTCRank(rank-1), helper.WithTCNewestQC(newestQC))

	processed := atomic.NewBool(false)
	partialTimeoutCertificateCreated := &consensus.PartialTimeoutCertificateCreated{
		Rank:                        rank,
		NewestQuorumCertificate:     newestQC,
		PriorRankTimeoutCertificate: previousRankTimeoutCert,
	}
	s.eh.On("OnPartialTimeoutCertificateCreated", partialTimeoutCertificateCreated).Run(func(args mock.Arguments) {
		processed.Store(true)
	}).Return(nil).Once()
	s.eventLoop.OnPartialTimeoutCertificateCreated(rank, newestQC, previousRankTimeoutCert)
	require.Eventually(s.T(), processed.Load, time.Millisecond*100, time.Millisecond*10)
}

// TestEventLoop_Timeout tests that event loop delivers timeout events to event handler under pressure
func TestEventLoop_Timeout(t *testing.T) {
	eh := &mocks.EventHandler[*helper.TestState, *helper.TestVote]{}
	processed := atomic.NewBool(false)
	eh.On("Start", mock.Anything).Return(nil).Once()
	eh.On("OnReceiveQuorumCertificate", mock.Anything).Return(nil).Maybe()
	eh.On("OnReceiveProposal", mock.Anything).Return(nil).Maybe()
	eh.On("OnLocalTimeout").Run(func(args mock.Arguments) {
		processed.Store(true)
	}).Return(nil).Once()

	eventLoop, err := NewEventLoop(helper.Logger(), eh, time.Time{})
	require.NoError(t, err)

	eh.On("TimeoutChannel").Return(time.After(100 * time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	signalerCtx := ctx
	eventLoop.Start(signalerCtx)

	time.Sleep(10 * time.Millisecond)

	var wg sync.WaitGroup
	wg.Add(2)

	// spam with proposals and QCs
	go func() {
		defer wg.Done()
		for !processed.Load() {
			qc := helper.MakeQC()
			eventLoop.OnQuorumCertificateConstructedFromVotes(qc)
		}
	}()

	go func() {
		defer wg.Done()
		for !processed.Load() {
			eventLoop.SubmitProposal(helper.MakeSignedProposal[*helper.TestState, *helper.TestVote]())
		}
	}()

	require.Eventually(t, processed.Load, time.Millisecond*200, time.Millisecond*10)

	cancel()
}

// TestReadyDoneWithStartTime tests that event loop correctly starts and schedules start of processing
// when startTime argument is used
func TestReadyDoneWithStartTime(t *testing.T) {
	eh := &mocks.EventHandler[*helper.TestState, *helper.TestVote]{}
	eh.On("Start", mock.Anything).Return(nil)
	eh.On("TimeoutChannel").Return(make(<-chan time.Time, 1))
	eh.On("OnLocalTimeout").Return(nil)

	startTimeDuration := 2 * time.Second
	startTime := time.Now().Add(startTimeDuration)
	eventLoop, err := NewEventLoop(helper.Logger(), eh, startTime)
	require.NoError(t, err)

	done := make(chan struct{})
	eh.On("OnReceiveProposal", mock.AnythingOfType("*models.SignedProposal")).Run(func(args mock.Arguments) {
		require.True(t, time.Now().After(startTime))
		close(done)
	}).Return(nil).Once()

	ctx, cancel := context.WithCancel(context.Background())
	signalerCtx := ctx
	eventLoop.Start(signalerCtx)

	eventLoop.SubmitProposal(helper.MakeSignedProposal[*helper.TestState, *helper.TestVote]())

	cancel()
}
