package integration

import (
	"errors"

	"source.quilibrium.com/quilibrium/monorepo/consensus"
	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
	"source.quilibrium.com/quilibrium/monorepo/consensus/pacemaker/timeout"
)

var errStopCondition = errors.New("stop condition reached")

type Option func(*Config)

type Config struct {
	Logger                consensus.TraceLogger
	Root                  *models.State[*helper.TestState]
	Participants          []models.WeightedIdentity
	LocalID               models.Identity
	Timeouts              timeout.Config
	IncomingVotes         VoteFilter
	OutgoingVotes         VoteFilter
	IncomingTimeoutStates TimeoutStateFilter
	OutgoingTimeoutStates TimeoutStateFilter
	IncomingProposals     ProposalFilter
	OutgoingProposals     ProposalFilter

	StopCondition Condition
}

func WithRoot(root *models.State[*helper.TestState]) Option {
	return func(cfg *Config) {
		cfg.Root = root
	}
}

func WithParticipants(participants []models.WeightedIdentity) Option {
	return func(cfg *Config) {
		cfg.Participants = participants
	}
}

func WithLocalID(localID models.Identity) Option {
	return func(cfg *Config) {
		cfg.LocalID = localID
		cfg.Logger = cfg.Logger.With(consensus.IdentityParam("self", localID))
	}
}

func WithTimeouts(timeouts timeout.Config) Option {
	return func(cfg *Config) {
		cfg.Timeouts = timeouts
	}
}

func WithBufferLogger() Option {
	return func(cfg *Config) {
		cfg.Logger = helper.BufferLogger()
	}
}

func WithLoggerParams(params ...consensus.LogParam) Option {
	return func(cfg *Config) {
		cfg.Logger = cfg.Logger.With(params...)
	}
}

func WithIncomingVotes(Filter VoteFilter) Option {
	return func(cfg *Config) {
		cfg.IncomingVotes = Filter
	}
}

func WithOutgoingVotes(Filter VoteFilter) Option {
	return func(cfg *Config) {
		cfg.OutgoingVotes = Filter
	}
}

func WithIncomingProposals(Filter ProposalFilter) Option {
	return func(cfg *Config) {
		cfg.IncomingProposals = Filter
	}
}

func WithOutgoingProposals(Filter ProposalFilter) Option {
	return func(cfg *Config) {
		cfg.OutgoingProposals = Filter
	}
}

func WithIncomingTimeoutStates(Filter TimeoutStateFilter) Option {
	return func(cfg *Config) {
		cfg.IncomingTimeoutStates = Filter
	}
}

func WithOutgoingTimeoutStates(Filter TimeoutStateFilter) Option {
	return func(cfg *Config) {
		cfg.OutgoingTimeoutStates = Filter
	}
}

func WithStopCondition(stop Condition) Option {
	return func(cfg *Config) {
		cfg.StopCondition = stop
	}
}
