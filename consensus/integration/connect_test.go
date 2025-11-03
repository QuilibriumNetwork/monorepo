package integration

import (
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/consensus/helper"
	"source.quilibrium.com/quilibrium/monorepo/consensus/models"
)

func Connect(t *testing.T, instances []*Instance) {

	// first, create a map of all instances and a queue for each
	lookup := make(map[models.Identity]*Instance)
	for _, in := range instances {
		lookup[in.localID] = in
	}

	// then, for each instance, initialize a wired up communicator
	for _, sender := range instances {
		sender := sender // avoid capturing loop variable in closure

		*sender.notifier = *NewMockedCommunicatorConsumer()
		sender.notifier.CommunicatorConsumer.On("OnOwnProposal", mock.Anything, mock.Anything).Run(
			func(args mock.Arguments) {
				proposal, ok := args[0].(*models.SignedProposal[*helper.TestState, *helper.TestVote])
				require.True(t, ok)
				// sender should always have the parent
				sender.updatingStates.RLock()
				_, exists := sender.headers[proposal.State.ParentQuorumCertificate.Identity()]
				sender.updatingStates.RUnlock()
				if !exists {
					t.Fatalf("parent for proposal not found (sender: %x, parent: %x)", sender.localID, proposal.State.ParentQuorumCertificate.Identity())
				}

				// store locally and loop back to engine for processing
				sender.ProcessState(proposal)

				// check if we should drop the outgoing proposal
				if sender.dropPropOut(proposal) {
					return
				}

				// iterate through potential receivers
				for _, receiver := range instances {
					// we should skip ourselves always
					if receiver.localID == sender.localID {
						continue
					}

					// check if we should drop the incoming proposal
					if receiver.dropPropIn(proposal) {
						continue
					}

					receiver.ProcessState(proposal)
				}
			},
		)
		sender.notifier.CommunicatorConsumer.On("OnOwnVote", mock.Anything, mock.Anything).Run(
			func(args mock.Arguments) {
				vote, ok := args[0].(**helper.TestVote)
				require.True(t, ok)
				recipientID, ok := args[1].(models.Identity)
				require.True(t, ok)
				// get the receiver
				receiver, exists := lookup[recipientID]
				if !exists {
					t.Fatalf("recipient doesn't exist (sender: %x, receiver: %x)", sender.localID, recipientID)
				}
				// if we are next leader we should be receiving our own vote
				if recipientID != sender.localID {
					// check if we should drop the outgoing vote
					if sender.dropVoteOut(*vote) {
						return
					}
					// check if we should drop the incoming vote
					if receiver.dropVoteIn(*vote) {
						return
					}
				}

				// submit the vote to the receiving event loop (non-dropping)
				receiver.queue <- *vote
			},
		)
		sender.notifier.CommunicatorConsumer.On("OnOwnTimeout", mock.Anything).Run(
			func(args mock.Arguments) {
				timeoutState, ok := args[0].(*models.TimeoutState[*helper.TestVote])
				require.True(t, ok)
				// iterate through potential receivers
				for _, receiver := range instances {

					// we should skip ourselves always
					if receiver.localID == sender.localID {
						continue
					}

					// check if we should drop the outgoing value
					if sender.dropTimeoutStateOut(timeoutState) {
						continue
					}

					// check if we should drop the incoming value
					if receiver.dropTimeoutStateIn(timeoutState) {
						continue
					}

					receiver.queue <- timeoutState
				}
			})
	}
}
