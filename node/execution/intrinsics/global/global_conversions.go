package global

import (
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/schema"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
	"source.quilibrium.com/quilibrium/monorepo/types/tries"
)

// FromProtobuf converts a protobuf BLS48581G2PublicKey to raw bytes
func BLS48581G2PublicKeyFromProtobuf(pb *protobufs.BLS48581G2PublicKey) []byte {
	if pb == nil {
		return nil
	}
	return pb.KeyValue
}

// ToProtobuf converts raw bytes to a protobuf BLS48581G2PublicKey
func BLS48581G2PublicKeyToProtobuf(
	keyValue []byte,
) *protobufs.BLS48581G2PublicKey {
	if keyValue == nil {
		return nil
	}
	return &protobufs.BLS48581G2PublicKey{
		KeyValue: keyValue,
	}
}

// FromProtobuf converts a protobuf BLS48581SignatureWithProofOfPossession to
// intrinsics
func BLS48581SignatureWithProofOfPossessionFromProtobuf(
	pb *protobufs.BLS48581SignatureWithProofOfPossession,
) (*BLS48581SignatureWithProofOfPossession, error) {
	if pb == nil {
		return nil, nil
	}

	// Validate field lengths
	publicKey := BLS48581G2PublicKeyFromProtobuf(pb.PublicKey)
	if len(publicKey) != 585 {
		return nil, errors.Errorf(
			"invalid public key length: expected 585, got %d",
			len(publicKey),
		)
	}
	if len(pb.Signature) != 74 {
		return nil, errors.Errorf(
			"invalid signature length: expected 74, got %d",
			len(pb.Signature),
		)
	}
	if len(pb.PopSignature) != 74 {
		return nil, errors.Errorf(
			"invalid pop signature length: expected 74, got %d",
			len(pb.PopSignature),
		)
	}

	return &BLS48581SignatureWithProofOfPossession{
		PublicKey:    publicKey,
		Signature:    pb.Signature,
		PopSignature: pb.PopSignature,
	}, nil
}

// ToProtobuf converts an intrinsics BLS48581SignatureWithProofOfPossession to
// protobuf
func (
	s *BLS48581SignatureWithProofOfPossession,
) ToProtobuf() *protobufs.BLS48581SignatureWithProofOfPossession {
	if s == nil {
		return nil
	}

	return &protobufs.BLS48581SignatureWithProofOfPossession{
		Signature:    s.Signature,
		PublicKey:    BLS48581G2PublicKeyToProtobuf(s.PublicKey),
		PopSignature: s.PopSignature,
	}
}

// FromProtobuf converts a protobuf BLS48581AddressedSignature to intrinsics
func BLS48581AddressedSignatureFromProtobuf(
	pb *protobufs.BLS48581AddressedSignature,
) (*BLS48581AddressedSignature, error) {
	if pb == nil {
		return nil, nil
	}

	return &BLS48581AddressedSignature{
		Address:   pb.Address,
		Signature: pb.Signature,
	}, nil
}

// ToProtobuf converts an intrinsics BLS48581AddressedSignature to protobuf
func (
	s *BLS48581AddressedSignature,
) ToProtobuf() *protobufs.BLS48581AddressedSignature {
	if s == nil {
		return nil
	}

	return &protobufs.BLS48581AddressedSignature{
		Signature: s.Signature,
		Address:   s.Address,
	}
}

// FromProtobuf converts a protobuf SeniorityMerge to intrinsics
func SeniorityMergeFromProtobuf(pb *protobufs.SeniorityMerge) (
	*SeniorityMerge,
	error,
) {
	if pb == nil {
		return nil, nil
	}

	return &SeniorityMerge{
		KeyType:   crypto.KeyType(pb.KeyType),
		PublicKey: pb.ProverPublicKey,
		Signature: pb.Signature,
	}, nil
}

// ToProtobuf converts an intrinsics SeniorityMerge to protobuf
func (s *SeniorityMerge) ToProtobuf() *protobufs.SeniorityMerge {
	if s == nil {
		return nil
	}

	return &protobufs.SeniorityMerge{
		Signature:       s.Signature,
		KeyType:         uint32(s.KeyType),
		ProverPublicKey: s.PublicKey,
	}
}

// FromProtobuf converts a protobuf ProverJoin to intrinsics ProverJoin
func ProverJoinFromProtobuf(
	pb *protobufs.ProverJoin,
	hg hypergraph.Hypergraph,
	signer crypto.Signer,
	inclusionProver crypto.InclusionProver,
	keyManager keys.KeyManager,
	frameProver crypto.FrameProver,
	frameStore store.ClockStore,
) (*ProverJoin, error) {
	if pb == nil {
		return nil, nil
	}

	// Convert PublicKeySignatureBls48581
	pubKeySig, err := BLS48581SignatureWithProofOfPossessionFromProtobuf(
		pb.PublicKeySignatureBls48581,
	)
	if err != nil {
		return nil, errors.Wrap(err, "converting public key signature")
	}

	// Convert MergeTargets
	var mergeTargets []*SeniorityMerge
	if len(pb.MergeTargets) > 0 {
		mergeTargets = make([]*SeniorityMerge, len(pb.MergeTargets))
		for i, target := range pb.MergeTargets {
			converted, err := SeniorityMergeFromProtobuf(target)
			if err != nil {
				return nil, errors.Wrapf(err, "converting merge target %d", i)
			}
			mergeTargets[i] = converted
		}
	}

	return &ProverJoin{
		Filters:                    pb.Filters,
		FrameNumber:                pb.FrameNumber,
		PublicKeySignatureBLS48581: *pubKeySig,
		MergeTargets:               mergeTargets,
		DelegateAddress:            pb.DelegateAddress,
		Proof:                      pb.Proof,
		hypergraph:                 hg,
		keyManager:                 keyManager,
		rdfMultiprover:             nil, // Will be set by caller
		frameProver:                frameProver,
		frameStore:                 frameStore,
	}, nil
}

// ToProtobuf converts an intrinsics ProverJoin to protobuf ProverJoin
func (p *ProverJoin) ToProtobuf() *protobufs.ProverJoin {
	if p == nil {
		return nil
	}

	// Convert MergeTargets
	mergeTargets := make([]*protobufs.SeniorityMerge, len(p.MergeTargets))
	for i, target := range p.MergeTargets {
		mergeTargets[i] = target.ToProtobuf()
	}

	return &protobufs.ProverJoin{
		Filters:                    p.Filters,
		FrameNumber:                p.FrameNumber,
		PublicKeySignatureBls48581: p.PublicKeySignatureBLS48581.ToProtobuf(),
		Proof:                      p.Proof,
		DelegateAddress:            p.DelegateAddress,
		MergeTargets:               mergeTargets,
	}
}

// FromProtobuf converts a protobuf ProverLeave to intrinsics ProverLeave
func ProverLeaveFromProtobuf(
	pb *protobufs.ProverLeave,
	hg hypergraph.Hypergraph,
	signer crypto.Signer,
	inclusionProver crypto.InclusionProver,
	keyManager keys.KeyManager,
) (*ProverLeave, error) {
	if pb == nil {
		return nil, nil
	}

	// Convert PublicKeySignatureBls48581
	pubKeySig, err := BLS48581AddressedSignatureFromProtobuf(
		pb.PublicKeySignatureBls48581,
	)
	if err != nil {
		return nil, errors.Wrap(err, "converting public key signature")
	}

	return &ProverLeave{
		Filters:                    pb.Filters,
		FrameNumber:                pb.FrameNumber,
		PublicKeySignatureBLS48581: *pubKeySig,
		hypergraph:                 hg,
		keyManager:                 keyManager,
		rdfMultiprover:             nil, // Will be set by caller
	}, nil
}

// ToProtobuf converts an intrinsics ProverLeave to protobuf ProverLeave
func (p *ProverLeave) ToProtobuf() *protobufs.ProverLeave {
	if p == nil {
		return nil
	}

	return &protobufs.ProverLeave{
		Filters:                    p.Filters,
		FrameNumber:                p.FrameNumber,
		PublicKeySignatureBls48581: p.PublicKeySignatureBLS48581.ToProtobuf(),
	}
}

// FromProtobuf converts a protobuf ProverPause to intrinsics ProverPause
func ProverPauseFromProtobuf(
	pb *protobufs.ProverPause,
	hg hypergraph.Hypergraph,
	signer crypto.Signer,
	inclusionProver crypto.InclusionProver,
	keyManager keys.KeyManager,
) (*ProverPause, error) {
	if pb == nil {
		return nil, nil
	}

	// Convert PublicKeySignatureBls48581
	pubKeySig, err := BLS48581AddressedSignatureFromProtobuf(
		pb.PublicKeySignatureBls48581,
	)
	if err != nil {
		return nil, errors.Wrap(err, "converting public key signature")
	}

	return &ProverPause{
		Filter:                     pb.Filter,
		FrameNumber:                pb.FrameNumber,
		PublicKeySignatureBLS48581: *pubKeySig,
		hypergraph:                 hg,
		keyManager:                 keyManager,
		rdfMultiprover:             nil, // Will be set by caller
	}, nil
}

// ToProtobuf converts an intrinsics ProverPause to protobuf ProverPause
func (p *ProverPause) ToProtobuf() *protobufs.ProverPause {
	if p == nil {
		return nil
	}

	return &protobufs.ProverPause{
		Filter:                     p.Filter,
		FrameNumber:                p.FrameNumber,
		PublicKeySignatureBls48581: p.PublicKeySignatureBLS48581.ToProtobuf(),
	}
}

// FromProtobuf converts a protobuf ProverResume to intrinsics ProverResume
func ProverResumeFromProtobuf(
	pb *protobufs.ProverResume,
	hg hypergraph.Hypergraph,
	signer crypto.Signer,
	inclusionProver crypto.InclusionProver,
	keyManager keys.KeyManager,
) (*ProverResume, error) {
	if pb == nil {
		return nil, nil
	}

	// Convert PublicKeySignatureBls48581
	pubKeySig, err := BLS48581AddressedSignatureFromProtobuf(
		pb.PublicKeySignatureBls48581,
	)
	if err != nil {
		return nil, errors.Wrap(err, "converting public key signature")
	}

	return &ProverResume{
		Filter:                     pb.Filter,
		FrameNumber:                pb.FrameNumber,
		PublicKeySignatureBLS48581: *pubKeySig,
		hypergraph:                 hg,
		keyManager:                 keyManager,
		rdfMultiprover:             nil, // Will be set by caller
	}, nil
}

// ToProtobuf converts an intrinsics ProverResume to protobuf ProverResume
func (p *ProverResume) ToProtobuf() *protobufs.ProverResume {
	if p == nil {
		return nil
	}

	return &protobufs.ProverResume{
		Filter:                     p.Filter,
		FrameNumber:                p.FrameNumber,
		PublicKeySignatureBls48581: p.PublicKeySignatureBLS48581.ToProtobuf(),
	}
}

// FromProtobuf converts a protobuf ProverConfirm to intrinsics ProverConfirm
func ProverConfirmFromProtobuf(
	pb *protobufs.ProverConfirm,
	hg hypergraph.Hypergraph,
	signer crypto.Signer,
	inclusionProver crypto.InclusionProver,
	keyManager keys.KeyManager,
) (*ProverConfirm, error) {
	if pb == nil {
		return nil, nil
	}

	// Convert PublicKeySignatureBls48581
	pubKeySig, err := BLS48581AddressedSignatureFromProtobuf(
		pb.PublicKeySignatureBls48581,
	)
	if err != nil {
		return nil, errors.Wrap(err, "converting public key signature")
	}

	return &ProverConfirm{
		Filter:                     pb.Filter,
		FrameNumber:                pb.FrameNumber,
		PublicKeySignatureBLS48581: *pubKeySig,
		hypergraph:                 hg,
		keyManager:                 keyManager,
		rdfMultiprover:             nil, // Will be set by caller
	}, nil
}

// ToProtobuf converts an intrinsics ProverConfirm to protobuf ProverConfirm
func (p *ProverConfirm) ToProtobuf() *protobufs.ProverConfirm {
	if p == nil {
		return nil
	}

	return &protobufs.ProverConfirm{
		Filter:                     p.Filter,
		FrameNumber:                p.FrameNumber,
		PublicKeySignatureBls48581: p.PublicKeySignatureBLS48581.ToProtobuf(),
	}
}

// FromProtobuf converts a protobuf ProverReject to intrinsics ProverReject
func ProverRejectFromProtobuf(
	pb *protobufs.ProverReject,
	hg hypergraph.Hypergraph,
	signer crypto.Signer,
	inclusionProver crypto.InclusionProver,
	keyManager keys.KeyManager,
) (*ProverReject, error) {
	if pb == nil {
		return nil, nil
	}

	// Convert PublicKeySignatureBls48581
	pubKeySig, err := BLS48581AddressedSignatureFromProtobuf(
		pb.PublicKeySignatureBls48581,
	)
	if err != nil {
		return nil, errors.Wrap(err, "converting public key signature")
	}

	return &ProverReject{
		Filter:                     pb.Filter,
		FrameNumber:                pb.FrameNumber,
		PublicKeySignatureBLS48581: *pubKeySig,
		hypergraph:                 hg,
		keyManager:                 keyManager,
		rdfMultiprover:             nil, // Will be set by caller
	}, nil
}

// ToProtobuf converts an intrinsics ProverReject to protobuf ProverReject
func (p *ProverReject) ToProtobuf() *protobufs.ProverReject {
	if p == nil {
		return nil
	}

	return &protobufs.ProverReject{
		Filter:                     p.Filter,
		FrameNumber:                p.FrameNumber,
		PublicKeySignatureBls48581: p.PublicKeySignatureBLS48581.ToProtobuf(),
	}
}

// FromProtobuf converts a protobuf ProverKick to intrinsics ProverKick
func ProverKickFromProtobuf(
	pb *protobufs.ProverKick,
	hg hypergraph.Hypergraph,
	inclusionProver crypto.InclusionProver,
	keyManager keys.KeyManager,
) (*ProverKick, error) {
	if pb == nil {
		return nil, nil
	}

	var traversalProof *tries.TraversalProof
	if pb.TraversalProof != nil {
		traversalProof = &tries.TraversalProof{}

		// Convert Multiproof if present
		if pb.TraversalProof.Multiproof != nil {
			if inclusionProver != nil {
				// Create a new multiproof instance and populate it from protobuf data
				mp := inclusionProver.NewMultiproof()
				// Reconstruct the multiproof from its components
				// The protobuf stores the multicommitment and proof separately
				// We need to serialize them back into the format expected by FromBytes
				multiproofBytes := append(
					pb.TraversalProof.Multiproof.Multicommitment,
					pb.TraversalProof.Multiproof.Proof...,
				)
				if err := mp.FromBytes(multiproofBytes); err != nil {
					return nil, errors.Wrap(err, "deserializing multiproof")
				}
				traversalProof.Multiproof = mp
			} else {
				// If no inclusionProver, we can't reconstruct the Multiproof
				// This happens in simple FromBytes() calls without dependencies
				// The Multiproof will remain nil
				traversalProof.Multiproof = nil
			}
		}

		// Convert SubProofs
		for _, pbSubProof := range pb.TraversalProof.SubProofs {
			// Convert paths from protobuf Path to [][]uint64
			var paths [][]uint64
			for _, path := range pbSubProof.Paths {
				paths = append(paths, path.Indices)
			}
			subProof := tries.TraversalSubProof{
				Commits: pbSubProof.Commits,
				Ys:      pbSubProof.Ys,
				Paths:   paths,
			}
			traversalProof.SubProofs = append(traversalProof.SubProofs, subProof)
		}
	}

	return &ProverKick{
		FrameNumber:           pb.FrameNumber,
		KickedProverPublicKey: pb.KickedProverPublicKey,
		ConflictingFrame1:     pb.ConflictingFrame_1,
		ConflictingFrame2:     pb.ConflictingFrame_2,
		Commitment:            pb.Commitment,
		Proof:                 pb.Proof,
		TraversalProof:        traversalProof,
		hypergraph:            hg,
		rdfMultiprover:        nil, // Will be set by caller
	}, nil
}

// ToProtobuf converts an intrinsics ProverKick to protobuf ProverKick
func (p *ProverKick) ToProtobuf() *protobufs.ProverKick {
	if p == nil {
		return nil
	}

	// Convert TraversalProof if present
	var traversalProof *protobufs.TraversalProof
	if p.TraversalProof != nil {
		traversalProof = &protobufs.TraversalProof{}

		// Convert Multiproof if present
		if p.TraversalProof.Multiproof != nil {
			traversalProof.Multiproof = &protobufs.Multiproof{
				Multicommitment: p.TraversalProof.Multiproof.GetMulticommitment(),
				Proof:           p.TraversalProof.Multiproof.GetProof(),
			}
		}

		// Convert SubProofs
		for _, subProof := range p.TraversalProof.SubProofs {
			// Convert paths from [][]uint64 to protobuf Path
			var paths []*protobufs.Path
			for _, path := range subProof.Paths {
				paths = append(paths, &protobufs.Path{Indices: path})
			}
			pbSubProof := &protobufs.TraversalSubProof{
				Commits: subProof.Commits,
				Ys:      subProof.Ys,
				Paths:   paths,
			}
			traversalProof.SubProofs = append(traversalProof.SubProofs, pbSubProof)
		}
	}

	return &protobufs.ProverKick{
		FrameNumber:           p.FrameNumber,
		KickedProverPublicKey: p.KickedProverPublicKey,
		ConflictingFrame_1:    p.ConflictingFrame1,
		ConflictingFrame_2:    p.ConflictingFrame2,
		Commitment:            p.Commitment,
		Proof:                 p.Proof,
		TraversalProof:        traversalProof,
	}
}

// FromProtobuf converts a protobuf ProverUpdate to intrinsics
func ProverUpdateFromProtobuf(
	pb *protobufs.ProverUpdate,
	hg hypergraph.Hypergraph,
	signer crypto.Signer,
	rdfMultiprover *schema.RDFMultiprover,
	keyManager keys.KeyManager,
) (*ProverUpdate, error) {
	if pb == nil {
		return nil, nil
	}

	signature, err := BLS48581AddressedSignatureFromProtobuf(
		pb.PublicKeySignatureBls48581,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prover update from protobuf")
	}

	return &ProverUpdate{
		DelegateAddress:            pb.DelegateAddress,
		PublicKeySignatureBLS48581: signature,
		hypergraph:                 hg,
		signer:                     signer,
		rdfMultiprover:             rdfMultiprover,
		keyManager:                 keyManager,
	}, nil
}

// ToProtobuf converts an intrinsics ProverUpdate to protobuf
func (p *ProverUpdate) ToProtobuf() *protobufs.ProverUpdate {
	if p == nil {
		return nil
	}

	return &protobufs.ProverUpdate{
		DelegateAddress:            p.DelegateAddress,
		PublicKeySignatureBls48581: p.PublicKeySignatureBLS48581.ToProtobuf(),
	}
}

// FromProtobuf converts a protobuf MessageRequest to intrinsics types
func GlobalRequestFromProtobuf(
	pb *protobufs.MessageRequest,
	hg hypergraph.Hypergraph,
	signer crypto.Signer,
	inclusionProver crypto.InclusionProver,
	keyManager keys.KeyManager,
	frameProver crypto.FrameProver,
	frameStore store.ClockStore,
) (interface{}, error) {
	if pb == nil {
		return nil, nil
	}

	// Determine which type of request this is based on the Request field
	switch req := pb.Request.(type) {
	case *protobufs.MessageRequest_Join:
		return ProverJoinFromProtobuf(
			req.Join,
			hg,
			signer,
			inclusionProver,
			keyManager,
			frameProver,
			frameStore,
		)

	case *protobufs.MessageRequest_Leave:
		return ProverLeaveFromProtobuf(
			req.Leave,
			hg,
			signer,
			inclusionProver,
			keyManager,
		)

	case *protobufs.MessageRequest_Pause:
		return ProverPauseFromProtobuf(
			req.Pause,
			hg,
			signer,
			inclusionProver,
			keyManager,
		)

	case *protobufs.MessageRequest_Resume:
		return ProverResumeFromProtobuf(
			req.Resume,
			hg,
			signer,
			inclusionProver,
			keyManager,
		)

	case *protobufs.MessageRequest_Confirm:
		return ProverConfirmFromProtobuf(
			req.Confirm,
			hg,
			signer,
			inclusionProver,
			keyManager,
		)

	case *protobufs.MessageRequest_Reject:
		return ProverRejectFromProtobuf(
			req.Reject,
			hg,
			signer,
			inclusionProver,
			keyManager,
		)

	case *protobufs.MessageRequest_Kick:
		return ProverKickFromProtobuf(req.Kick, hg, inclusionProver, keyManager)

	case *protobufs.MessageRequest_Update:
		return ProverUpdateFromProtobuf(
			req.Update,
			hg,
			signer,
			schema.NewRDFMultiprover(&schema.TurtleRDFParser{}, inclusionProver),
			keyManager,
		)

	default:
		return nil, errors.New("unknown global request type")
	}
}
