package global

import (
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	"source.quilibrium.com/quilibrium/monorepo/types/hypergraph"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/types/store"
)

// ToBytes serializes a BLS48581SignatureWithProofOfPossession to bytes using
// protobuf
func (s *BLS48581SignatureWithProofOfPossession) ToBytes() ([]byte, error) {
	pb := s.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a BLS48581SignatureWithProofOfPossession from bytes
// using protobuf
func (s *BLS48581SignatureWithProofOfPossession) FromBytes(data []byte) error {
	pb := &protobufs.BLS48581SignatureWithProofOfPossession{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := BLS48581SignatureWithProofOfPossessionFromProtobuf(pb)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	*s = *converted
	return nil
}

// ToBytes serializes a BLS48581AddressedSignature to bytes using protobuf
func (s *BLS48581AddressedSignature) ToBytes() ([]byte, error) {
	pb := s.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a BLS48581AddressedSignature from bytes using protobuf
func (s *BLS48581AddressedSignature) FromBytes(data []byte) error {
	pb := &protobufs.BLS48581AddressedSignature{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := BLS48581AddressedSignatureFromProtobuf(pb)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	*s = *converted
	return nil
}

// ToBytes serializes a SeniorityMerge to bytes using protobuf
func (s *SeniorityMerge) ToBytes() ([]byte, error) {
	pb := s.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// FromBytes deserializes a SeniorityMerge from bytes using protobuf
func (s *SeniorityMerge) FromBytes(data []byte) error {
	pb := &protobufs.SeniorityMerge{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := SeniorityMergeFromProtobuf(pb)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	*s = *converted
	return nil
}

// ToBytes serializes a ProverJoin to bytes using protobuf
func (p *ProverJoin) ToBytes() ([]byte, error) {
	pb := p.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// ToRequestBytes serializes a ProverJoin to MessageRequest bytes using protobuf
func (p *ProverJoin) ToRequestBytes() ([]byte, error) {
	pb := p.ToProtobuf()
	req := &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Join{
			Join: pb,
		},
	}
	return req.ToCanonicalBytes()
}

// FromBytes deserializes a ProverJoin from bytes using protobuf
func (p *ProverJoin) FromBytes(data []byte) error {
	pb := &protobufs.ProverJoin{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Note: Runtime dependencies are not available here
	// They need to be injected separately after deserialization
	converted, err := ProverJoinFromProtobuf(pb, nil, nil, nil, nil, nil, nil)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Copy only the data fields, runtime dependencies will be set separately
	p.Filters = converted.Filters
	p.FrameNumber = converted.FrameNumber
	p.PublicKeySignatureBLS48581 = converted.PublicKeySignatureBLS48581
	p.MergeTargets = converted.MergeTargets

	return nil
}

// ToBytes serializes a ProverLeave to bytes using protobuf
func (p *ProverLeave) ToBytes() ([]byte, error) {
	pb := p.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// ToRequestBytes serializes a ProverLeave to MessageRequest bytes using protobuf
func (p *ProverLeave) ToRequestBytes() ([]byte, error) {
	pb := p.ToProtobuf()
	req := &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Leave{
			Leave: pb,
		},
	}
	return req.ToCanonicalBytes()
}

// FromBytes deserializes a ProverLeave from bytes using protobuf
func (p *ProverLeave) FromBytes(data []byte) error {
	pb := &protobufs.ProverLeave{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := ProverLeaveFromProtobuf(pb, nil, nil, nil, nil)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Copy only the data fields, runtime dependencies will be set separately
	p.Filters = converted.Filters
	p.FrameNumber = converted.FrameNumber
	p.PublicKeySignatureBLS48581 = converted.PublicKeySignatureBLS48581

	return nil
}

// ToBytes serializes a ProverPause to bytes using protobuf
func (p *ProverPause) ToBytes() ([]byte, error) {
	pb := p.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// ToRequestBytes serializes a ProverPause to MessageRequest bytes using protobuf
func (p *ProverPause) ToRequestBytes() ([]byte, error) {
	pb := p.ToProtobuf()
	req := &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Pause{
			Pause: pb,
		},
	}
	return req.ToCanonicalBytes()
}

// FromBytes deserializes a ProverPause from bytes using protobuf
func (p *ProverPause) FromBytes(data []byte) error {
	pb := &protobufs.ProverPause{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := ProverPauseFromProtobuf(pb, nil, nil, nil, nil)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Copy only the data fields, runtime dependencies will be set separately
	p.Filter = converted.Filter
	p.FrameNumber = converted.FrameNumber
	p.PublicKeySignatureBLS48581 = converted.PublicKeySignatureBLS48581

	return nil
}

// ToBytes serializes a ProverResume to bytes using protobuf
func (p *ProverResume) ToBytes() ([]byte, error) {
	pb := p.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// ToRequestBytes serializes a ProverResume to MessageRequest bytes using
// protobuf
func (p *ProverResume) ToRequestBytes() ([]byte, error) {
	pb := p.ToProtobuf()
	req := &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Resume{
			Resume: pb,
		},
	}
	return req.ToCanonicalBytes()
}

// FromBytes deserializes a ProverResume from bytes using protobuf
func (p *ProverResume) FromBytes(data []byte) error {
	pb := &protobufs.ProverResume{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := ProverResumeFromProtobuf(pb, nil, nil, nil, nil)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Copy only the data fields, runtime dependencies will be set separately
	p.Filter = converted.Filter
	p.FrameNumber = converted.FrameNumber
	p.PublicKeySignatureBLS48581 = converted.PublicKeySignatureBLS48581

	return nil
}

// ToBytes serializes a ProverConfirm to bytes using protobuf
func (p *ProverConfirm) ToBytes() ([]byte, error) {
	pb := p.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// ToRequestBytes serializes a ProverConfirm to MessageRequest bytes using
// protobuf
func (p *ProverConfirm) ToRequestBytes() ([]byte, error) {
	pb := p.ToProtobuf()
	req := &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Confirm{
			Confirm: pb,
		},
	}
	return req.ToCanonicalBytes()
}

// FromBytes deserializes a ProverConfirm from bytes using protobuf
func (p *ProverConfirm) FromBytes(data []byte) error {
	pb := &protobufs.ProverConfirm{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := ProverConfirmFromProtobuf(pb, nil, nil, nil, nil)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Copy only the data fields, runtime dependencies will be set separately
	p.Filter = converted.Filter
	p.FrameNumber = converted.FrameNumber
	p.PublicKeySignatureBLS48581 = converted.PublicKeySignatureBLS48581

	return nil
}

// ToBytes serializes a ProverReject to bytes using protobuf
func (p *ProverReject) ToBytes() ([]byte, error) {
	pb := p.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// ToRequestBytes serializes a ProverReject to MessageRequest bytes using
// protobuf
func (p *ProverReject) ToRequestBytes() ([]byte, error) {
	pb := p.ToProtobuf()
	req := &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Reject{
			Reject: pb,
		},
	}
	return req.ToCanonicalBytes()
}

// FromBytes deserializes a ProverReject from bytes using protobuf
func (p *ProverReject) FromBytes(data []byte) error {
	pb := &protobufs.ProverReject{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := ProverRejectFromProtobuf(pb, nil, nil, nil, nil)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Copy only the data fields, runtime dependencies will be set separately
	p.Filter = converted.Filter
	p.FrameNumber = converted.FrameNumber
	p.PublicKeySignatureBLS48581 = converted.PublicKeySignatureBLS48581

	return nil
}

// ToBytes serializes a ProverKick to bytes using protobuf
func (p *ProverKick) ToBytes() ([]byte, error) {
	pb := p.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// ToRequestBytes serializes a ProverKick to MessageRequest bytes using protobuf
func (p *ProverKick) ToRequestBytes() ([]byte, error) {
	pb := p.ToProtobuf()
	req := &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Kick{
			Kick: pb,
		},
	}
	return req.ToCanonicalBytes()
}

// FromBytes deserializes a ProverKick from bytes using protobuf
// Note: ProverKick requires special handling for traversal proof
func (p *ProverKick) FromBytes(data []byte) error {
	pb := &protobufs.ProverKick{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := ProverKickFromProtobuf(pb, nil, nil, nil)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Copy all fields including TraversalProof
	*p = *converted

	return nil
}

// Special FromBytes for ProverKick that handles hypergraph dependency
func (p *ProverKick) FromBytesWithHypergraph(
	data []byte,
	hg hypergraph.Hypergraph,
	inclusionProver crypto.InclusionProver,
	keyManager keys.KeyManager,
) error {
	pb := &protobufs.ProverKick{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := ProverKickFromProtobuf(pb, hg, inclusionProver, keyManager)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	*p = *converted
	return nil
}

// GlobalRequestFromBytes deserializes a global request from bytes using
// protobuf
func GlobalRequestFromBytes(
	data []byte,
	hg hypergraph.Hypergraph,
	signer crypto.Signer,
	inclusionProver crypto.InclusionProver,
	keyManager keys.KeyManager,
	frameProver crypto.FrameProver,
	frameStore store.ClockStore,
) (interface{}, error) {
	pb := &protobufs.MessageRequest{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return nil, errors.Wrap(err, "global request from bytes")
	}

	return GlobalRequestFromProtobuf(
		pb,
		hg,
		signer,
		inclusionProver,
		keyManager,
		frameProver,
		frameStore,
	)
}

// ToBytes serializes a ProverUpdate to bytes using protobuf
func (p *ProverUpdate) ToBytes() ([]byte, error) {
	pb := p.ToProtobuf()
	return pb.ToCanonicalBytes()
}

// ToRequestBytes serializes a ProverUpdate to MessageRequest bytes using protobuf
func (p *ProverUpdate) ToRequestBytes() ([]byte, error) {
	pb := p.ToProtobuf()
	req := &protobufs.MessageRequest{
		Request: &protobufs.MessageRequest_Update{
			Update: pb,
		},
	}
	return req.ToCanonicalBytes()
}

// FromBytes deserializes a ProverUpdate from bytes using protobuf
func (p *ProverUpdate) FromBytes(data []byte) error {
	pb := &protobufs.ProverUpdate{}
	if err := pb.FromCanonicalBytes(data); err != nil {
		return errors.Wrap(err, "from bytes")
	}

	converted, err := ProverUpdateFromProtobuf(pb, nil, nil, nil, nil)
	if err != nil {
		return errors.Wrap(err, "from bytes")
	}

	// Copy only the data fields, runtime dependencies will be set separately
	p.DelegateAddress = converted.DelegateAddress
	p.PublicKeySignatureBLS48581 = converted.PublicKeySignatureBLS48581

	return nil
}
