package protobufs

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/multiformats/go-multiaddr"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/consensus"
)

func (g *GlobalFrame) Clone() consensus.Unique {
	g.Identity()
	frame := proto.Clone(g)
	return frame.(*GlobalFrame)
}

func (g *GlobalFrame) Identity() consensus.Identity {
	return consensus.Identity(g.Header.Output)
}

func (g *GlobalFrame) Rank() uint64 {
	return g.Header.FrameNumber
}

func (a *AppShardFrame) Clone() consensus.Unique {
	a.Identity()
	frame := proto.Clone(a)
	return frame.(*AppShardFrame)
}

func (a *AppShardFrame) Identity() consensus.Identity {
	return consensus.Identity(a.Header.Output)
}

func (a *AppShardFrame) Rank() uint64 {
	return a.Header.FrameNumber
}

func (f *FrameVote) Clone() consensus.Unique {
	f.Identity()
	frame := proto.Clone(f)
	return frame.(*FrameVote)
}

func (f *FrameVote) Identity() consensus.Identity {
	return consensus.Identity(f.PublicKeySignatureBls48581.Signature)
}

func (f *FrameVote) Rank() uint64 {
	return f.FrameNumber
}

func (s *SeniorityMerge) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		SeniorityMergeType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(s.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(s.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write key_type
	if err := binary.Write(buf, binary.BigEndian, s.KeyType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write prover_public_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(s.ProverPublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(s.ProverPublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (s *SeniorityMerge) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != SeniorityMergeType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read signature
	var commitmentLen uint32
	if err := binary.Read(buf, binary.BigEndian, &commitmentLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	s.Signature = make([]byte, commitmentLen)
	if _, err := buf.Read(s.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read key_type
	if err := binary.Read(buf, binary.BigEndian, &s.KeyType); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read prover_public_key
	var keyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &keyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	s.ProverPublicKey = make([]byte, keyLen)
	if _, err := buf.Read(s.ProverPublicKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (l *LegacyProverRequest) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		LegacyProverRequestType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signatures_ed448 count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(l.PublicKeySignaturesEd448)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, sig := range l.PublicKeySignaturesEd448 {
		sigBytes, err := sig.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (l *LegacyProverRequest) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != LegacyProverRequestType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read public_key_signatures_ed448
	var sigCount uint32
	if err := binary.Read(buf, binary.BigEndian, &sigCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	l.PublicKeySignaturesEd448 = make([]*Ed448Signature, sigCount)
	for i := uint32(0); i < sigCount; i++ {
		var sigLen uint32
		if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		l.PublicKeySignaturesEd448[i] = &Ed448Signature{}
		if err := l.PublicKeySignaturesEd448[i].FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (p *ProverJoin) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ProverJoinType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write filters count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Filters)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	// Write each filter
	for _, filter := range p.Filters {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(filter)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(filter); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, p.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if p.PublicKeySignatureBls48581 != nil {
		sigBytes, err := p.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write delegate_address
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.DelegateAddress)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if len(p.DelegateAddress) != 0 {
		if _, err := buf.Write(p.DelegateAddress); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write merge_targets count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.MergeTargets)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	// Write each merge target
	for _, target := range p.MergeTargets {
		targetBytes, err := target.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(targetBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(targetBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *ProverJoin) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverJoinType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read filters count
	var filtersCount uint32
	if err := binary.Read(buf, binary.BigEndian, &filtersCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Filters = make([][]byte, filtersCount)
	// Read each filter
	for i := uint32(0); i < filtersCount; i++ {
		var filterLen uint32
		if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.Filters[i] = make([]byte, filterLen)
		if _, err := buf.Read(p.Filters[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &p.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.PublicKeySignatureBls48581 = &BLS48581SignatureWithProofOfPossession{}
		if err := p.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read delegate_address
	var delegateAddressLen uint32
	if err := binary.Read(buf, binary.BigEndian, &delegateAddressLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.DelegateAddress = make([]byte, delegateAddressLen)
	if _, err := buf.Read(p.DelegateAddress); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read merge_targets count
	var mergeTargetsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &mergeTargetsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.MergeTargets = make([]*SeniorityMerge, mergeTargetsCount)
	// Read each merge target
	for i := uint32(0); i < mergeTargetsCount; i++ {
		var targetLen uint32
		if err := binary.Read(buf, binary.BigEndian, &targetLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		targetBytes := make([]byte, targetLen)
		if _, err := buf.Read(targetBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.MergeTargets[i] = &SeniorityMerge{}
		if err := p.MergeTargets[i].FromCanonicalBytes(
			targetBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (p *ProverLeave) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ProverLeaveType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write filters count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Filters)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	// Write each filter
	for _, filter := range p.Filters {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(filter)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(filter); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, p.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if p.PublicKeySignatureBls48581 != nil {
		sigBytes, err := p.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *ProverLeave) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverLeaveType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read filters count
	var filtersCount uint32
	if err := binary.Read(buf, binary.BigEndian, &filtersCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Filters = make([][]byte, filtersCount)
	// Read each filter
	for i := uint32(0); i < filtersCount; i++ {
		var filterLen uint32
		if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.Filters[i] = make([]byte, filterLen)
		if _, err := buf.Read(p.Filters[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &p.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
		if err := p.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (p *ProverPause) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ProverPauseType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write filter
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Filter)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Filter); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, p.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if p.PublicKeySignatureBls48581 != nil {
		sigBytes, err := p.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *ProverPause) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverPauseType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read filter
	var filterLen uint32
	if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Filter = make([]byte, filterLen)
	if _, err := buf.Read(p.Filter); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &p.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
		if err := p.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (p *ProverResume) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ProverResumeType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write filter
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Filter)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Filter); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, p.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if p.PublicKeySignatureBls48581 != nil {
		sigBytes, err := p.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *ProverResume) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverResumeType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read filter
	var filterLen uint32
	if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Filter = make([]byte, filterLen)
	if _, err := buf.Read(p.Filter); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &p.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
		if err := p.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (p *ProverConfirm) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ProverConfirmType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write filter
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Filter)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Filter); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, p.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if p.PublicKeySignatureBls48581 != nil {
		sigBytes, err := p.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *ProverConfirm) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverConfirmType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read filter
	var filterLen uint32
	if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Filter = make([]byte, filterLen)
	if _, err := buf.Read(p.Filter); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &p.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
		if err := p.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (p *ProverReject) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ProverRejectType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write filter
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Filter)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Filter); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, p.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if p.PublicKeySignatureBls48581 != nil {
		sigBytes, err := p.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *ProverReject) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverRejectType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read filter
	var filterLen uint32
	if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Filter = make([]byte, filterLen)
	if _, err := buf.Read(p.Filter); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &p.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
		if err := p.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (p *ProverUpdate) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ProverUpdateType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write delegate_address
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.DelegateAddress)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.DelegateAddress); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if p.PublicKeySignatureBls48581 != nil {
		sigBytes, err := p.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *ProverUpdate) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverUpdateType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read delegate_address
	var addressLen uint32
	if err := binary.Read(buf, binary.BigEndian, &addressLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.DelegateAddress = make([]byte, addressLen)
	if _, err := buf.Read(p.DelegateAddress); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
		if err := p.PublicKeySignatureBls48581.FromCanonicalBytes(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (m *MessageRequest) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, MessageRequestType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Serialize the inner message (which already contains its own type discriminator)
	var innerBytes []byte
	var err error

	switch request := m.Request.(type) {
	case *MessageRequest_Join:
		innerBytes, err = request.Join.ToCanonicalBytes()
	case *MessageRequest_Leave:
		innerBytes, err = request.Leave.ToCanonicalBytes()
	case *MessageRequest_Pause:
		innerBytes, err = request.Pause.ToCanonicalBytes()
	case *MessageRequest_Resume:
		innerBytes, err = request.Resume.ToCanonicalBytes()
	case *MessageRequest_Confirm:
		innerBytes, err = request.Confirm.ToCanonicalBytes()
	case *MessageRequest_Reject:
		innerBytes, err = request.Reject.ToCanonicalBytes()
	case *MessageRequest_Kick:
		innerBytes, err = request.Kick.ToCanonicalBytes()
	case *MessageRequest_Update:
		innerBytes, err = request.Update.ToCanonicalBytes()
	case *MessageRequest_TokenDeploy:
		innerBytes, err = request.TokenDeploy.ToCanonicalBytes()
	case *MessageRequest_TokenUpdate:
		innerBytes, err = request.TokenUpdate.ToCanonicalBytes()
	case *MessageRequest_Transaction:
		innerBytes, err = request.Transaction.ToCanonicalBytes()
	case *MessageRequest_PendingTransaction:
		innerBytes, err = request.PendingTransaction.ToCanonicalBytes()
	case *MessageRequest_MintTransaction:
		innerBytes, err = request.MintTransaction.ToCanonicalBytes()
	case *MessageRequest_HypergraphDeploy:
		innerBytes, err = request.HypergraphDeploy.ToCanonicalBytes()
	case *MessageRequest_HypergraphUpdate:
		innerBytes, err = request.HypergraphUpdate.ToCanonicalBytes()
	case *MessageRequest_VertexAdd:
		innerBytes, err = request.VertexAdd.ToCanonicalBytes()
	case *MessageRequest_VertexRemove:
		innerBytes, err = request.VertexRemove.ToCanonicalBytes()
	case *MessageRequest_HyperedgeAdd:
		innerBytes, err = request.HyperedgeAdd.ToCanonicalBytes()
	case *MessageRequest_HyperedgeRemove:
		innerBytes, err = request.HyperedgeRemove.ToCanonicalBytes()
	case *MessageRequest_ComputeDeploy:
		innerBytes, err = request.ComputeDeploy.ToCanonicalBytes()
	case *MessageRequest_ComputeUpdate:
		innerBytes, err = request.ComputeUpdate.ToCanonicalBytes()
	case *MessageRequest_CodeDeploy:
		innerBytes, err = request.CodeDeploy.ToCanonicalBytes()
	case *MessageRequest_CodeExecute:
		innerBytes, err = request.CodeExecute.ToCanonicalBytes()
	case *MessageRequest_CodeFinalize:
		innerBytes, err = request.CodeFinalize.ToCanonicalBytes()
	default:
		return nil, errors.New("unknown request type")
	}

	if err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write length-prefixed inner message
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(innerBytes)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(innerBytes); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (m *MessageRequest) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != MessageRequestType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read length of inner message
	var dataLen uint32
	if err := binary.Read(buf, binary.BigEndian, &dataLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	if dataLen == 0 {
		return errors.New("empty message request")
	}

	// Read the inner message bytes
	dataBytes := make([]byte, dataLen)
	if _, err := buf.Read(dataBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Peek at the type discriminator (first 4 bytes)
	if len(dataBytes) < 4 {
		return errors.New("message too short to contain type discriminator")
	}

	innerTypeBuf := bytes.NewBuffer(dataBytes[:4])
	var innerType uint32
	if err := binary.Read(
		innerTypeBuf,
		binary.BigEndian,
		&innerType,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Route based on the embedded type discriminator
	switch innerType {
	case ProverJoinType:
		join := &ProverJoin{}
		if err := join.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Join{Join: join}

	case ProverLeaveType:
		leave := &ProverLeave{}
		if err := leave.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Leave{Leave: leave}

	case ProverPauseType:
		pause := &ProverPause{}
		if err := pause.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Pause{Pause: pause}

	case ProverResumeType:
		resume := &ProverResume{}
		if err := resume.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Resume{Resume: resume}

	case ProverConfirmType:
		confirm := &ProverConfirm{}
		if err := confirm.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Confirm{Confirm: confirm}

	case ProverRejectType:
		reject := &ProverReject{}
		if err := reject.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Reject{Reject: reject}

	case ProverKickType:
		kick := &ProverKick{}
		if err := kick.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Kick{Kick: kick}

	case ProverUpdateType:
		update := &ProverUpdate{}
		if err := update.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Update{Update: update}

	case TokenDeploymentType:
		tokenDeploy := &TokenDeploy{}
		if err := tokenDeploy.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_TokenDeploy{TokenDeploy: tokenDeploy}

	case TokenUpdateType:
		tokenUpdate := &TokenUpdate{}
		if err := tokenUpdate.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_TokenUpdate{TokenUpdate: tokenUpdate}

	case TransactionType:
		transaction := &Transaction{}
		if err := transaction.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_Transaction{Transaction: transaction}

	case PendingTransactionType:
		pendingTransaction := &PendingTransaction{}
		if err := pendingTransaction.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_PendingTransaction{
			PendingTransaction: pendingTransaction,
		}

	case MintTransactionType:
		mintTransaction := &MintTransaction{}
		if err := mintTransaction.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_MintTransaction{
			MintTransaction: mintTransaction,
		}

	case HypergraphDeploymentType:
		hypergraphDeploy := &HypergraphDeploy{}
		if err := hypergraphDeploy.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_HypergraphDeploy{
			HypergraphDeploy: hypergraphDeploy,
		}

	case HypergraphUpdateType:
		hypergraphUpdate := &HypergraphUpdate{}
		if err := hypergraphUpdate.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_HypergraphUpdate{
			HypergraphUpdate: hypergraphUpdate,
		}

	case VertexAddType:
		vertexAdd := &VertexAdd{}
		if err := vertexAdd.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_VertexAdd{VertexAdd: vertexAdd}

	case VertexRemoveType:
		vertexRemove := &VertexRemove{}
		if err := vertexRemove.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_VertexRemove{VertexRemove: vertexRemove}

	case HyperedgeAddType:
		hyperedgeAdd := &HyperedgeAdd{}
		if err := hyperedgeAdd.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_HyperedgeAdd{HyperedgeAdd: hyperedgeAdd}

	case HyperedgeRemoveType:
		hyperedgeRemove := &HyperedgeRemove{}
		if err := hyperedgeRemove.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_HyperedgeRemove{
			HyperedgeRemove: hyperedgeRemove,
		}

	case ComputeDeploymentType:
		computeDeploy := &ComputeDeploy{}
		if err := computeDeploy.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_ComputeDeploy{ComputeDeploy: computeDeploy}

	case ComputeUpdateType:
		computeUpdate := &ComputeUpdate{}
		if err := computeUpdate.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_ComputeUpdate{ComputeUpdate: computeUpdate}

	case CodeDeploymentType:
		codeDeploy := &CodeDeployment{}
		if err := codeDeploy.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_CodeDeploy{CodeDeploy: codeDeploy}

	case CodeExecuteType:
		codeExecute := &CodeExecute{}
		if err := codeExecute.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_CodeExecute{CodeExecute: codeExecute}

	case CodeFinalizeType:
		codeFinalize := &CodeFinalize{}
		if err := codeFinalize.FromCanonicalBytes(dataBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		m.Request = &MessageRequest_CodeFinalize{CodeFinalize: codeFinalize}

	default:
		return errors.Errorf("unknown message type: 0x%08X", innerType)
	}

	return nil
}

func (m *MessageBundle) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, MessageBundleType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write number of requests
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Requests)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write each request
	for _, request := range m.Requests {
		if request != nil {
			requestBytes, err := request.ToCanonicalBytes()
			if err != nil {
				return nil, errors.Wrap(err, "to canonical bytes")
			}
			if err := binary.Write(
				buf,
				binary.BigEndian,
				uint32(len(requestBytes)),
			); err != nil {
				return nil, errors.Wrap(err, "to canonical bytes")
			}
			if _, err := buf.Write(requestBytes); err != nil {
				return nil, errors.Wrap(err, "to canonical bytes")
			}
		} else {
			if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
				return nil, errors.Wrap(err, "to canonical bytes")
			}
		}
	}

	// Write timestamp
	if err := binary.Write(buf, binary.BigEndian, m.Timestamp); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (m *MessageBundle) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != MessageBundleType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read number of requests
	var numRequests uint32
	if err := binary.Read(buf, binary.BigEndian, &numRequests); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read each request
	m.Requests = make([]*MessageRequest, 0, numRequests)
	for i := uint32(0); i < numRequests; i++ {
		var requestLen uint32
		if err := binary.Read(buf, binary.BigEndian, &requestLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		if requestLen > 0 {
			requestBytes := make([]byte, requestLen)
			if _, err := buf.Read(requestBytes); err != nil {
				return errors.Wrap(err, "from canonical bytes")
			}
			request := &MessageRequest{}
			if err := request.FromCanonicalBytes(requestBytes); err != nil {
				return errors.Wrap(err, "from canonical bytes")
			}
			m.Requests = append(m.Requests, request)
		} else {
			m.Requests = append(m.Requests, nil)
		}
	}

	// Read timestamp
	if err := binary.Read(buf, binary.BigEndian, &m.Timestamp); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (g *GlobalFrameHeader) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		GlobalFrameHeaderType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, g.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write timestamp
	if err := binary.Write(buf, binary.BigEndian, g.Timestamp); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write difficulty
	if err := binary.Write(buf, binary.BigEndian, g.Difficulty); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write output
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(g.Output)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(g.Output); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write parent_selector
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(g.ParentSelector)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(g.ParentSelector); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write global_commitments count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(g.GlobalCommitments)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, commitment := range g.GlobalCommitments {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(commitment)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(commitment); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write prover_tree_commitment
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(g.ProverTreeCommitment)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(g.ProverTreeCommitment); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if g.PublicKeySignatureBls48581 != nil {
		sigBytes, err := g.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (g *GlobalFrameHeader) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != GlobalFrameHeaderType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &g.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read timestamp
	if err := binary.Read(buf, binary.BigEndian, &g.Timestamp); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read difficulty
	if err := binary.Read(buf, binary.BigEndian, &g.Difficulty); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read output
	var outputLen uint32
	if err := binary.Read(buf, binary.BigEndian, &outputLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	g.Output = make([]byte, outputLen)
	if _, err := buf.Read(g.Output); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read parent_selector
	var parentSelectorLen uint32
	if err := binary.Read(buf, binary.BigEndian, &parentSelectorLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	g.ParentSelector = make([]byte, parentSelectorLen)
	if _, err := buf.Read(g.ParentSelector); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read global_commitments
	var commitmentsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &commitmentsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	g.GlobalCommitments = make([][]byte, commitmentsCount)
	for i := uint32(0); i < commitmentsCount; i++ {
		var commitmentLen uint32
		if err := binary.Read(buf, binary.BigEndian, &commitmentLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		g.GlobalCommitments[i] = make([]byte, commitmentLen)
		if _, err := buf.Read(g.GlobalCommitments[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read prover_tree_commitment
	var proverTreeCommitmentLen uint32
	if err := binary.Read(
		buf,
		binary.BigEndian,
		&proverTreeCommitmentLen,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	g.ProverTreeCommitment = make([]byte, proverTreeCommitmentLen)
	if _, err := buf.Read(g.ProverTreeCommitment); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		g.PublicKeySignatureBls48581 = &BLS48581AggregateSignature{}
		if err := g.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (f *FrameHeader) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, FrameHeaderType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write address
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.Address)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(f.Address); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, f.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write timestamp
	if err := binary.Write(buf, binary.BigEndian, f.Timestamp); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write difficulty
	if err := binary.Write(buf, binary.BigEndian, f.Difficulty); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write output
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.Output)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(f.Output); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write parent_selector
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.ParentSelector)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(f.ParentSelector); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write requests_root
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.RequestsRoot)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(f.RequestsRoot); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write state_roots count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.StateRoots)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, root := range f.StateRoots {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(root)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(root); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write prover
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.Prover)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(f.Prover); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write fee_multiplier_vote
	if err := binary.Write(
		buf,
		binary.BigEndian,
		f.FeeMultiplierVote,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if f.PublicKeySignatureBls48581 != nil {
		sigBytes, err := f.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (f *FrameHeader) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != FrameHeaderType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read address
	var addressLen uint32
	if err := binary.Read(buf, binary.BigEndian, &addressLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	f.Address = make([]byte, addressLen)
	if _, err := buf.Read(f.Address); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &f.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read timestamp
	if err := binary.Read(buf, binary.BigEndian, &f.Timestamp); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read difficulty
	if err := binary.Read(buf, binary.BigEndian, &f.Difficulty); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read output
	var outputLen uint32
	if err := binary.Read(buf, binary.BigEndian, &outputLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	f.Output = make([]byte, outputLen)
	if _, err := buf.Read(f.Output); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read parent_selector
	var parentSelectorLen uint32
	if err := binary.Read(buf, binary.BigEndian, &parentSelectorLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	f.ParentSelector = make([]byte, parentSelectorLen)
	if _, err := buf.Read(f.ParentSelector); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read requests_root
	var requestsRootLen uint32
	if err := binary.Read(buf, binary.BigEndian, &requestsRootLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	f.RequestsRoot = make([]byte, requestsRootLen)
	if _, err := buf.Read(f.RequestsRoot); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read state_roots
	var stateRootsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &stateRootsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	f.StateRoots = make([][]byte, stateRootsCount)
	for i := uint32(0); i < stateRootsCount; i++ {
		var rootLen uint32
		if err := binary.Read(buf, binary.BigEndian, &rootLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		f.StateRoots[i] = make([]byte, rootLen)
		if _, err := buf.Read(f.StateRoots[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read prover
	var proverLen uint32
	if err := binary.Read(buf, binary.BigEndian, &proverLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	f.Prover = make([]byte, proverLen)
	if _, err := buf.Read(f.Prover); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read fee_multiplier_vote
	if err := binary.Read(
		buf,
		binary.BigEndian,
		&f.FeeMultiplierVote,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		f.PublicKeySignatureBls48581 = &BLS48581AggregateSignature{}
		if err := f.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (p *ProverLivenessCheck) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		ProverLivenessCheckType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write filter
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Filter)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Filter); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, p.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write timestamp
	if err := binary.Write(buf, binary.BigEndian, p.Timestamp); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write commitment_hash
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.CommitmentHash)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.CommitmentHash); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if p.PublicKeySignatureBls48581 != nil {
		sigBytes, err := p.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *ProverLivenessCheck) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverLivenessCheckType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read filter
	var filterLen uint32
	if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Filter = make([]byte, filterLen)
	if _, err := buf.Read(p.Filter); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &p.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read timestamp
	if err := binary.Read(buf, binary.BigEndian, &p.Timestamp); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read commitment_hash
	var commitmentHashLen uint32
	if err := binary.Read(buf, binary.BigEndian, &commitmentHashLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.CommitmentHash = make([]byte, commitmentHashLen)
	if _, err := buf.Read(p.CommitmentHash); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	if sigLen == 0 {
		return errors.Wrap(errors.New("invalid signature"), "from canonical bytes")
	}

	sigBytes := make([]byte, sigLen)
	if _, err := buf.Read(sigBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
	if err := p.PublicKeySignatureBls48581.FromCanonicalBytes(
		sigBytes,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (f *FrameVote) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, FrameVoteType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, f.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write proposer
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.Proposer)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(f.Proposer); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write approve
	approve := uint8(0)
	if f.Approve {
		approve = 1
	}
	if err := binary.Write(buf, binary.BigEndian, approve); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write public_key_signature_bls48581
	if f.PublicKeySignatureBls48581 != nil {
		sigBytes, err := f.PublicKeySignatureBls48581.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (f *FrameVote) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != FrameVoteType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &f.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read proposer
	var proposerLen uint32
	if err := binary.Read(buf, binary.BigEndian, &proposerLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	f.Proposer = make([]byte, proposerLen)
	if _, err := buf.Read(f.Proposer); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read approve
	var approve uint8
	if err := binary.Read(buf, binary.BigEndian, &approve); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	f.Approve = approve != 0

	// Read public_key_signature_bls48581
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		f.PublicKeySignatureBls48581 = &BLS48581AddressedSignature{}
		if err := f.PublicKeySignatureBls48581.FromCanonicalBytes(
			sigBytes,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (f *FrameConfirmation) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(
		buf,
		binary.BigEndian,
		FrameConfirmationType,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, f.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write selector
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(f.Selector)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(f.Selector); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write aggregate_signature
	if f.AggregateSignature != nil {
		sigBytes, err := f.AggregateSignature.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(sigBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(sigBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (f *FrameConfirmation) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != FrameConfirmationType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &f.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read selector
	var selectorLen uint32
	if err := binary.Read(buf, binary.BigEndian, &selectorLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	f.Selector = make([]byte, selectorLen)
	if _, err := buf.Read(f.Selector); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read aggregate_signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if sigLen > 0 {
		sigBytes := make([]byte, sigLen)
		if _, err := buf.Read(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		f.AggregateSignature = &BLS48581AggregateSignature{}
		if err := f.AggregateSignature.FromCanonicalBytes(sigBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (g *GlobalFrame) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, GlobalFrameType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write header
	if g.Header != nil {
		headerBytes, err := g.Header.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(headerBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(headerBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write requests count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(g.Requests)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, request := range g.Requests {
		requestBytes, err := request.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(requestBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(requestBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (g *GlobalFrame) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != GlobalFrameType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read header
	var headerLen uint32
	if err := binary.Read(buf, binary.BigEndian, &headerLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if headerLen > 0 {
		headerBytes := make([]byte, headerLen)
		if _, err := buf.Read(headerBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		g.Header = &GlobalFrameHeader{}
		if err := g.Header.FromCanonicalBytes(headerBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read requests
	var requestsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &requestsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	g.Requests = make([]*MessageBundle, requestsCount)
	for i := uint32(0); i < requestsCount; i++ {
		var requestLen uint32
		if err := binary.Read(buf, binary.BigEndian, &requestLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		requestBytes := make([]byte, requestLen)
		if _, err := buf.Read(requestBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		g.Requests[i] = &MessageBundle{}
		if err := g.Requests[i].FromCanonicalBytes(requestBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (a *AppShardFrame) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, AppShardFrameType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write header
	if a.Header != nil {
		headerBytes, err := a.Header.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(headerBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(headerBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write requests count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(a.Requests)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, request := range a.Requests {
		requestBytes, err := request.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(requestBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(requestBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (a *AppShardFrame) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != AppShardFrameType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read header
	var headerLen uint32
	if err := binary.Read(buf, binary.BigEndian, &headerLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if headerLen > 0 {
		headerBytes := make([]byte, headerLen)
		if _, err := buf.Read(headerBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		a.Header = &FrameHeader{}
		if err := a.Header.FromCanonicalBytes(headerBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read requests
	var requestsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &requestsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	a.Requests = make([]*MessageBundle, requestsCount)
	for i := uint32(0); i < requestsCount; i++ {
		var requestLen uint32
		if err := binary.Read(buf, binary.BigEndian, &requestLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		requestBytes := make([]byte, requestLen)
		if _, err := buf.Read(requestBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		a.Requests[i] = &MessageBundle{}
		if err := a.Requests[i].FromCanonicalBytes(requestBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

// Multiproof serialization methods
func (m *Multiproof) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, MultiproofType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write multicommitment
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Multicommitment)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.Multicommitment); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write proof
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(m.Proof)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(m.Proof); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (m *Multiproof) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != MultiproofType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read multicommitment
	var commitLen uint32
	if err := binary.Read(buf, binary.BigEndian, &commitLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.Multicommitment = make([]byte, commitLen)
	if _, err := buf.Read(m.Multicommitment); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read proof
	var proofLen uint32
	if err := binary.Read(buf, binary.BigEndian, &proofLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	m.Proof = make([]byte, proofLen)
	if _, err := buf.Read(m.Proof); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

// Path serialization methods
func (p *Path) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, PathType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write indices count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Indices)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	// Write each index
	for _, index := range p.Indices {
		if err := binary.Write(buf, binary.BigEndian, index); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *Path) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != PathType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read indices count
	var indicesCount uint32
	if err := binary.Read(buf, binary.BigEndian, &indicesCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Indices = make([]uint64, indicesCount)
	// Read each index
	for i := uint32(0); i < indicesCount; i++ {
		if err := binary.Read(buf, binary.BigEndian, &p.Indices[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

// TraversalSubProof serialization methods
func (t *TraversalSubProof) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, TraversalSubProofType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write commits count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Commits)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	// Write each commit
	for _, commit := range t.Commits {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(commit)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(commit); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write ys count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Ys)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	// Write each y
	for _, y := range t.Ys {
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(y)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(y); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write paths count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.Paths)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	// Write each path
	for _, path := range t.Paths {
		pathBytes, err := path.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(pathBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(pathBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (t *TraversalSubProof) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != TraversalSubProofType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read commits count
	var commitsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &commitsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	t.Commits = make([][]byte, commitsCount)
	// Read each commit
	for i := uint32(0); i < commitsCount; i++ {
		var commitLen uint32
		if err := binary.Read(buf, binary.BigEndian, &commitLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.Commits[i] = make([]byte, commitLen)
		if _, err := buf.Read(t.Commits[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read ys count
	var ysCount uint32
	if err := binary.Read(buf, binary.BigEndian, &ysCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	t.Ys = make([][]byte, ysCount)
	// Read each y
	for i := uint32(0); i < ysCount; i++ {
		var yLen uint32
		if err := binary.Read(buf, binary.BigEndian, &yLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.Ys[i] = make([]byte, yLen)
		if _, err := buf.Read(t.Ys[i]); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read paths count
	var pathsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &pathsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	t.Paths = make([]*Path, pathsCount)
	// Read each path
	for i := uint32(0); i < pathsCount; i++ {
		var pathLen uint32
		if err := binary.Read(buf, binary.BigEndian, &pathLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		pathBytes := make([]byte, pathLen)
		if _, err := buf.Read(pathBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.Paths[i] = &Path{}
		if err := t.Paths[i].FromCanonicalBytes(pathBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

// TraversalProof serialization methods
func (t *TraversalProof) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, TraversalProofType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write multiproof
	if t.Multiproof != nil {
		multiproofBytes, err := t.Multiproof.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(multiproofBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(multiproofBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write sub_proofs count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(t.SubProofs)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	// Write each sub proof
	for _, subProof := range t.SubProofs {
		subProofBytes, err := subProof.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(subProofBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(subProofBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (t *TraversalProof) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != TraversalProofType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read multiproof
	var multiproofLen uint32
	if err := binary.Read(buf, binary.BigEndian, &multiproofLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if multiproofLen > 0 {
		multiproofBytes := make([]byte, multiproofLen)
		if _, err := buf.Read(multiproofBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.Multiproof = &Multiproof{}
		if err := t.Multiproof.FromCanonicalBytes(multiproofBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	// Read sub_proofs count
	var subProofsCount uint32
	if err := binary.Read(buf, binary.BigEndian, &subProofsCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	t.SubProofs = make([]*TraversalSubProof, subProofsCount)
	// Read each sub proof
	for i := uint32(0); i < subProofsCount; i++ {
		var subProofLen uint32
		if err := binary.Read(buf, binary.BigEndian, &subProofLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		subProofBytes := make([]byte, subProofLen)
		if _, err := buf.Read(subProofBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		t.SubProofs[i] = &TraversalSubProof{}
		if err := t.SubProofs[i].FromCanonicalBytes(subProofBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

// ProverKick serialization methods
func (p *ProverKick) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, ProverKickType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write frame_number
	if err := binary.Write(buf, binary.BigEndian, p.FrameNumber); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write kicked_prover_public_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.KickedProverPublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.KickedProverPublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write conflicting_frame_1
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.ConflictingFrame_1)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.ConflictingFrame_1); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write conflicting_frame_2
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.ConflictingFrame_2)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.ConflictingFrame_2); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write commitment
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Commitment)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Commitment); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write proof
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Proof)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Proof); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write traversal_proof
	if p.TraversalProof != nil {
		traversalBytes, err := p.TraversalProof.ToCanonicalBytes()
		if err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(traversalBytes)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(traversalBytes); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	} else {
		if err := binary.Write(buf, binary.BigEndian, uint32(0)); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	return buf.Bytes(), nil
}

func (p *ProverKick) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != ProverKickType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read frame_number
	if err := binary.Read(buf, binary.BigEndian, &p.FrameNumber); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read kicked_prover_public_key
	var keyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &keyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.KickedProverPublicKey = make([]byte, keyLen)
	if _, err := buf.Read(p.KickedProverPublicKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read conflicting_frame_1
	var frame1Len uint32
	if err := binary.Read(buf, binary.BigEndian, &frame1Len); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.ConflictingFrame_1 = make([]byte, frame1Len)
	if _, err := buf.Read(p.ConflictingFrame_1); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read conflicting_frame_2
	var frame2Len uint32
	if err := binary.Read(buf, binary.BigEndian, &frame2Len); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.ConflictingFrame_2 = make([]byte, frame2Len)
	if _, err := buf.Read(p.ConflictingFrame_2); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read commitment
	var commitmentLen uint32
	if err := binary.Read(buf, binary.BigEndian, &commitmentLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Commitment = make([]byte, commitmentLen)
	if _, err := buf.Read(p.Commitment); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read proof
	var proofLen uint32
	if err := binary.Read(buf, binary.BigEndian, &proofLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Proof = make([]byte, proofLen)
	if _, err := buf.Read(p.Proof); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read traversal_proof
	var traversalLen uint32
	if err := binary.Read(buf, binary.BigEndian, &traversalLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if traversalLen > 0 {
		traversalBytes := make([]byte, traversalLen)
		if _, err := buf.Read(traversalBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		p.TraversalProof = &TraversalProof{}
		if err := p.TraversalProof.FromCanonicalBytes(traversalBytes); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
	}

	return nil
}

func (g *GlobalAlert) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, GlobalAlertType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write message
	msgBytes := []byte(g.Message)
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(msgBytes)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(msgBytes); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(g.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(g.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (g *GlobalAlert) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != GlobalAlertType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read message
	var msgLen uint32
	if err := binary.Read(buf, binary.BigEndian, &msgLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	msgBytes := make([]byte, msgLen)
	if _, err := buf.Read(msgBytes); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	g.Message = string(msgBytes)

	// Read signature
	var sigLen uint32
	if err := binary.Read(buf, binary.BigEndian, &sigLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	g.Signature = make([]byte, sigLen)
	if _, err := buf.Read(g.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

var _ SignedMessage = (*LegacyProverRequest)(nil)

// ValidateSignature checks the signature of the announce prover request.
func (t *LegacyProverRequest) ValidateSignature() error {
	payload := []byte{}
	primary := t.PublicKeySignaturesEd448[0]
	for _, p := range t.PublicKeySignaturesEd448[1:] {
		payload = append(payload, p.PublicKey.KeyValue...)
		if err := p.verifyUnsafe(primary.PublicKey.KeyValue, []byte{}); err != nil {
			return errors.Wrap(err, "validate signature")
		}
	}
	if err := primary.verifyUnsafe(payload, []byte{}); err != nil {
		return errors.Wrap(err, "validate signature")
	}
	return nil
}

var _ ValidatableMessage = (*MessageRequest)(nil)

// Validate checks the message request.
func (m *MessageRequest) Validate() error {
	if m == nil {
		return errors.Wrap(errors.New("nil message request"), "validate")
	}
	switch {
	case m.GetJoin() != nil:
		return m.GetJoin().Validate()
	case m.GetLeave() != nil:
		return m.GetLeave().Validate()
	case m.GetPause() != nil:
		return m.GetPause().Validate()
	case m.GetResume() != nil:
		return m.GetResume().Validate()
	case m.GetConfirm() != nil:
		return m.GetConfirm().Validate()
	case m.GetReject() != nil:
		return m.GetReject().Validate()
	case m.GetKick() != nil:
		return m.GetKick().Validate()
	case m.GetUpdate() != nil:
		return m.GetUpdate().Validate()
	case m.GetTokenDeploy() != nil:
		return m.GetTokenDeploy().Validate()
	case m.GetTokenUpdate() != nil:
		return m.GetTokenUpdate().Validate()
	case m.GetTransaction() != nil:
		return m.GetTransaction().Validate()
	case m.GetPendingTransaction() != nil:
		return m.GetPendingTransaction().Validate()
	case m.GetMintTransaction() != nil:
		return m.GetMintTransaction().Validate()
	case m.GetHypergraphDeploy() != nil:
		return m.GetHypergraphDeploy().Validate()
	case m.GetHypergraphUpdate() != nil:
		return m.GetHypergraphUpdate().Validate()
	case m.GetVertexAdd() != nil:
		return m.GetVertexAdd().Validate()
	case m.GetVertexRemove() != nil:
		return m.GetVertexRemove().Validate()
	case m.GetHyperedgeAdd() != nil:
		return m.GetHyperedgeAdd().Validate()
	case m.GetHyperedgeRemove() != nil:
		return m.GetHyperedgeRemove().Validate()
	case m.GetComputeDeploy() != nil:
		return m.GetComputeDeploy().Validate()
	case m.GetComputeUpdate() != nil:
		return m.GetComputeUpdate().Validate()
	case m.GetCodeDeploy() != nil:
		return m.GetCodeDeploy().Validate()
	case m.GetCodeExecute() != nil:
		return m.GetCodeExecute().Validate()
	case m.GetCodeFinalize() != nil:
		return m.GetCodeFinalize().Validate()
	default:
		return nil
	}
}

var _ ValidatableMessage = (*MessageBundle)(nil)

// Validate checks the message bundle.
func (m *MessageBundle) Validate() error {
	if m == nil {
		return errors.Wrap(errors.New("nil message bundle"), "validate")
	}
	for i, request := range m.Requests {
		if request != nil {
			if err := request.Validate(); err != nil {
				return errors.Wrapf(err, "validate request at index %d", i)
			}
		}
	}
	if m.Timestamp == 0 {
		return errors.Wrap(errors.New("timestamp required"), "validate")
	}
	return nil
}

var _ ValidatableMessage = (*LegacyProverRequest)(nil)

// Validate checks the announce prover request.
func (t *LegacyProverRequest) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil announce prover request"), "validate")
	}
	if len(t.PublicKeySignaturesEd448) == 0 {
		return errors.Wrap(errors.New("invalid public key signatures"), "validate")
	}
	for _, p := range t.PublicKeySignaturesEd448 {
		if err := p.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}
	if err := t.ValidateSignature(); err != nil {
		return errors.Wrap(err, "validate")
	}
	return nil
}

var _ ValidatableMessage = (*ProverJoin)(nil)

// Validate checks the announce prover join.
func (t *ProverJoin) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil announce prover join"), "validate")
	}
	if len(t.Filters) == 0 {
		return errors.Wrap(errors.New("no filters provided"), "validate")
	}
	for _, filter := range t.Filters {
		if len(filter) != 32 && len(filter) != 64 {
			return errors.Wrap(errors.New("invalid filter"), "validate")
		}
	}
	if t.PublicKeySignatureBls48581 != nil {
		if err := t.PublicKeySignatureBls48581.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}

	return nil
}

var _ ValidatableMessage = (*ProverLeave)(nil)

// Validate checks the announce prover leave.
func (t *ProverLeave) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil announce prover leave"), "validate")
	}
	if len(t.Filters) == 0 {
		return errors.Wrap(errors.New("no filters provided"), "validate")
	}
	for _, filter := range t.Filters {
		if len(filter) != 32 && len(filter) != 64 {
			return errors.Wrap(errors.New("invalid filter"), "validate")
		}
	}
	if err := t.PublicKeySignatureBls48581.Validate(); err != nil {
		return errors.Wrap(err, "validate")
	}

	return nil
}

var _ ValidatableMessage = (*ProverPause)(nil)

// Validate checks the announce prover pause.
func (t *ProverPause) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil announce prover pause"), "validate")
	}
	if len(t.Filter) != 32 {
		return errors.Wrap(errors.New("invalid filter"), "validate")
	}
	if err := t.PublicKeySignatureBls48581.Validate(); err != nil {
		return errors.Wrap(err, "public key signature")
	}

	return nil
}

var _ ValidatableMessage = (*ProverResume)(nil)

// Validate checks the announce prover resume.
func (t *ProverResume) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil announce prover resume"), "validate")
	}
	if len(t.Filter) != 32 {
		return errors.Wrap(errors.New("invalid filter"), "validate")
	}
	if err := t.PublicKeySignatureBls48581.Validate(); err != nil {
		return errors.Wrap(err, "public key signature")
	}
	return nil
}

// SignableED448Message is a message that can be signed.
type SignableED448Message interface {
	// SignED448 signs the message with the given key, modifying the message.
	// The message contents are expected to be valid - message contents must be
	// validated, or correctly constructed, before signing.
	SignED448(publicKey []byte, sign func([]byte) ([]byte, error)) error
}

func newED448Signature(publicKey, signature []byte) *Ed448Signature {
	return &Ed448Signature{
		PublicKey: &Ed448PublicKey{
			KeyValue: publicKey,
		},
		Signature: signature,
	}
}

type ED448SignHelper struct {
	PublicKey []byte
	Sign      func([]byte) ([]byte, error)
}

type BLS48581SignHelper struct {
	PublicKey []byte
	Sign      func([]byte) ([]byte, error)
}

// SignED448 signs the announce prover request with the given keys.
func (t *LegacyProverRequest) SignED448(helpers []ED448SignHelper) error {
	if len(helpers) == 0 {
		return errors.Wrap(errors.New("no keys"), "sign ed448")
	}
	payload := []byte{}
	primary := helpers[0]
	signatures := make([]*Ed448Signature, len(helpers))
	for i, k := range helpers[1:] {
		payload = append(payload, k.PublicKey...)
		signature, err := k.Sign(primary.PublicKey)
		if err != nil {
			return errors.Wrap(err, "sign ed448")
		}
		signatures[i+1] = newED448Signature(k.PublicKey, signature)
	}
	signature, err := primary.Sign(payload)
	if err != nil {
		return errors.Wrap(err, "sign ed448")
	}
	signatures[0] = newED448Signature(primary.PublicKey, signature)
	t.PublicKeySignaturesEd448 = signatures
	return nil
}

var _ ValidatableMessage = (*ProverConfirm)(nil)

// Validate checks the prover confirm.
func (t *ProverConfirm) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil prover confirm"), "validate")
	}
	if len(t.Filter) != 32 && len(t.Filter) != 64 {
		return errors.Wrap(errors.New("invalid filter"), "validate")
	}
	if err := t.PublicKeySignatureBls48581.Validate(); err != nil {
		return errors.Wrap(err, "public key signature")
	}
	return nil
}

var _ ValidatableMessage = (*ProverReject)(nil)

// Validate checks the prover reject.
func (t *ProverReject) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil prover reject"), "validate")
	}
	if len(t.Filter) != 32 && len(t.Filter) != 64 {
		return errors.Wrap(errors.New("invalid filter"), "validate")
	}
	if err := t.PublicKeySignatureBls48581.Validate(); err != nil {
		return errors.Wrap(err, "public key signature")
	}
	return nil
}

var _ ValidatableMessage = (*ProverUpdate)(nil)

// Validate checks the prover update.
func (p *ProverUpdate) Validate() error {
	if p == nil {
		return errors.Wrap(errors.New("nil prover update"), "validate")
	}
	if len(p.DelegateAddress) == 0 {
		return errors.Wrap(errors.New("delegate address is empty"), "validate")
	}
	if p.PublicKeySignatureBls48581 == nil {
		return errors.Wrap(errors.New("public key signature is nil"), "validate")
	}
	if err := p.PublicKeySignatureBls48581.Validate(); err != nil {
		return errors.Wrap(err, "validate signature")
	}
	return nil
}

var _ ValidatableMessage = (*ProverKick)(nil)

// Validate checks the prover kick.
func (t *ProverKick) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil prover kick"), "validate")
	}
	if len(t.KickedProverPublicKey) == 0 {
		return errors.Wrap(
			errors.New("kicked prover public key is empty"),
			"validate",
		)
	}
	if len(t.ConflictingFrame_1) == 0 {
		return errors.Wrap(errors.New("conflicting frame 1 is empty"), "validate")
	}
	if len(t.ConflictingFrame_2) == 0 {
		return errors.Wrap(errors.New("conflicting frame 2 is empty"), "validate")
	}
	if len(t.Commitment) == 0 {
		return errors.Wrap(errors.New("commitment is empty"), "validate")
	}
	if len(t.Proof) == 0 {
		return errors.Wrap(errors.New("proof is empty"), "validate")
	}
	// TraversalProof is optional
	if t.TraversalProof != nil {
		if err := t.TraversalProof.Validate(); err != nil {
			return errors.Wrap(err, "traversal proof")
		}
	}
	return nil
}

var _ ValidatableMessage = (*SeniorityMerge)(nil)

// Validate checks the seniority merge.
func (t *SeniorityMerge) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil seniority merge"), "validate")
	}
	if len(t.Signature) != 74 {
		return errors.Wrap(errors.New("invalid signature length"), "validate")
	}
	if len(t.ProverPublicKey) == 0 {
		return errors.Wrap(errors.New("prover public key is empty"), "validate")
	}
	return nil
}

var _ ValidatableMessage = (*Multiproof)(nil)

// Validate checks the multiproof.
func (t *Multiproof) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil multiproof"), "validate")
	}
	if len(t.Multicommitment) == 0 {
		return errors.Wrap(errors.New("multicommitment is empty"), "validate")
	}
	if len(t.Proof) == 0 {
		return errors.Wrap(errors.New("proof is empty"), "validate")
	}
	return nil
}

var _ ValidatableMessage = (*Path)(nil)

// Validate checks the path.
func (t *Path) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil path"), "validate")
	}
	// Path can have empty indices
	return nil
}

var _ ValidatableMessage = (*TraversalSubProof)(nil)

// Validate checks the traversal sub proof.
func (t *TraversalSubProof) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil traversal sub proof"), "validate")
	}
	if len(t.Commits) == 0 {
		return errors.Wrap(errors.New("no commits in sub proof"), "validate")
	}
	if len(t.Ys) == 0 {
		return errors.Wrap(errors.New("no ys in sub proof"), "validate")
	}
	if len(t.Paths) == 0 {
		return errors.Wrap(errors.New("no paths in sub proof"), "validate")
	}
	// All arrays should have the same length
	if len(t.Commits) != len(t.Ys) || len(t.Commits) != len(t.Paths) {
		return errors.Wrap(
			errors.New("mismatched array lengths in sub proof"),
			"validate",
		)
	}
	for _, path := range t.Paths {
		if err := path.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}
	return nil
}

var _ ValidatableMessage = (*TraversalProof)(nil)

// Validate checks the traversal proof.
func (t *TraversalProof) Validate() error {
	if t == nil {
		return errors.Wrap(errors.New("nil traversal proof"), "validate")
	}
	if t.Multiproof == nil {
		return errors.Wrap(errors.New("nil multiproof"), "validate")
	}
	if err := t.Multiproof.Validate(); err != nil {
		return errors.Wrap(err, "validate")
	}
	if len(t.SubProofs) == 0 {
		return errors.Wrap(errors.New("no sub proofs"), "validate")
	}
	for _, subProof := range t.SubProofs {
		if err := subProof.Validate(); err != nil {
			return errors.Wrap(err, "validate")
		}
	}
	return nil
}

var _ ValidatableMessage = (*GlobalFrameHeader)(nil)

func (h *GlobalFrameHeader) Validate() error {
	if h == nil {
		return errors.Wrap(errors.New("nil global frame header"), "validate")
	}

	// Frame number is uint64, any value is valid

	// Timestamp should be reasonable (not 0, not too far in future)
	if h.Timestamp == 0 {
		return errors.Wrap(errors.New("invalid timestamp"), "validate")
	}

	// Difficulty should be non-zero
	if h.Difficulty == 0 {
		return errors.Wrap(errors.New("invalid difficulty"), "validate")
	}

	// Output should be 516 bytes (258 byte Y + 258 byte proof)
	if len(h.Output) != 516 {
		return errors.Wrap(errors.New("invalid output length"), "validate")
	}

	// Parent selector should be 32 bytes
	if len(h.ParentSelector) != 32 {
		return errors.Wrap(errors.New("invalid parent selector length"), "validate")
	}

	// Global commitments should be exactly 256 entries
	if len(h.GlobalCommitments) != 256 {
		return errors.Wrap(
			errors.New("invalid global commitments count"),
			"validate",
		)
	}

	// Each commitment should be 64 or 74 bytes
	for i, commitment := range h.GlobalCommitments {
		if len(commitment) != 64 && len(commitment) != 74 {
			return errors.Wrapf(
				errors.New("invalid commitment length"),
				"validate: commitment %d",
				i,
			)
		}
	}

	// Prover tree commitment should be 64 or 74 bytes
	if len(h.ProverTreeCommitment) != 64 && len(h.ProverTreeCommitment) != 74 {
		return errors.Wrap(
			errors.New("invalid prover tree commitment length"),
			"validate",
		)
	}

	// Signature must be present
	if h.PublicKeySignatureBls48581 == nil {
		return errors.Wrap(errors.New("missing signature"), "validate")
	}

	return nil
}

var _ ValidatableMessage = (*FrameHeader)(nil)

func (h *FrameHeader) Validate() error {
	if h == nil {
		return errors.Wrap(errors.New("nil frame header"), "validate")
	}

	// Address should be 32 to 64 bytes
	if len(h.Address) < 32 || len(h.Address) > 64 {
		return errors.Wrap(errors.New("invalid address length"), "validate")
	}

	// Frame number is uint64, any value is valid

	// Timestamp should be reasonable (not 0)
	if h.Timestamp == 0 {
		return errors.Wrap(errors.New("invalid timestamp"), "validate")
	}

	// Difficulty should be non-zero
	if h.Difficulty == 0 {
		return errors.Wrap(errors.New("invalid difficulty"), "validate")
	}

	// Output should be 516 bytes
	if len(h.Output) != 516 {
		return errors.Wrap(errors.New("invalid output length"), "validate")
	}

	// Parent selector should be 32 bytes
	if len(h.ParentSelector) != 32 {
		return errors.Wrap(errors.New("invalid parent selector length"), "validate")
	}

	// Requests root should be 64 or 74 bytes
	if len(h.RequestsRoot) != 64 && len(h.RequestsRoot) != 74 {
		return errors.Wrap(errors.New("invalid requests root length"), "validate")
	}

	// State roots should be exactly 4 entries
	if len(h.StateRoots) != 4 {
		return errors.Wrap(errors.New("invalid state roots count"), "validate")
	}

	// Each state root should be 64 or 74 bytes
	for i, root := range h.StateRoots {
		if len(root) != 64 && len(root) != 74 {
			return errors.Wrapf(
				errors.New("invalid state root length"),
				"validate: state root %d",
				i,
			)
		}
	}

	// Prover should be 32 bytes
	if len(h.Prover) != 32 {
		return errors.Wrap(errors.New("invalid prover length"), "validate")
	}

	// Fee multiplier vote is uint64, any value is valid

	// Signature must be present
	if h.PublicKeySignatureBls48581 == nil {
		return errors.Wrap(errors.New("missing signature"), "validate")
	}

	return nil
}

var _ ValidatableMessage = (*ProverLivenessCheck)(nil)

func (p *ProverLivenessCheck) Validate() error {
	if p == nil {
		return errors.Wrap(errors.New("nil prover liveness check"), "validate")
	}

	// Filter should be 64 bytes or fewer
	if len(p.Filter) > 64 {
		return errors.Wrap(errors.New("invalid filter length"), "validate")
	}

	// Commitment hash should be 32 bytes
	if len(p.CommitmentHash) != 32 {
		return errors.Wrap(errors.New("invalid commitment hash length"), "validate")
	}

	// Signature must be present
	if p.PublicKeySignatureBls48581 == nil {
		return errors.Wrap(errors.New("missing signature"), "validate")
	}

	// Validate the signature
	if err := p.PublicKeySignatureBls48581.Validate(); err != nil {
		return errors.Wrap(err, "validate")
	}

	return nil
}

var _ ValidatableMessage = (*FrameVote)(nil)

func (f *FrameVote) Validate() error {
	if f == nil {
		return errors.Wrap(errors.New("nil frame vote"), "validate")
	}

	// Frame number is uint64, any value is valid

	// Proposer should be 32 bytes
	if len(f.Proposer) != 32 {
		return errors.Wrap(errors.New("invalid proposer length"), "validate")
	}

	// Approve is bool, any value is valid

	// Signature must be present
	if f.PublicKeySignatureBls48581 == nil {
		return errors.Wrap(errors.New("missing signature"), "validate")
	}

	// Validate the signature
	if err := f.PublicKeySignatureBls48581.Validate(); err != nil {
		return errors.Wrap(err, "validate")
	}

	return nil
}

var _ ValidatableMessage = (*FrameConfirmation)(nil)

func (f *FrameConfirmation) Validate() error {
	if f == nil {
		return errors.Wrap(errors.New("nil frame confirmation"), "validate")
	}

	// Frame number is uint64, any value is valid

	// Selector should be 32 bytes
	if len(f.Selector) != 32 {
		return errors.Wrap(
			errors.Errorf("invalid selector length: %d", len(f.Selector)),
			"validate",
		)
	}

	// Aggregate signature must be present
	if f.AggregateSignature == nil {
		return errors.Wrap(errors.New("missing aggregate signature"), "validate")
	}

	return nil
}

var _ ValidatableMessage = (*GlobalFrame)(nil)

func (g *GlobalFrame) Validate() error {
	if g == nil {
		return errors.Wrap(errors.New("nil global frame"), "validate")
	}

	// Header must be present and valid
	if g.Header == nil {
		return errors.Wrap(errors.New("missing header"), "validate")
	}
	if err := g.Header.Validate(); err != nil {
		return errors.Wrap(err, "validate")
	}

	// Validate each request
	for i, request := range g.Requests {
		if request == nil {
			return errors.Wrapf(
				errors.New("nil request"),
				"validate: request %d",
				i,
			)
		}
		if err := request.Validate(); err != nil {
			return errors.Wrapf(err, "validate: request %d", i)
		}
	}

	return nil
}

var _ ValidatableMessage = (*AppShardFrame)(nil)

func (a *AppShardFrame) Validate() error {
	if a == nil {
		return errors.Wrap(errors.New("nil app shard frame"), "validate")
	}

	// Header must be present and valid
	if a.Header == nil {
		return errors.Wrap(errors.New("missing header"), "validate")
	}
	if err := a.Header.Validate(); err != nil {
		return errors.Wrap(err, "validate")
	}

	// Requests are raw bytes, no specific validation needed
	// Each request will be validated when deserialized

	return nil
}

var _ ValidatableMessage = (*PeerInfo)(nil)

// Validate checks the PeerInfo message.
func (p *PeerInfo) Validate() error {
	if p == nil {
		return errors.Wrap(errors.New("nil peer info"), "validate")
	}

	// Validate peer_id
	if len(p.PeerId) == 0 {
		return errors.Wrap(errors.New("missing peer id"), "validate")
	}

	// Validate reachability entries
	for _, reach := range p.Reachability {
		if reach == nil {
			return errors.Wrap(errors.New("nil reachability entry"), "validate")
		}

		// Validate filter in reachability
		if len(reach.Filter) > 64 {
			return errors.Wrap(
				errors.New("invalid filter size in reachability"),
				"validate",
			)
		}

		// Validate pubsub multiaddrs
		for _, addr := range reach.PubsubMultiaddrs {
			if addr == "" {
				return errors.Wrap(errors.New("empty pubsub multiaddr"), "validate")
			}
			if _, err := multiaddr.StringCast(addr); err != nil {
				return errors.Wrap(err, "validate pubsub multiaddr")
			}
		}

		// Validate stream multiaddrs
		for _, addr := range reach.StreamMultiaddrs {
			if addr == "" {
				return errors.Wrap(errors.New("empty stream multiaddr"), "validate")
			}
			if _, err := multiaddr.StringCast(addr); err != nil {
				return errors.Wrap(err, "validate stream multiaddr")
			}
		}
	}

	now := time.Now().UnixMilli()

	// Timestamp is int64
	if p.Timestamp < now-5000 || p.Timestamp > now+5000 {
		return errors.Wrap(errors.New("invalid timestamp"), "validate")
	}

	// Validate version
	if len(p.Version) == 0 {
		return errors.Wrap(errors.New("missing version"), "validate")
	}

	// Validate patch version
	if len(p.PatchVersion) == 0 {
		return errors.Wrap(errors.New("missing patch version"), "validate")
	}

	// Validate capabilities
	if len(p.Capabilities) == 0 {
		return errors.Wrap(errors.New("missing capabilities"), "validate")
	}

	for _, cap := range p.Capabilities {
		if cap == nil {
			return errors.Wrap(errors.New("nil capability"), "validate")
		}

		// Protocol identifier should be non-zero
		if cap.ProtocolIdentifier == 0 {
			return errors.Wrap(errors.New("invalid protocol identifier"), "validate")
		}
	}

	// Validate signature
	if len(p.Signature) != 114 {
		return errors.Wrap(errors.New("invalid signature length"), "validate")
	}

	// Validate public key (Ed448 public key should be 57 bytes)
	if len(p.PublicKey) != 57 {
		return errors.Wrap(errors.New("invalid public key length"), "validate")
	}

	return nil
}

var _ ValidatableMessage = (*GlobalAlert)(nil)

// Validate checks the GlobalAlert message.
func (g *GlobalAlert) Validate() error {
	if g == nil {
		return errors.Wrap(errors.New("nil global alert"), "validate")
	}

	// Validate message content
	if g.Message == "" {
		return errors.Wrap(errors.New("empty alert message"), "validate")
	}

	// Validate signature
	if len(g.Signature) != 114 {
		return errors.Wrap(errors.New("invalid signature"), "validate")
	}

	return nil
}
