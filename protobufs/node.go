package protobufs

import (
	"bytes"
	"encoding/binary"

	"github.com/pkg/errors"
)

func (p *PeerInfo) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, PeerInfoType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write peer_id
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.PeerId)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.PeerId); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write reachability count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Reachability)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, reach := range p.Reachability {
		// Write filter
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(reach.Filter)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(reach.Filter); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}

		// Write pubsub_multiaddrs count
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(reach.PubsubMultiaddrs)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		for _, addr := range reach.PubsubMultiaddrs {
			if err := binary.Write(
				buf,
				binary.BigEndian,
				uint32(len(addr)),
			); err != nil {
				return nil, errors.Wrap(err, "to canonical bytes")
			}
			if _, err := buf.WriteString(addr); err != nil {
				return nil, errors.Wrap(err, "to canonical bytes")
			}
		}

		// Write stream_multiaddrs count
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(reach.StreamMultiaddrs)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		for _, addr := range reach.StreamMultiaddrs {
			if err := binary.Write(
				buf,
				binary.BigEndian,
				uint32(len(addr)),
			); err != nil {
				return nil, errors.Wrap(err, "to canonical bytes")
			}
			if _, err := buf.WriteString(addr); err != nil {
				return nil, errors.Wrap(err, "to canonical bytes")
			}
		}
	}

	// Write timestamp
	if err := binary.Write(buf, binary.BigEndian, p.Timestamp); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write version
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Version)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Version); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write patch_version
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.PatchVersion)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.PatchVersion); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write capabilities count
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Capabilities)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	for _, cap := range p.Capabilities {
		// Write protocol_identifier
		if err := binary.Write(
			buf,
			binary.BigEndian,
			cap.ProtocolIdentifier,
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		// Write additional_metadata
		if err := binary.Write(
			buf,
			binary.BigEndian,
			uint32(len(cap.AdditionalMetadata)),
		); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
		if _, err := buf.Write(cap.AdditionalMetadata); err != nil {
			return nil, errors.Wrap(err, "to canonical bytes")
		}
	}

	// Write public_key
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.PublicKey)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.PublicKey); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write signature
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(p.Signature)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(p.Signature); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (p *PeerInfo) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != PeerInfoType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read peer_id
	var peerIdLen uint32
	if err := binary.Read(buf, binary.BigEndian, &peerIdLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.PeerId = make([]byte, peerIdLen)
	if _, err := buf.Read(p.PeerId); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read reachability
	var reachCount uint32
	if err := binary.Read(buf, binary.BigEndian, &reachCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Reachability = make([]*Reachability, reachCount)
	for i := uint32(0); i < reachCount; i++ {
		reach := &Reachability{}

		// Read filter
		var filterLen uint32
		if err := binary.Read(buf, binary.BigEndian, &filterLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		reach.Filter = make([]byte, filterLen)
		if _, err := buf.Read(reach.Filter); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}

		// Read pubsub_multiaddrs
		var pubsubCount uint32
		if err := binary.Read(buf, binary.BigEndian, &pubsubCount); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		reach.PubsubMultiaddrs = make([]string, pubsubCount)
		for j := uint32(0); j < pubsubCount; j++ {
			var addrLen uint32
			if err := binary.Read(buf, binary.BigEndian, &addrLen); err != nil {
				return errors.Wrap(err, "from canonical bytes")
			}
			addrBytes := make([]byte, addrLen)
			if _, err := buf.Read(addrBytes); err != nil {
				return errors.Wrap(err, "from canonical bytes")
			}
			reach.PubsubMultiaddrs[j] = string(addrBytes)
		}

		// Read stream_multiaddrs
		var streamCount uint32
		if err := binary.Read(buf, binary.BigEndian, &streamCount); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		reach.StreamMultiaddrs = make([]string, streamCount)
		for j := uint32(0); j < streamCount; j++ {
			var addrLen uint32
			if err := binary.Read(buf, binary.BigEndian, &addrLen); err != nil {
				return errors.Wrap(err, "from canonical bytes")
			}
			addrBytes := make([]byte, addrLen)
			if _, err := buf.Read(addrBytes); err != nil {
				return errors.Wrap(err, "from canonical bytes")
			}
			reach.StreamMultiaddrs[j] = string(addrBytes)
		}

		p.Reachability[i] = reach
	}

	// Read timestamp
	if err := binary.Read(buf, binary.BigEndian, &p.Timestamp); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read version
	var versionLen uint32
	if err := binary.Read(buf, binary.BigEndian, &versionLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Version = make([]byte, versionLen)
	if _, err := buf.Read(p.Version); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read patch_version
	var patchVersionLen uint32
	if err := binary.Read(buf, binary.BigEndian, &patchVersionLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.PatchVersion = make([]byte, patchVersionLen)
	if _, err := buf.Read(p.PatchVersion); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read capabilities
	var capCount uint32
	if err := binary.Read(buf, binary.BigEndian, &capCount); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Capabilities = make([]*Capability, capCount)
	for i := uint32(0); i < capCount; i++ {
		cap := &Capability{}

		// Read protocol_identifier
		if err := binary.Read(
			buf,
			binary.BigEndian,
			&cap.ProtocolIdentifier,
		); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}

		// Read additional_metadata
		var metadataLen uint32
		if err := binary.Read(buf, binary.BigEndian, &metadataLen); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}
		cap.AdditionalMetadata = make([]byte, metadataLen)
		if _, err := buf.Read(cap.AdditionalMetadata); err != nil {
			return errors.Wrap(err, "from canonical bytes")
		}

		p.Capabilities[i] = cap
	}

	// Read public_key
	var publicKeyLen uint32
	if err := binary.Read(buf, binary.BigEndian, &publicKeyLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.PublicKey = make([]byte, publicKeyLen)
	if _, err := buf.Read(p.PublicKey); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read signature
	var signatureLen uint32
	if err := binary.Read(buf, binary.BigEndian, &signatureLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	p.Signature = make([]byte, signatureLen)
	if _, err := buf.Read(p.Signature); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}

func (c *Capability) ToCanonicalBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type prefix
	if err := binary.Write(buf, binary.BigEndian, CapabilityType); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write protocol_identifier
	if err := binary.Write(
		buf,
		binary.BigEndian,
		c.ProtocolIdentifier,
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	// Write additional_metadata
	if err := binary.Write(
		buf,
		binary.BigEndian,
		uint32(len(c.AdditionalMetadata)),
	); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}
	if _, err := buf.Write(c.AdditionalMetadata); err != nil {
		return nil, errors.Wrap(err, "to canonical bytes")
	}

	return buf.Bytes(), nil
}

func (c *Capability) FromCanonicalBytes(data []byte) error {
	buf := bytes.NewBuffer(data)

	// Read and verify type prefix
	var typePrefix uint32
	if err := binary.Read(buf, binary.BigEndian, &typePrefix); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	if typePrefix != CapabilityType {
		return errors.Wrap(
			errors.New("invalid type prefix"),
			"from canonical bytes",
		)
	}

	// Read protocol_identifier
	if err := binary.Read(
		buf,
		binary.BigEndian,
		&c.ProtocolIdentifier,
	); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	// Read additional_metadata
	var metadataLen uint32
	if err := binary.Read(buf, binary.BigEndian, &metadataLen); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}
	c.AdditionalMetadata = make([]byte, metadataLen)
	if _, err := buf.Read(c.AdditionalMetadata); err != nil {
		return errors.Wrap(err, "from canonical bytes")
	}

	return nil
}
