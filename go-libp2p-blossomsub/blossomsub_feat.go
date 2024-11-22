package blossomsub

import (
	"fmt"

	"github.com/libp2p/go-libp2p/core/protocol"
)

// BlossomSubFeatureTest is a feature test function; it takes a feature and a protocol ID and
// should return true if the feature is supported by the protocol
type BlossomSubFeatureTest = func(BlossomSubFeature, protocol.ID) bool

// BlossomSubFeature is a feature discriminant enum
type BlossomSubFeature int

const (
	// Protocol supports basic BlossomSub Mesh -- BlossomSub-v2 compatible
	BlossomSubFeatureMesh = iota
	// Protocol supports Peer eXchange on prune -- BlossomSub-v2 compatible
	BlossomSubFeaturePX
	// Protocol supports IDONTWANT -- BlossomSub-v2.1 compatible
	BlossomSubFeatureIdontwant
)

// BlossomSubDefaultProtocols is the default BlossomSub router protocol list
var BlossomSubDefaultProtocols = []protocol.ID{BlossomSubID_v21, BlossomSubID_v2}

// BlossomSubDefaultFeatures is the feature test function for the default BlossomSub protocols
func BlossomSubDefaultFeatures(feat BlossomSubFeature, proto protocol.ID) bool {
	switch feat {
	case BlossomSubFeatureMesh:
		return proto == BlossomSubID_v21 || proto == BlossomSubID_v2
	case BlossomSubFeaturePX:
		return proto == BlossomSubID_v21 || proto == BlossomSubID_v2
	case BlossomSubFeatureIdontwant:
		return proto == BlossomSubID_v21
	default:
		return false
	}
}

// WithBlossomSubProtocols is a BlossomSub router option that configures a custom protocol list
// and feature test function
func WithBlossomSubProtocols(protos []protocol.ID, feature BlossomSubFeatureTest) Option {
	return func(ps *PubSub) error {
		gs, ok := ps.rt.(*BlossomSubRouter)
		if !ok {
			return fmt.Errorf("pubsub router is not BlossomSub")
		}

		gs.protos = protos
		gs.feature = feature

		return nil
	}
}
