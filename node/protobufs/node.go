package protobufs

import (
	"encoding/binary"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
)

func (t *TokenRequest) Priority() uint64 {
	switch p := t.Request.(type) {
	case *TokenRequest_Mint:
		if len(p.Mint.Proofs) >= 3 {
			return binary.BigEndian.Uint64(p.Mint.Proofs[2])
		}
	}
	return 0
}

func (t *MintCoinRequest) RingAndParallelism(
	ringCalc func(addr []byte) int,
) (int, uint32, error) {
	pk, err := pcrypto.UnmarshalEd448PublicKey(
		t.Signature.PublicKey.KeyValue,
	)
	if err != nil {
		return -1, 0, errors.New("invalid")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return -1, 0, errors.New("invalid")
	}

	altAddr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		return -1, 0, errors.New("invalid")
	}

	ring := ringCalc(altAddr.FillBytes(make([]byte, 32)))
	if ring == -1 {
		return -1, 0, errors.New("invalid")
	}

	if t.Proofs != nil && len(t.Proofs) >= 3 && len(t.Proofs[1]) == 4 {
		return ring, binary.BigEndian.Uint32(t.Proofs[1]), nil
	}

	return -1, 0, errors.New("invalid")
}

// TokenRequest returns the TokenRequest for the TransferCoinRequest.
func (t *TransferCoinRequest) TokenRequest() *TokenRequest {
	return &TokenRequest{
		Request: &TokenRequest_Transfer{
			Transfer: t,
		},
		Timestamp: time.Now().UnixMilli(),
	}
}

// TokenRequest returns the TokenRequest for the SplitCoinRequest.
func (t *SplitCoinRequest) TokenRequest() *TokenRequest {
	return &TokenRequest{
		Request: &TokenRequest_Split{
			Split: t,
		},
		Timestamp: time.Now().UnixMilli(),
	}
}

// TokenRequest returns the TokenRequest for the MergeCoinRequest.
func (t *MergeCoinRequest) TokenRequest() *TokenRequest {
	return &TokenRequest{
		Request: &TokenRequest_Merge{
			Merge: t,
		},
		Timestamp: time.Now().UnixMilli(),
	}
}

// TokenRequest returns the TokenRequest for the MintCoinRequest.
func (t *MintCoinRequest) TokenRequest() *TokenRequest {
	return &TokenRequest{
		Request: &TokenRequest_Mint{
			Mint: t,
		},
		Timestamp: time.Now().UnixMilli(),
	}
}

// TokenRequest returns the TokenRequest for the AnnounceProverRequest.
func (t *AnnounceProverRequest) TokenRequest() *TokenRequest {
	return &TokenRequest{
		Request: &TokenRequest_Announce{
			Announce: t,
		},
		Timestamp: time.Now().UnixMilli(),
	}
}

// TokenRequest returns the TokenRequest for the AnnounceProverJoin.
func (t *AnnounceProverJoin) TokenRequest() *TokenRequest {
	return &TokenRequest{
		Request: &TokenRequest_Join{
			Join: t,
		},
		Timestamp: time.Now().UnixMilli(),
	}
}

// TokenRequest returns the TokenRequest for the AnnounceProverLeave.
func (t *AnnounceProverLeave) TokenRequest() *TokenRequest {
	return &TokenRequest{
		Request: &TokenRequest_Leave{
			Leave: t,
		},
		Timestamp: time.Now().UnixMilli(),
	}
}

// TokenRequest returns the TokenRequest for the AnnounceProverPause.
func (t *AnnounceProverPause) TokenRequest() *TokenRequest {
	return &TokenRequest{
		Request: &TokenRequest_Pause{
			Pause: t,
		},
		Timestamp: time.Now().UnixMilli(),
	}
}

// TokenRequest returns the TokenRequest for the AnnounceProverResume.
func (t *AnnounceProverResume) TokenRequest() *TokenRequest {
	return &TokenRequest{
		Request: &TokenRequest_Resume{
			Resume: t,
		},
		Timestamp: time.Now().UnixMilli(),
	}
}
