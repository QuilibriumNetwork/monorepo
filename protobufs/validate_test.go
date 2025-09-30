package protobufs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMessageCiphertext_Validate(t *testing.T) {
	tests := []struct {
		name    string
		msg     *MessageCiphertext
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid with 12 byte IV",
			msg: &MessageCiphertext{
				InitializationVector: make([]byte, 12),
				Ciphertext:           []byte("test"),
				AssociatedData:       []byte("data"),
			},
			wantErr: false,
		},
		{
			name: "empty fields valid",
			msg: &MessageCiphertext{
				InitializationVector: []byte{},
				Ciphertext:           []byte{},
				AssociatedData:       []byte{},
			},
			wantErr: false,
		},
		{
			name:    "nil message",
			msg:     nil,
			wantErr: true,
			errMsg:  "message ciphertext is nil",
		},
		{
			name: "invalid IV length",
			msg: &MessageCiphertext{
				InitializationVector: make([]byte, 16),
			},
			wantErr: true,
			errMsg:  "initialization vector must be 12 bytes, got 16",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEd448Signature_Validate(t *testing.T) {
	tests := []struct {
		name    string
		sig     *Ed448Signature
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid signature",
			sig: &Ed448Signature{
				Signature: make([]byte, 114),
				PublicKey: &Ed448PublicKey{
					KeyValue: make([]byte, 57),
				},
			},
			wantErr: false,
		},
		{
			name: "empty signature invalid",
			sig: &Ed448Signature{
				Signature: []byte{},
			},
			wantErr: true,
			errMsg:  "nil ed448 public key",
		},
		{
			name:    "nil signature",
			sig:     nil,
			wantErr: true,
			errMsg:  "nil ed448 signature",
		},
		{
			name: "invalid signature length",
			sig: &Ed448Signature{
				Signature: make([]byte, 100),
			},
			wantErr: true,
			errMsg:  "nil ed448 public key",
		},
		{
			name: "invalid public key",
			sig: &Ed448Signature{
				Signature: make([]byte, 114),
				PublicKey: &Ed448PublicKey{
					KeyValue: make([]byte, 32),
				},
			},
			wantErr: true,
			errMsg:  "invalid ed448 public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sig.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBLS48581SignatureWithProofOfPossession_Validate(t *testing.T) {
	tests := []struct {
		name    string
		sig     *BLS48581SignatureWithProofOfPossession
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid signature with PoP",
			sig: &BLS48581SignatureWithProofOfPossession{
				Signature:    make([]byte, 74),
				PopSignature: make([]byte, 74),
				PublicKey: &BLS48581G2PublicKey{
					KeyValue: make([]byte, 585),
				},
			},
			wantErr: false,
		},
		{
			name: "empty fields invalid",
			sig: &BLS48581SignatureWithProofOfPossession{
				Signature:    []byte{},
				PopSignature: []byte{},
			},
			wantErr: true,
			errMsg:  "invalid bls48581 public key",
		},
		{
			name:    "nil signature",
			sig:     nil,
			wantErr: true,
			errMsg:  "nil bls48581 signature",
		},
		{
			name: "invalid signature length",
			sig: &BLS48581SignatureWithProofOfPossession{
				Signature:    make([]byte, 50),
				PopSignature: make([]byte, 74),
			},
			wantErr: true,
			errMsg:  "invalid bls48581 public key",
		},
		{
			name: "invalid PoP signature length",
			sig: &BLS48581SignatureWithProofOfPossession{
				Signature:    make([]byte, 74),
				PopSignature: make([]byte, 50),
			},
			wantErr: true,
			errMsg:  "invalid bls48581 public key",
		},
		{
			name: "invalid public key",
			sig: &BLS48581SignatureWithProofOfPossession{
				Signature:    make([]byte, 74),
				PopSignature: make([]byte, 74),
				PublicKey: &BLS48581G2PublicKey{
					KeyValue: make([]byte, 100),
				},
			},
			wantErr: true,
			errMsg:  "invalid bls48581 public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sig.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBLS48581AddressedSignature_Validate(t *testing.T) {
	tests := []struct {
		name    string
		sig     *BLS48581AddressedSignature
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid addressed signature",
			sig: &BLS48581AddressedSignature{
				Signature: make([]byte, 74),
				Address:   make([]byte, 32),
			},
			wantErr: false,
		},
		{
			name: "empty signature invalid",
			sig: &BLS48581AddressedSignature{
				Signature: []byte{},
				Address:   []byte{},
			},
			wantErr: true,
			errMsg:  "invalid address",
		},
		{
			name:    "nil signature",
			sig:     nil,
			wantErr: true,
			errMsg:  "nil bls48581 signature",
		},
		{
			name: "invalid signature length",
			sig: &BLS48581AddressedSignature{
				Signature: make([]byte, 50),
				Address:   make([]byte, 32),
			},
			wantErr: true,
			errMsg:  "invalid bls48581 signature",
		},
		{
			name: "invalid address length",
			sig: &BLS48581AddressedSignature{
				Signature: make([]byte, 74),
				Address:   make([]byte, 16),
			},
			wantErr: true,
			errMsg:  "invalid address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sig.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
