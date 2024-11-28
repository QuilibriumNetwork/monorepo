package protobufs_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func newPrivateKey() crypto.PrivKey {
	privKey, _, err := crypto.GenerateEd448Key(rand.Reader)
	if err != nil {
		panic(err)
	}
	return privKey
}

func publicKeyBytesOf(privKey crypto.PrivKey) []byte {
	b, err := privKey.GetPublic().Raw()
	if err != nil {
		panic(err)
	}
	return b
}

var (
	primaryPrivateKey     crypto.PrivKey = newPrivateKey()
	primaryPublicKeyBytes []byte         = publicKeyBytesOf(primaryPrivateKey)

	secondaryPrivateKey     crypto.PrivKey = newPrivateKey()
	secondaryPublicKeyBytes []byte         = publicKeyBytesOf(secondaryPrivateKey)
)

func metaAppend[T any](bs ...[]T) []T {
	var result []T
	for _, b := range bs {
		result = append(result, b...)
	}
	return result
}

func TestClockFrameFragmentSignatureRoundtrip(t *testing.T) {
	t.Parallel()
	message := &protobufs.ClockFrameFragment{
		Filter:      bytes.Repeat([]byte{0x01}, 32),
		FrameNumber: 1,
		Timestamp:   2,
		FrameHash:   bytes.Repeat([]byte{0x03}, 28),
		Encoding: &protobufs.ClockFrameFragment_ReedSolomon{
			ReedSolomon: &protobufs.ClockFrameFragment_ReedSolomonEncoding{
				FrameSize:                3,
				FragmentShard:            4,
				FragmentDataShardCount:   5,
				FragmentParityShardCount: 6,
				FragmentData:             bytes.Repeat([]byte{0x02}, 6),
			},
		},
		PublicKeySignature: &protobufs.ClockFrameFragment_PublicKeySignatureEd448{
			PublicKeySignatureEd448: &protobufs.Ed448Signature{
				Signature: bytes.Repeat([]byte{0x02}, 114),
				PublicKey: &protobufs.Ed448PublicKey{
					KeyValue: bytes.Repeat([]byte{0x03}, 57),
				},
			},
		},
	}
	if !bytes.Equal(
		protobufs.SignatureMessageOf(message),
		metaAppend(
			[]byte("fragment"),
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			bytes.Repeat([]byte{0x01}, 32),
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
			bytes.Repeat([]byte{0x03}, 28),
			metaAppend(
				[]byte("reed-solomon-fragment"),
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
				[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
				[]byte{
					0x2e, 0xbd, 0x9a, 0x4e, 0x48, 0x8b, 0x47, 0x1c,
					0xd7, 0x0a, 0x25, 0xae, 0xcc, 0xb2, 0xdb, 0x50,
					0xaa, 0xbd, 0xa7, 0x3c, 0x92, 0xce, 0x8e, 0xe0,
					0xe2, 0x15, 0xcd, 0x89, 0x32, 0x0f, 0x6b, 0x9a,
				},
			),
		),
	) {
		t.Fatal("unexpected signature message")
	}
	if err := message.ValidateSignature(); err == nil {
		t.Fatal("expected error")
	}
	if err := message.SignED448(primaryPublicKeyBytes, primaryPrivateKey.Sign); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message.GetPublicKeySignatureEd448().PublicKey.KeyValue, primaryPublicKeyBytes) {
		t.Fatal("unexpected public key")
	}
	if err := message.ValidateSignature(); err != nil {
		t.Fatal(err)
	}
}

func TestTransferCoinRequestSignatureRoundtrip(t *testing.T) {
	t.Parallel()
	message := &protobufs.TransferCoinRequest{
		OfCoin: &protobufs.CoinRef{
			Address: bytes.Repeat([]byte{0x01}, 32),
		},
		ToAccount: &protobufs.AccountRef{
			Account: &protobufs.AccountRef_ImplicitAccount{
				ImplicitAccount: &protobufs.ImplicitAccount{
					Address: bytes.Repeat([]byte{0x02}, 32),
				},
			},
		},
		Signature: &protobufs.Ed448Signature{
			Signature: bytes.Repeat([]byte{0x03}, 114),
			PublicKey: &protobufs.Ed448PublicKey{
				KeyValue: bytes.Repeat([]byte{0x04}, 57),
			},
		},
	}
	if !bytes.Equal(
		protobufs.SignatureMessageOf(message),
		metaAppend(
			[]byte("transfer"),
			bytes.Repeat([]byte{0x01}, 32),
			bytes.Repeat([]byte{0x02}, 32),
		),
	) {
		t.Fatal("unexpected signature message")
	}
	if err := message.ValidateSignature(); err == nil {
		t.Fatal("expected error")
	}
	if err := message.SignED448(primaryPublicKeyBytes, primaryPrivateKey.Sign); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message.Signature.PublicKey.KeyValue, primaryPublicKeyBytes) {
		t.Fatal("unexpected public key")
	}
	if err := message.ValidateSignature(); err != nil {
		t.Fatal(err)
	}
}

func TestSplitCoinRequestSignatureRoundtrip(t *testing.T) {
	t.Parallel()
	message := &protobufs.SplitCoinRequest{
		OfCoin: &protobufs.CoinRef{
			Address: bytes.Repeat([]byte{0x01}, 32),
		},
		Amounts: [][]byte{
			bytes.Repeat([]byte{0x02}, 32),
			bytes.Repeat([]byte{0x03}, 32),
		},
		Signature: &protobufs.Ed448Signature{
			Signature: bytes.Repeat([]byte{0x04}, 114),
			PublicKey: &protobufs.Ed448PublicKey{
				KeyValue: bytes.Repeat([]byte{0x05}, 57),
			},
		},
	}
	if !bytes.Equal(
		protobufs.SignatureMessageOf(message),
		metaAppend(
			[]byte("split"),
			bytes.Repeat([]byte{0x01}, 32),
			bytes.Repeat([]byte{0x02}, 32),
			bytes.Repeat([]byte{0x03}, 32),
		),
	) {
		t.Fatal("unexpected signature message")
	}
	if err := message.ValidateSignature(); err == nil {
		t.Fatal("expected error")
	}
	if err := message.SignED448(primaryPublicKeyBytes, primaryPrivateKey.Sign); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message.Signature.PublicKey.KeyValue, primaryPublicKeyBytes) {
		t.Fatal("unexpected public key")
	}
	if err := message.ValidateSignature(); err != nil {
		t.Fatal(err)
	}
}

func TestMergeCoinRequestSignatureRoundtrip(t *testing.T) {
	t.Parallel()
	message := &protobufs.MergeCoinRequest{
		Coins: []*protobufs.CoinRef{
			{
				Address: bytes.Repeat([]byte{0x01}, 32),
			},
			{
				Address: bytes.Repeat([]byte{0x02}, 32),
			},
		},
		Signature: &protobufs.Ed448Signature{
			Signature: bytes.Repeat([]byte{0x03}, 114),
			PublicKey: &protobufs.Ed448PublicKey{
				KeyValue: bytes.Repeat([]byte{0x04}, 57),
			},
		},
	}
	if !bytes.Equal(
		protobufs.SignatureMessageOf(message),
		metaAppend(
			[]byte("merge"),
			bytes.Repeat([]byte{0x01}, 32),
			bytes.Repeat([]byte{0x02}, 32),
		),
	) {
		t.Fatal("unexpected signature message")
	}
	if err := message.ValidateSignature(); err == nil {
		t.Fatal("expected error")
	}
	if err := message.SignED448(primaryPublicKeyBytes, primaryPrivateKey.Sign); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message.Signature.PublicKey.KeyValue, primaryPublicKeyBytes) {
		t.Fatal("unexpected public key")
	}
	if err := message.ValidateSignature(); err != nil {
		t.Fatal(err)
	}
}

func TestMintCoinRequestSignatureRoundtrip(t *testing.T) {
	t.Parallel()
	message := &protobufs.MintCoinRequest{
		Proofs: [][]byte{
			bytes.Repeat([]byte{0x01}, 32),
			bytes.Repeat([]byte{0x02}, 32),
		},
		Signature: &protobufs.Ed448Signature{
			Signature: bytes.Repeat([]byte{0x03}, 114),
			PublicKey: &protobufs.Ed448PublicKey{
				KeyValue: bytes.Repeat([]byte{0x04}, 57),
			},
		},
	}
	if !bytes.Equal(
		protobufs.SignatureMessageOf(message),
		metaAppend(
			[]byte("mint"),
			bytes.Repeat([]byte{0x01}, 32),
			bytes.Repeat([]byte{0x02}, 32),
		),
	) {
		t.Fatal("unexpected signature message")
	}
	if err := message.ValidateSignature(); err == nil {
		t.Fatal("expected error")
	}
	if err := message.SignED448(primaryPublicKeyBytes, primaryPrivateKey.Sign); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message.Signature.PublicKey.KeyValue, primaryPublicKeyBytes) {
		t.Fatal("unexpected public key")
	}
	if err := message.ValidateSignature(); err != nil {
		t.Fatal(err)
	}
}

func TestAnnounceProverRequestSignatureRoundtrip(t *testing.T) {
	t.Parallel()
	message := &protobufs.AnnounceProverRequest{
		PublicKeySignaturesEd448: []*protobufs.Ed448Signature{
			{
				Signature: bytes.Repeat([]byte{0x01}, 114),
				PublicKey: &protobufs.Ed448PublicKey{
					KeyValue: bytes.Repeat([]byte{0x02}, 57),
				},
			},
			{
				Signature: bytes.Repeat([]byte{0x03}, 114),
				PublicKey: &protobufs.Ed448PublicKey{
					KeyValue: bytes.Repeat([]byte{0x04}, 57),
				},
			},
		},
	}
	if err := message.ValidateSignature(); err == nil {
		t.Fatal("expected error")
	}
	if err := message.SignED448([]protobufs.ED448SignHelper{
		{
			PublicKey: primaryPublicKeyBytes,
			Sign:      primaryPrivateKey.Sign,
		},
		{
			PublicKey: secondaryPublicKeyBytes,
			Sign:      secondaryPrivateKey.Sign,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message.PublicKeySignaturesEd448[0].PublicKey.KeyValue, primaryPublicKeyBytes) {
		t.Fatal("unexpected public key")
	}
	if !bytes.Equal(message.PublicKeySignaturesEd448[1].PublicKey.KeyValue, secondaryPublicKeyBytes) {
		t.Fatal("unexpected public key")
	}
	if err := message.ValidateSignature(); err != nil {
		t.Fatal(err)
	}
	message = &protobufs.AnnounceProverRequest{
		PublicKeySignaturesEd448: []*protobufs.Ed448Signature{
			{
				Signature: bytes.Repeat([]byte{0x01}, 114),
				PublicKey: &protobufs.Ed448PublicKey{
					KeyValue: bytes.Repeat([]byte{0x02}, 57),
				},
			},
		},
	}
	if err := message.ValidateSignature(); err == nil {
		t.Fatal("expected error")
	}
	if err := message.SignED448([]protobufs.ED448SignHelper{
		{
			PublicKey: primaryPublicKeyBytes,
			Sign:      primaryPrivateKey.Sign,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message.PublicKeySignaturesEd448[0].PublicKey.KeyValue, primaryPublicKeyBytes) {
		t.Fatal("unexpected public key")
	}
	if err := message.ValidateSignature(); err != nil {
		t.Fatal(err)
	}
}

func TestAnnounceProverJoinSignatureRoundtrip(t *testing.T) {
	t.Parallel()
	message := &protobufs.AnnounceProverJoin{
		Filter:      bytes.Repeat([]byte{0x01}, 32),
		FrameNumber: 1,
		PublicKeySignatureEd448: &protobufs.Ed448Signature{
			Signature: bytes.Repeat([]byte{0x02}, 114),
			PublicKey: &protobufs.Ed448PublicKey{
				KeyValue: bytes.Repeat([]byte{0x03}, 57),
			},
		},
	}
	if !bytes.Equal(
		protobufs.SignatureMessageOf(message),
		metaAppend(
			[]byte("join"),
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			bytes.Repeat([]byte{0x01}, 32),
		),
	) {
		t.Fatal("unexpected signature message")
	}
	if err := message.ValidateSignature(); err == nil {
		t.Fatal("expected error")
	}
	if err := message.SignED448(primaryPublicKeyBytes, primaryPrivateKey.Sign); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message.PublicKeySignatureEd448.PublicKey.KeyValue, primaryPublicKeyBytes) {
		t.Fatal("unexpected public key")
	}
	if err := message.ValidateSignature(); err != nil {
		t.Fatal(err)
	}
}

func TestAnnounceProverLeaveSignatureRoundtrip(t *testing.T) {
	t.Parallel()
	message := &protobufs.AnnounceProverLeave{
		Filter:      bytes.Repeat([]byte{0x01}, 32),
		FrameNumber: 1,
		PublicKeySignatureEd448: &protobufs.Ed448Signature{
			Signature: bytes.Repeat([]byte{0x02}, 114),
			PublicKey: &protobufs.Ed448PublicKey{
				KeyValue: bytes.Repeat([]byte{0x03}, 57),
			},
		},
	}
	if !bytes.Equal(
		protobufs.SignatureMessageOf(message),
		metaAppend(
			[]byte("leave"),
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			bytes.Repeat([]byte{0x01}, 32),
		),
	) {
		t.Fatal("unexpected signature message")
	}
	if err := message.ValidateSignature(); err == nil {
		t.Fatal("expected error")
	}
	if err := message.SignED448(primaryPublicKeyBytes, primaryPrivateKey.Sign); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message.PublicKeySignatureEd448.PublicKey.KeyValue, primaryPublicKeyBytes) {
		t.Fatal("unexpected public key")
	}
	if err := message.ValidateSignature(); err != nil {
		t.Fatal(err)
	}
}

func TestAnnounceProverPauseSignatureRoundtrip(t *testing.T) {
	t.Parallel()
	message := &protobufs.AnnounceProverPause{
		Filter:      bytes.Repeat([]byte{0x01}, 32),
		FrameNumber: 1,
		PublicKeySignatureEd448: &protobufs.Ed448Signature{
			Signature: bytes.Repeat([]byte{0x02}, 114),
			PublicKey: &protobufs.Ed448PublicKey{
				KeyValue: bytes.Repeat([]byte{0x03}, 57),
			},
		},
	}
	if !bytes.Equal(
		protobufs.SignatureMessageOf(message),
		metaAppend(
			[]byte("pause"),
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			bytes.Repeat([]byte{0x01}, 32),
		),
	) {
		t.Fatal("unexpected signature message")
	}
	if err := message.ValidateSignature(); err == nil {
		t.Fatal("expected error")
	}
	if err := message.SignED448(primaryPublicKeyBytes, primaryPrivateKey.Sign); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message.PublicKeySignatureEd448.PublicKey.KeyValue, primaryPublicKeyBytes) {
		t.Fatal("unexpected public key")
	}
	if err := message.ValidateSignature(); err != nil {
		t.Fatal(err)
	}
}

func TestAnnounceProverResumeSignatureRoundtrip(t *testing.T) {
	t.Parallel()
	message := &protobufs.AnnounceProverResume{
		Filter:      bytes.Repeat([]byte{0x01}, 32),
		FrameNumber: 1,
		PublicKeySignatureEd448: &protobufs.Ed448Signature{
			Signature: bytes.Repeat([]byte{0x02}, 114),
			PublicKey: &protobufs.Ed448PublicKey{
				KeyValue: bytes.Repeat([]byte{0x03}, 57),
			},
		},
	}
	if !bytes.Equal(
		protobufs.SignatureMessageOf(message),
		metaAppend(
			[]byte("resume"),
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			bytes.Repeat([]byte{0x01}, 32),
		),
	) {
		t.Fatal("unexpected signature message")
	}
	if err := message.ValidateSignature(); err == nil {
		t.Fatal("expected error")
	}
	if err := message.SignED448(primaryPublicKeyBytes, primaryPrivateKey.Sign); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message.PublicKeySignatureEd448.PublicKey.KeyValue, primaryPublicKeyBytes) {
		t.Fatal("unexpected public key")
	}
	if err := message.ValidateSignature(); err != nil {
		t.Fatal(err)
	}
}

func TestClockFrameFragmentReedSolomonEncodingValidate(t *testing.T) {
	t.Parallel()
	if err := (*protobufs.ClockFrameFragment_ReedSolomonEncoding)(nil).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message := &protobufs.ClockFrameFragment_ReedSolomonEncoding{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.FrameSize = 1
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.FragmentShard = 2
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.FragmentDataShardCount = 3
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.FragmentParityShardCount = 4
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.FragmentData = bytes.Repeat([]byte{0x01}, 6)
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestClockFrameFragmentValidate(t *testing.T) {
	t.Parallel()
	if err := (*protobufs.ClockFrameFragment)(nil).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message := &protobufs.ClockFrameFragment{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.Filter = bytes.Repeat([]byte{0x01}, 32)
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.FrameNumber = 1
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.Timestamp = 2
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.FrameHash = bytes.Repeat([]byte{0x03}, 28)
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.Encoding = &protobufs.ClockFrameFragment_ReedSolomon{
		ReedSolomon: &protobufs.ClockFrameFragment_ReedSolomonEncoding{
			FrameSize:                2,
			FragmentShard:            3,
			FragmentDataShardCount:   4,
			FragmentParityShardCount: 5,
			FragmentData:             bytes.Repeat([]byte{0x02}, 6),
		},
	}
	if err := message.SignED448(primaryPublicKeyBytes, primaryPrivateKey.Sign); err != nil {
		t.Fatal(err)
	}
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestEd448PublicKeyValidate(t *testing.T) {
	t.Parallel()
	if err := (*protobufs.Ed448PublicKey)(nil).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message := &protobufs.Ed448PublicKey{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.KeyValue = bytes.Repeat([]byte{0x01}, 57)
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestEd448SignatureValidate(t *testing.T) {
	t.Parallel()
	if err := (*protobufs.Ed448Signature)(nil).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message := &protobufs.Ed448Signature{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.Signature = bytes.Repeat([]byte{0x01}, 114)
	message.PublicKey = &protobufs.Ed448PublicKey{
		KeyValue: bytes.Repeat([]byte{0x02}, 57),
	}
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestImplicitAccountValidate(t *testing.T) {
	t.Parallel()
	if err := (*protobufs.ImplicitAccount)(nil).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message := &protobufs.ImplicitAccount{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.Address = bytes.Repeat([]byte{0x01}, 32)
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestOriginatedAccountRefValidate(t *testing.T) {
	t.Parallel()
	if err := (*protobufs.OriginatedAccountRef)(nil).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message := &protobufs.OriginatedAccountRef{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.Address = bytes.Repeat([]byte{0x01}, 32)
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAccountRefValidate(t *testing.T) {
	t.Parallel()
	message := &protobufs.AccountRef{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.Account = &protobufs.AccountRef_ImplicitAccount{
		ImplicitAccount: &protobufs.ImplicitAccount{
			Address: bytes.Repeat([]byte{0x01}, 32),
		},
	}
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
	message.Account = &protobufs.AccountRef_OriginatedAccount{
		OriginatedAccount: &protobufs.OriginatedAccountRef{
			Address: bytes.Repeat([]byte{0x02}, 32),
		},
	}
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCoinRefValidate(t *testing.T) {
	t.Parallel()
	if err := (*protobufs.CoinRef)(nil).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message := &protobufs.CoinRef{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.Address = bytes.Repeat([]byte{0x01}, 32)
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAccountAllowanceRefValidate(t *testing.T) {
	t.Parallel()
	if err := (*protobufs.AccountAllowanceRef)(nil).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message := &protobufs.AccountAllowanceRef{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.Address = bytes.Repeat([]byte{0x01}, 32)
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCoinAllowanceRefValidate(t *testing.T) {
	t.Parallel()
	if err := (*protobufs.CoinAllowanceRef)(nil).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message := &protobufs.CoinAllowanceRef{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.Address = bytes.Repeat([]byte{0x01}, 32)
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestTransferCoinRequestValidate(t *testing.T) {
	t.Parallel()
	if err := (*protobufs.TransferCoinRequest)(nil).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message := &protobufs.TransferCoinRequest{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Transfer{
			Transfer: message,
		},
	}).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.OfCoin = &protobufs.CoinRef{
		Address: bytes.Repeat([]byte{0x01}, 32),
	}
	message.ToAccount = &protobufs.AccountRef{
		Account: &protobufs.AccountRef_ImplicitAccount{
			ImplicitAccount: &protobufs.ImplicitAccount{
				Address: bytes.Repeat([]byte{0x02}, 32),
			},
		},
	}
	if err := message.SignED448(primaryPublicKeyBytes, primaryPrivateKey.Sign); err != nil {
		t.Fatal(err)
	}
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Transfer{
			Transfer: message,
		},
	}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSplitCoinRequestValidate(t *testing.T) {
	t.Parallel()
	if err := (*protobufs.SplitCoinRequest)(nil).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message := &protobufs.SplitCoinRequest{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Split{
			Split: message,
		},
	}).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.OfCoin = &protobufs.CoinRef{
		Address: bytes.Repeat([]byte{0x01}, 32),
	}
	message.Amounts = [][]byte{
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
	}
	if err := message.SignED448(primaryPublicKeyBytes, primaryPrivateKey.Sign); err != nil {
		t.Fatal(err)
	}
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Split{
			Split: message,
		},
	}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMergeCoinRequestValidate(t *testing.T) {
	t.Parallel()
	if err := (*protobufs.MergeCoinRequest)(nil).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message := &protobufs.MergeCoinRequest{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Merge{
			Merge: message,
		},
	}).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.Coins = []*protobufs.CoinRef{
		{
			Address: bytes.Repeat([]byte{0x01}, 32),
		},
		{
			Address: bytes.Repeat([]byte{0x02}, 32),
		},
	}
	if err := message.SignED448(primaryPublicKeyBytes, primaryPrivateKey.Sign); err != nil {
		t.Fatal(err)
	}
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Merge{
			Merge: message,
		},
	}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMintCoinRequestValidate(t *testing.T) {
	t.Parallel()
	if err := (*protobufs.MintCoinRequest)(nil).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message := &protobufs.MintCoinRequest{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Mint{
			Mint: message,
		},
	}).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.Proofs = [][]byte{
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
	}
	if err := message.SignED448(primaryPublicKeyBytes, primaryPrivateKey.Sign); err != nil {
		t.Fatal(err)
	}
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Mint{
			Mint: message,
		},
	}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAnnounceProverRequestValidate(t *testing.T) {
	t.Parallel()
	if err := (*protobufs.AnnounceProverRequest)(nil).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message := &protobufs.AnnounceProverRequest{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Announce{
			Announce: message,
		},
	}).Validate(); err == nil {
		t.Fatal("expected error")
	}
	if err := message.SignED448([]protobufs.ED448SignHelper{
		{
			PublicKey: primaryPublicKeyBytes,
			Sign:      primaryPrivateKey.Sign,
		},
		{
			PublicKey: secondaryPublicKeyBytes,
			Sign:      secondaryPrivateKey.Sign,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Announce{
			Announce: message,
		},
	}).Validate(); err != nil {
		t.Fatal("expected error")
	}
}

func TestAnnounceProverJoinValidate(t *testing.T) {
	t.Parallel()
	if err := (*protobufs.AnnounceProverJoin)(nil).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message := &protobufs.AnnounceProverJoin{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Join{
			Join: message,
		},
	}).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.Filter = bytes.Repeat([]byte{0x01}, 32)
	message.FrameNumber = 1
	if err := message.SignED448(primaryPublicKeyBytes, primaryPrivateKey.Sign); err != nil {
		t.Fatal(err)
	}
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Join{
			Join: message,
		},
	}).Validate(); err != nil {
		t.Fatal(err)
	}
	announce := &protobufs.AnnounceProverRequest{}
	message.Announce = announce
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Join{
			Join: message,
		},
	}).Validate(); err == nil {
		t.Fatal("expected error")
	}
	if err := announce.SignED448([]protobufs.ED448SignHelper{
		{
			PublicKey: primaryPublicKeyBytes,
			Sign:      primaryPrivateKey.Sign,
		},
		{
			PublicKey: secondaryPublicKeyBytes,
			Sign:      secondaryPrivateKey.Sign,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Join{
			Join: message,
		},
	}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAnnounceProverLeaveValidate(t *testing.T) {
	t.Parallel()
	if err := (*protobufs.AnnounceProverLeave)(nil).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message := &protobufs.AnnounceProverLeave{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Leave{
			Leave: message,
		},
	}).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.Filter = bytes.Repeat([]byte{0x01}, 32)
	message.FrameNumber = 1
	if err := message.SignED448(primaryPublicKeyBytes, primaryPrivateKey.Sign); err != nil {
		t.Fatal(err)
	}
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Leave{
			Leave: message,
		},
	}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAnnounceProverPauseValidate(t *testing.T) {
	t.Parallel()
	if err := (*protobufs.AnnounceProverPause)(nil).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message := &protobufs.AnnounceProverPause{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Pause{
			Pause: message,
		},
	}).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.Filter = bytes.Repeat([]byte{0x01}, 32)
	message.FrameNumber = 1
	if err := message.SignED448(primaryPublicKeyBytes, primaryPrivateKey.Sign); err != nil {
		t.Fatal(err)
	}
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Pause{
			Pause: message,
		},
	}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAnnounceProverResumeValidate(t *testing.T) {
	t.Parallel()
	if err := (*protobufs.AnnounceProverResume)(nil).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message := &protobufs.AnnounceProverResume{}
	if err := message.Validate(); err == nil {
		t.Fatal("expected error")
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Resume{
			Resume: message,
		},
	}).Validate(); err == nil {
		t.Fatal("expected error")
	}
	message.Filter = bytes.Repeat([]byte{0x01}, 32)
	message.FrameNumber = 1
	if err := message.SignED448(primaryPublicKeyBytes, primaryPrivateKey.Sign); err != nil {
		t.Fatal(err)
	}
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (&protobufs.TokenRequest{
		Request: &protobufs.TokenRequest_Resume{
			Resume: message,
		},
	}).Validate(); err != nil {
		t.Fatal(err)
	}
}
