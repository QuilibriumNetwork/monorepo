package token

import (
	"context"
	"slices"
	"time"

	"github.com/pkg/errors"

	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/keys"
)

// SendTransaction wraps a MessageRequest in a MessageBundle, signs it, and
// sends it to the network via the Send RPC.
func SendTransaction(
	client protobufs.NodeServiceClient,
	domain []byte,
	request *protobufs.MessageRequest,
	keyManager keys.KeyManager,
) error {
	bundle := &protobufs.MessageBundle{
		Requests:  []*protobufs.MessageRequest{request},
		Timestamp: time.Now().UnixMilli(),
	}

	payload, err := bundle.ToCanonicalBytes()
	if err != nil {
		return errors.Wrap(err, "send transaction")
	}

	signer, err := keyManager.GetSigningKey("q-peer-key")
	if err != nil {
		return errors.Wrap(err, "send transaction: get signing key")
	}

	sig, err := signer.SignWithDomain(
		payload,
		slices.Concat([]byte("NODE_AUTHENTICATION"), domain),
	)
	if err != nil {
		return errors.Wrap(err, "send transaction: sign")
	}

	_, err = client.Send(
		context.Background(),
		&protobufs.SendRequest{
			Domain:         domain,
			Request:        bundle,
			Authentication: sig,
		},
	)
	if err != nil {
		return errors.Wrap(err, "send transaction: rpc")
	}

	return nil
}
