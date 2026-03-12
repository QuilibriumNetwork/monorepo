package deploy

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/pkg/errors"
	"google.golang.org/grpc"

	aliases "source.quilibrium.com/quilibrium/monorepo/alias"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	tkeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
)

var nodeConfig *config.Config
var keyManager tkeys.KeyManager
var aliasStore *aliases.Store

func getConfig() *config.Config {
	if nodeConfig != nil {
		return nodeConfig
	}
	cfg, err := utils.LoadDefaultNodeConfig()
	if err != nil {
		return nil
	}
	nodeConfig = cfg
	return cfg
}

func initAliasStore() {
	if aliasStore != nil {
		return
	}
	cfg := getConfig()
	if cfg == nil {
		return
	}
	aliasStore, _ = utils.LoadAliasStore(cfg)
}

func resolveAddress(input string, expectedLen int) ([]byte, error) {
	initAliasStore()
	if aliasStore != nil {
		if addr, _, ok := aliasStore.Resolve(input); ok {
			if len(addr) != expectedLen {
				return nil, fmt.Errorf(
					"alias %q resolved to %d bytes, expected %d",
					input, len(addr), expectedLen,
				)
			}
			fmt.Printf("Resolved alias %q to %s\n", input, hex.EncodeToString(addr))
			return addr, nil
		}
	}

	h := strings.TrimPrefix(input, "0x")
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("must be an alias or hex address: %w", err)
	}
	if len(b) != expectedLen {
		return nil, fmt.Errorf(
			"expected %d bytes (%d hex chars), got %d bytes",
			expectedLen, expectedLen*2, len(b),
		)
	}
	return b, nil
}

func initKeyManager() {
	if keyManager != nil {
		return
	}
	cfg := getConfig()
	if cfg == nil {
		return
	}
	keyManager = keys.NewFileKeyManager(cfg, nil, nil, nil)
}

func getNodeClient() (protobufs.NodeServiceClient, *grpc.ClientConn, error) {
	cfg := getConfig()
	if cfg == nil {
		return nil, nil, errors.New("no config available")
	}

	conn, err := utils.GetGRPCClient(false, "", cfg)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get node client")
	}

	return protobufs.NewNodeServiceClient(conn), conn, nil
}

func sendDeployMessage(
	client protobufs.NodeServiceClient,
	domain []byte,
	request *protobufs.MessageRequest,
) error {
	initKeyManager()
	if keyManager == nil {
		return errors.New("key manager not available")
	}

	bundle := &protobufs.MessageBundle{
		Requests:  []*protobufs.MessageRequest{request},
		Timestamp: time.Now().UnixMilli(),
	}

	payload, err := bundle.ToCanonicalBytes()
	if err != nil {
		return errors.Wrap(err, "send deploy message")
	}

	signer, err := keyManager.GetSigningKey("q-peer-key")
	if err != nil {
		return errors.Wrap(err, "send deploy message: get signing key")
	}

	sig, err := signer.SignWithDomain(
		payload,
		slices.Concat([]byte("NODE_AUTHENTICATION"), domain),
	)
	if err != nil {
		return errors.Wrap(err, "send deploy message: sign")
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
		return errors.Wrap(err, "send deploy message: rpc")
	}

	return nil
}

// getDeployKeys extracts the three public keys needed for deploy configurations:
//   - readPubKey (57 bytes Ed448): peer key public key
//   - writePubKey (57 bytes Ed448): same as readPubKey
//   - ownerPubKey (585 bytes BLS48-581): proving key public key
func getDeployKeys() (readPubKey, writePubKey, ownerPubKey []byte, err error) {
	cfg := getConfig()
	if cfg == nil {
		return nil, nil, nil, errors.New("no config available")
	}

	// Extract Ed448 peer public key (57 bytes)
	rawPeerKey, err := hex.DecodeString(cfg.P2P.PeerPrivKey)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "decode peer private key")
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(rawPeerKey)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "unmarshal peer private key")
	}

	pubKey := privKey.GetPublic()
	readPubKey, err = pubKey.Raw()
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "get peer public key bytes")
	}
	writePubKey = readPubKey

	// Extract BLS48-581 owner public key (585 bytes)
	initKeyManager()
	if keyManager == nil {
		return nil, nil, nil, errors.New("key manager not available")
	}

	signer, err := keyManager.GetSigningKey(cfg.Engine.ProvingKeyId)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "get proving key")
	}

	blsPub := signer.Public()
	pubBytes, ok := blsPub.([]byte)
	if !ok {
		return nil, nil, nil, errors.New("unexpected owner public key type")
	}
	ownerPubKey = pubBytes

	return readPubKey, writePubKey, ownerPubKey, nil
}
