package hypergraph

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	aliases "source.quilibrium.com/quilibrium/monorepo/alias"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/types/crypto"
	tkeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
	"source.quilibrium.com/quilibrium/monorepo/verenc"
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

// resolveAddress resolves an alias or hex string to raw bytes.
// expectedLen is the required byte length (e.g. 32 for domain, 64 for full address).
// Returns the resolved bytes or an error.
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

func initCrypto() (
	crypto.InclusionProver,
	crypto.BulletproofProver,
	crypto.VerifiableEncryptor,
	crypto.Signer,
	error,
) {
	initKeyManager()
	if keyManager == nil {
		return nil, nil, nil, nil, errors.New("key manager not available")
	}

	logger, _ := zap.NewProduction()
	inclusionProver := bls48581.NewKZGInclusionProver(logger)
	bulletproofProver := bulletproofs.NewBulletproofProver()
	verEncryptor := verenc.NewMPCitHVerifiableEncryptor(1)

	signer, err := keyManager.GetSigningKey("q-node-auth")
	if err != nil {
		return nil, nil, nil, nil, errors.Wrap(err, "init crypto: get signing key")
	}

	return inclusionProver, bulletproofProver, verEncryptor, signer, nil
}

func sendHypergraphMessage(
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
		return errors.Wrap(err, "send hypergraph message")
	}

	signer, err := keyManager.GetSigningKey("q-peer-key")
	if err != nil {
		return errors.Wrap(err, "send hypergraph message: get signing key")
	}

	sig, err := signer.SignWithDomain(
		payload,
		slices.Concat([]byte("NODE_AUTHENTICATION"), domain),
	)
	if err != nil {
		return errors.Wrap(err, "send hypergraph message: sign")
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
		return errors.Wrap(err, "send hypergraph message: rpc")
	}

	return nil
}
