package prover

import (
	"context"
	"encoding/hex"
	"slices"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/bulletproofs"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
	"source.quilibrium.com/quilibrium/monorepo/config"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/protobufs"
	tkeys "source.quilibrium.com/quilibrium/monorepo/types/keys"
)

var NodeConfig *config.Config
var KeyManager tkeys.KeyManager

func initKeyManager() {
	if KeyManager != nil {
		return
	}
	cfg := getConfig()
	if cfg == nil {
		return
	}
	logger, _ := zap.NewProduction()
	KeyManager = keys.NewFileKeyManager(
		cfg,
		&bls48581.Bls48581KeyConstructor{},
		&bulletproofs.Decaf448KeyConstructor{},
		logger,
	)

}

func getConfig() *config.Config {
	if NodeConfig != nil {
		return NodeConfig
	}
	cfg, err := utils.LoadDefaultNodeConfig()
	if err != nil {
		return nil
	}
	NodeConfig = cfg
	return cfg
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

// workerByFilter calls GetWorkerInfo and returns a map from hex-encoded filter
// to core_id. Returns an empty map on error.
func workerByFilter(client protobufs.NodeServiceClient) map[string]uint32 {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()
	resp, err := client.GetWorkerInfo(
		ctx,
		&protobufs.GetWorkerInfoRequest{},
	)
	m := make(map[string]uint32)
	if err != nil || resp == nil {
		return m
	}
	for _, w := range resp.GetWorkerInfo() {
		m[hex.EncodeToString(w.GetFilter())] = w.GetCoreId()
	}
	return m
}

func sendProverMessage(
	client protobufs.NodeServiceClient,
	domain []byte,
	request *protobufs.MessageRequest,
) error {
	initKeyManager()
	if KeyManager == nil {
		return errors.New("key manager not available")
	}

	bundle := &protobufs.MessageBundle{
		Requests:  []*protobufs.MessageRequest{request},
		Timestamp: time.Now().UnixMilli(),
	}

	payload, err := bundle.ToCanonicalBytes()
	if err != nil {
		return errors.Wrap(err, "send prover message")
	}

	signer, err := KeyManager.GetSigningKey("q-peer-key")
	if err != nil {
		return errors.Wrap(err, "send prover message: get signing key")
	}

	sig, err := signer.SignWithDomain(
		payload,
		slices.Concat([]byte("NODE_AUTHENTICATION"), domain),
	)
	if err != nil {
		return errors.Wrap(err, "send prover message: sign")
	}

	// Bounded context — Send can be expensive (signature verification
	// + BlossomSub publish chain on the node side) but should not be
	// open-ended; a hung node would otherwise freeze the TUI's
	// broadcast step indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()
	_, err = client.Send(
		ctx,
		&protobufs.SendRequest{
			Domain:         domain,
			Request:        bundle,
			Authentication: sig,
		},
	)
	if err != nil {
		return errors.Wrap(err, "send prover message: rpc")
	}

	return nil
}
