package utils

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
)

func GetPeerIDFromConfig(cfg *config.Config) peer.ID {
	peerPrivKey, err := hex.DecodeString(cfg.P2P.PeerPrivKey)
	if err != nil {
		panic(errors.Wrap(err, "error unmarshaling peerkey"))
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		panic(errors.Wrap(err, "error unmarshaling peerkey"))
	}

	pub := privKey.GetPublic()
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		panic(errors.Wrap(err, "error getting peer id"))
	}

	return id
}

func GetPrivKeyFromConfig(cfg *config.Config) (crypto.PrivKey, error) {
	peerPrivKey, err := hex.DecodeString(cfg.P2P.PeerPrivKey)
	if err != nil {
		panic(errors.Wrap(err, "error unmarshaling peerkey"))
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	return privKey, err
}

func IsExistingNodeVersion(version string) bool {
	return FileExists(filepath.Join(NodeDataPath, version))
}

func CheckForSystemd() bool {
	// Check if systemctl command exists
	_, err := exec.LookPath("systemctl")
	return err == nil
}

func LoadNodeConfig(configDirectory string) (*config.Config, error) {
	NodeConfig, err := config.LoadConfig(configDirectory, "", false)
	if err != nil {
		fmt.Printf("invalid config directory: %s\n", configDirectory)
		os.Exit(1)
	}
	return NodeConfig, nil
}
