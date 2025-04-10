package node

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"source.quilibrium.com/quilibrium/monorepo/client/utils"
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
	return utils.FileExists(filepath.Join(utils.NodeDataPath, version))
}

func CheckForSystemd() bool {
	// Check if systemctl command exists
	_, err := exec.LookPath("systemctl")
	return err == nil
}

func checkForQuilibriumUser() (*user.User, error) {
	user, err := user.Lookup(nodeUser)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func InstallQuilibriumUser() (*user.User, error) {
	var user *user.User
	var err error
	user, err = checkForQuilibriumUser()
	if err != nil {
		if err := createNodeUser(nodeUser); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating user: %v\n", err)
			os.Exit(1)
		}
		user, err = checkForQuilibriumUser()
	}

	return user, err
}
