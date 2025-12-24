package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/libp2p/go-libp2p/core/crypto"
	"source.quilibrium.com/quilibrium/monorepo/config"
)

func main() {
	configDir := flag.String("config", ".config", "directory to save configuration")
	proverKey := flag.String("prover-key", "", "hex-encoded proving key (optional, will generate one if empty)")
	flag.Parse()

	// Robustness: if run from utils/config-gen, warn the user.
	cwd, _ := os.Getwd()
	if filepath.Base(cwd) == "config-gen" {
		fmt.Println("WARNING: Running from utils/config-gen. It is RECOMMENDED to run this from the project root.")
		fmt.Println("Example: go run utils/config-gen/main.go --config .config")
	}

	// Ensure the directory exists
	if err := os.MkdirAll(*configDir, 0700); err != nil {
		log.Fatalf("failed to create config directory: %v", err)
	}

	pk := *proverKey
	if pk == "" {
		fmt.Println("No proving key provided, generating a random Ed448 key...")
		privkey, _, err := crypto.GenerateEd448Key(rand.Reader)
		if err != nil {
			log.Fatalf("failed to generate proving key: %v", err)
		}

		rawKey, err := privkey.Raw()
		if err != nil {
			log.Fatalf("failed to get raw proving key: %v", err)
		}
		pk = hex.EncodeToString(rawKey)
		fmt.Printf("Generated Proving Key: %s\n", pk)
		fmt.Println("IMPORTANT: Save this key in a secure location!")
	}

	// config.LoadConfig will generate defaults if config.yml doesn't exist.
	// We pass skipGenesisCheck=true because we don't want to download the
	// genesis file just for generating a local config and keys.
	_, err := config.LoadConfig(*configDir, pk, true)
	if err != nil {
		log.Fatalf("failed to generate config: %v", err)
	}

	// Path Stabilization: Load the generated config and clean up any relative paths
	// that might have been created if run from a subdirectory.
	confPath := filepath.Join(*configDir, "config.yml")
	cfg, err := config.NewConfig(confPath)
	if err != nil {
		log.Fatalf("failed to load generated config for stabilization: %v", err)
	}

	stabilized := false
	cleanPath := func(p string) string {
		if strings.HasPrefix(p, "../../") {
			stabilized = true
			return strings.TrimPrefix(p, "../../")
		}
		return p
	}

	if cfg.DB != nil {
		cfg.DB.Path = cleanPath(cfg.DB.Path)
		cfg.DB.WorkerPathPrefix = cleanPath(cfg.DB.WorkerPathPrefix)
	}
	if cfg.Key != nil && cfg.Key.KeyStoreFile != nil {
		cfg.Key.KeyStoreFile.Path = cleanPath(cfg.Key.KeyStoreFile.Path)
	}

	// Protocol Stabilization: Ensure listenMultiaddr is UDP/QUIC-v1 for Docker compatibility.
	// We want to avoid TCP 8336 if it was accidentally defaulted.
	if cfg.P2P != nil {
		if cfg.P2P.ListenMultiaddr == "/ip4/0.0.0.0/tcp/8336" || cfg.P2P.ListenMultiaddr == "" {
			fmt.Println("Stabilizing P2P protocol to UDP/QUIC-v1...")
			cfg.P2P.ListenMultiaddr = "/ip4/0.0.0.0/udp/8336/quic-v1"
			stabilized = true
		}
	}

	if stabilized {
		fmt.Println("Saving stabilized configuration to config.yml...")
		if err := config.SaveConfig(*configDir, cfg); err != nil {
			log.Fatalf("failed to save stabilized config: %v", err)
		}
	}

	fmt.Println("Configuration and keys generated successfully.")
}
