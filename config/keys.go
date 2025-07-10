package config

import (
	"fmt"
)

type KeyManagerType int

const (
	KeyManagerTypeInMemory KeyManagerType = iota
	KeyManagerTypeFile
	// KeyStoreTypePKCS11
	// KeyStoreTypeRPC
)

func (k KeyManagerType) MarshalText() ([]byte, error) {
	switch k {
	case KeyManagerTypeInMemory:
		return []byte("mem"), nil
	case KeyManagerTypeFile:
		return []byte("file"), nil
	// case KeyStoreTypePKCS11:
	//   return []byte("pkcs11"), nil
	// case KeyStoreTypeRPC:
	//   return []byte("rpc"), nil
	default:
		return nil, fmt.Errorf("unknown keystore type (%d)", int(k))
	}
}

func (k *KeyManagerType) UnmarshalText(b []byte) error {
	switch string(b) {
	case "mem":
		*k = KeyManagerTypeInMemory
	case "file":
		*k = KeyManagerTypeFile
	// case "pkcs11":
	//   *k = KeyStoreTypePKCS11
	// case "rpc":
	//   *k = KeyStoreTypeRPC
	default:
		return fmt.Errorf("unknown keystore type %q", b)
	}
	return nil
}

type KeyConfig struct {
	KeyStore     KeyManagerType      `yaml:"keyManagerType"`
	KeyStoreFile *KeyStoreFileConfig `yaml:"keyManagerFile"`
	// KeyStorePKCS11 *KeyStorePKCS11Config `yaml:"keyStorePKCS11"`
	// KeyStoreRPC *KeyStoreRPCConfig `yaml:"keyStoreRPC"`
}

type KeyStoreFileConfig struct {
	Path            string `yaml:"path"`
	CreateIfMissing bool   `yaml:"createIfMissing"`
	EncryptionKey   string `yaml:"encryptionKey"`
}
