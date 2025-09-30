module source.quilibrium.com/quilibrium/monorepo/config

go 1.23.2

toolchain go1.23.4

replace github.com/multiformats/go-multiaddr => ../go-multiaddr

replace github.com/multiformats/go-multiaddr-dns => ../go-multiaddr-dns

replace github.com/libp2p/go-libp2p => ../go-libp2p

replace github.com/libp2p/go-libp2p-kad-dht => ../go-libp2p-kad-dht

replace source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub => ../go-libp2p-blossomsub

replace source.quilibrium.com/quilibrium/monorepo/utils => ../utils

require (
	gopkg.in/yaml.v2 v2.4.0
	source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub v0.0.0-00010101000000-000000000000
	source.quilibrium.com/quilibrium/monorepo/utils v0.0.0-00010101000000-000000000000
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/ipfs/go-log/v2 v2.5.1 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/libp2p/go-msgio v0.3.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/multiformats/go-multiaddr-fmt v0.1.0 // indirect
	github.com/multiformats/go-multistream v0.6.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/cloudflare/circl v1.6.1
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/ipfs/go-cid v0.5.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/libp2p/go-buffer-pool v0.1.0 // indirect
	github.com/libp2p/go-libp2p v0.41.1
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-base32 v0.1.0 // indirect
	github.com/multiformats/go-base36 v0.2.0 // indirect
	github.com/multiformats/go-multiaddr v0.16.0 // indirect
	github.com/multiformats/go-multibase v0.2.0 // indirect
	github.com/multiformats/go-multicodec v0.9.1 // indirect
	github.com/multiformats/go-multihash v0.2.3 // indirect
	github.com/multiformats/go-varint v0.0.7 // indirect
	github.com/pkg/errors v0.9.1
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/stretchr/testify v1.10.0
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/exp v0.0.0-20250606033433-dcc06ee1d476 // indirect
	golang.org/x/sys v0.33.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	lukechampine.com/blake3 v1.4.1 // indirect
)
