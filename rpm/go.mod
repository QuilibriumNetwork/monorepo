module source.quilibrium.com/quilibrium/monorepo/rpm

go 1.23.2

toolchain go1.23.4

// A necessary hack until source.quilibrium.com is open to all
replace source.quilibrium.com/quilibrium/monorepo/nekryptology => ../nekryptology

replace source.quilibrium.com/quilibrium/monorepo/types => ../types

replace source.quilibrium.com/quilibrium/monorepo/protobufs => ../protobufs

replace github.com/libp2p/go-libp2p => ../go-libp2p

replace github.com/libp2p/go-libp2p-kad-dht => ../go-libp2p-kad-dht

replace source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub => ../go-libp2p-blossomsub

replace source.quilibrium.com/quilibrium/monorepo/utils => ../utils

replace source.quilibrium.com/quilibrium/monorepo/config => ../config

replace source.quilibrium.com/quilibrium/monorepo/consensus => ../consensus

replace github.com/multiformats/go-multiaddr => ../go-multiaddr

replace github.com/multiformats/go-multiaddr-dns => ../go-multiaddr-dns

require source.quilibrium.com/quilibrium/monorepo/nekryptology v0.0.0-00010101000000-000000000000

require (
	filippo.io/edwards25519 v1.0.0-rc.1
	github.com/iden3/go-iden3-crypto v0.0.17
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.39.0
	google.golang.org/protobuf v1.36.6
	source.quilibrium.com/quilibrium/monorepo/protobufs v0.0.0-00010101000000-000000000000
	source.quilibrium.com/quilibrium/monorepo/types v0.0.0-00010101000000-000000000000
)

require (
	github.com/btcsuite/btcd v0.21.0-beta.0.20201114000516-e9c7a5ac6401 // indirect
	github.com/bwesterb/go-ristretto v1.2.3 // indirect
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/consensys/gnark-crypto v0.5.3 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.26.3 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/ipfs/go-cid v0.5.0 // indirect
	github.com/ipfs/go-datastore v0.8.2 // indirect
	github.com/ipfs/go-log/v2 v2.5.1 // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/libp2p/go-buffer-pool v0.1.0 // indirect
	github.com/libp2p/go-libp2p v0.41.1 // indirect
	github.com/libp2p/go-msgio v0.3.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-base32 v0.1.0 // indirect
	github.com/multiformats/go-base36 v0.2.0 // indirect
	github.com/multiformats/go-multiaddr v0.16.1 // indirect
	github.com/multiformats/go-multiaddr-fmt v0.1.0 // indirect
	github.com/multiformats/go-multibase v0.2.0 // indirect
	github.com/multiformats/go-multicodec v0.9.1 // indirect
	github.com/multiformats/go-multihash v0.2.3 // indirect
	github.com/multiformats/go-multistream v0.6.1 // indirect
	github.com/multiformats/go-varint v0.0.7 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20250606033433-dcc06ee1d476 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250303144028-a0af3efb3deb // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250303144028-a0af3efb3deb // indirect
	google.golang.org/grpc v1.72.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	lukechampine.com/blake3 v1.4.1 // indirect
	source.quilibrium.com/quilibrium/monorepo/config v0.0.0-00010101000000-000000000000 // indirect
	source.quilibrium.com/quilibrium/monorepo/consensus v0.0.0-00010101000000-000000000000 // indirect
	source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub v0.0.0-00010101000000-000000000000 // indirect
	source.quilibrium.com/quilibrium/monorepo/utils v0.0.0-00010101000000-000000000000 // indirect
)
