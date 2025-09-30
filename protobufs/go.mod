module source.quilibrium.com/quilibrium/monorepo/protobufs

go 1.23.0

toolchain go1.23.4

replace github.com/libp2p/go-libp2p => ../go-libp2p

replace github.com/multiformats/go-multiaddr => ../go-multiaddr

replace source.quilibrium.com/quilibrium/monorepo/consensus => ../consensus

require (
	github.com/cloudflare/circl v1.6.1
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.26.3
	github.com/iden3/go-iden3-crypto v0.0.17
	github.com/multiformats/go-multiaddr v0.16.1
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.10.0
	google.golang.org/grpc v1.72.0
	google.golang.org/protobuf v1.36.6
	source.quilibrium.com/quilibrium/monorepo/consensus v0.0.0-00010101000000-000000000000
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/ipfs/go-cid v0.0.7 // indirect
	github.com/klauspost/cpuid/v2 v2.2.6 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-base32 v0.1.0 // indirect
	github.com/multiformats/go-base36 v0.2.0 // indirect
	github.com/multiformats/go-multibase v0.2.0 // indirect
	github.com/multiformats/go-multihash v0.2.3 // indirect
	github.com/multiformats/go-varint v0.0.7 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/exp v0.0.0-20230725012225-302865e7556b // indirect
	golang.org/x/net v0.35.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250303144028-a0af3efb3deb // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250303144028-a0af3efb3deb // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	lukechampine.com/blake3 v1.2.1 // indirect
)
