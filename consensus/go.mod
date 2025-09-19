module source.quilibrium.com/quilibrium/monorepo/consensus

go 1.23.0

toolchain go1.23.4

replace source.quilibrium.com/quilibrium/monorepo/protobufs => ../protobufs

replace source.quilibrium.com/quilibrium/monorepo/types => ../types

replace source.quilibrium.com/quilibrium/monorepo/config => ../config

replace source.quilibrium.com/quilibrium/monorepo/utils => ../utils

replace github.com/multiformats/go-multiaddr => ../go-multiaddr

replace github.com/multiformats/go-multiaddr-dns => ../go-multiaddr-dns

replace github.com/libp2p/go-libp2p => ../go-libp2p

replace github.com/libp2p/go-libp2p-kad-dht => ../go-libp2p-kad-dht

replace source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub => ../go-libp2p-blossomsub

require go.uber.org/zap v1.27.0

require (
	github.com/stretchr/testify v1.10.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
)

require github.com/pkg/errors v0.9.1
