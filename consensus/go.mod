module source.quilibrium.com/quilibrium/monorepo/consensus

go 1.24.0

toolchain go1.24.9

replace github.com/multiformats/go-multiaddr => ../go-multiaddr

replace github.com/multiformats/go-multiaddr-dns => ../go-multiaddr-dns

replace github.com/libp2p/go-libp2p => ../go-libp2p

replace github.com/libp2p/go-libp2p-kad-dht => ../go-libp2p-kad-dht

replace source.quilibrium.com/quilibrium/monorepo/lifecycle => ../lifecycle

require github.com/gammazero/workerpool v1.1.3

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gammazero/deque v0.2.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	go.uber.org/goleak v1.3.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/stretchr/testify v1.11.1
	go.uber.org/atomic v1.11.0
	golang.org/x/sync v0.17.0
	source.quilibrium.com/quilibrium/monorepo/lifecycle v0.0.0-00010101000000-000000000000
)
