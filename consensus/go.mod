module source.quilibrium.com/quilibrium/monorepo/consensus

go 1.24.0

toolchain go1.24.9

replace github.com/multiformats/go-multiaddr => ../go-multiaddr

replace github.com/multiformats/go-multiaddr-dns => ../go-multiaddr-dns

replace github.com/libp2p/go-libp2p => ../go-libp2p

replace github.com/libp2p/go-libp2p-kad-dht => ../go-libp2p-kad-dht

require (
	github.com/gammazero/workerpool v1.1.3
	github.com/rs/zerolog v1.34.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gammazero/deque v0.2.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	go.uber.org/goleak v1.3.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.11.1
	go.uber.org/atomic v1.11.0
	golang.org/x/sys v0.33.0 // indirect
)
