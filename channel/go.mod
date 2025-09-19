module source.quilibrium.com/quilibrium/monorepo/channel

go 1.20

// A necessary hack until source.quilibrium.com is open to all
replace source.quilibrium.com/quilibrium/monorepo/nekryptology => ../nekryptology

replace source.quilibrium.com/quilibrium/monorepo/protobufs => ../protobufs

replace github.com/multiformats/go-multiaddr => ../go-multiaddr

replace github.com/multiformats/go-multiaddr-dns => ../go-multiaddr-dns

replace github.com/libp2p/go-libp2p => ../go-libp2p

replace source.quilibrium.com/quilibrium/monorepo/types => ../types

replace source.quilibrium.com/quilibrium/monorepo/utils => ../utils

require (
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.10.0
	source.quilibrium.com/quilibrium/monorepo/types v0.0.0-00010101000000-000000000000
)

require (
	filippo.io/edwards25519 v1.0.0-rc.1 // indirect
	github.com/btcsuite/btcd v0.21.0-beta.0.20201114000516-e9c7a5ac6401 // indirect
	github.com/bwesterb/go-ristretto v1.2.3 // indirect
	github.com/consensys/gnark-crypto v0.5.3 // indirect
	github.com/kr/pretty v0.2.1 // indirect

)

require (
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.38.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	source.quilibrium.com/quilibrium/monorepo/nekryptology v0.0.0-00010101000000-000000000000
)
