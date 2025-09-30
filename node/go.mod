module source.quilibrium.com/quilibrium/monorepo/node

go 1.23.2

toolchain go1.23.4

replace source.quilibrium.com/quilibrium/monorepo/nekryptology => ../nekryptology

replace source.quilibrium.com/quilibrium/monorepo/bls48581 => ../bls48581

replace source.quilibrium.com/quilibrium/monorepo/bulletproofs => ../bulletproofs

replace source.quilibrium.com/quilibrium/monorepo/ferret => ../ferret

replace source.quilibrium.com/quilibrium/monorepo/channel => ../channel

replace source.quilibrium.com/quilibrium/monorepo/bedlam => ../bedlam

replace source.quilibrium.com/quilibrium/monorepo/types => ../types

replace source.quilibrium.com/quilibrium/monorepo/vdf => ../vdf

replace source.quilibrium.com/quilibrium/monorepo/verenc => ../verenc

replace source.quilibrium.com/quilibrium/monorepo/protobufs => ../protobufs

replace source.quilibrium.com/quilibrium/monorepo/utils => ../utils

replace source.quilibrium.com/quilibrium/monorepo/config => ../config

replace source.quilibrium.com/quilibrium/monorepo/hypergraph => ../hypergraph

replace source.quilibrium.com/quilibrium/monorepo/consensus => ../consensus

replace source.quilibrium.com/quilibrium/monorepo/rpm => ../rpm

replace github.com/multiformats/go-multiaddr => ../go-multiaddr

replace github.com/multiformats/go-multiaddr-dns => ../go-multiaddr-dns

replace github.com/libp2p/go-libp2p => ../go-libp2p

replace github.com/libp2p/go-libp2p-kad-dht => ../go-libp2p-kad-dht

replace source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub => ../go-libp2p-blossomsub

require (
	github.com/cockroachdb/pebble v1.1.4
	github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus v1.0.1
	github.com/libp2p/go-libp2p v0.41.1
	github.com/libp2p/go-libp2p-kad-dht v0.23.0
	github.com/shopspring/decimal v1.4.0
	google.golang.org/protobuf v1.36.6
	gopkg.in/yaml.v2 v2.4.0
	source.quilibrium.com/quilibrium/monorepo/bedlam v0.0.0-00010101000000-000000000000
	source.quilibrium.com/quilibrium/monorepo/bls48581 v0.0.0-00010101000000-000000000000
	source.quilibrium.com/quilibrium/monorepo/bulletproofs v0.0.0-00010101000000-000000000000
	source.quilibrium.com/quilibrium/monorepo/channel v0.0.0-00010101000000-000000000000
	source.quilibrium.com/quilibrium/monorepo/config v0.0.0-00010101000000-000000000000
	source.quilibrium.com/quilibrium/monorepo/consensus v0.0.0-00010101000000-000000000000
	source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub v0.0.0-00010101000000-000000000000
	source.quilibrium.com/quilibrium/monorepo/hypergraph v0.0.0-00010101000000-000000000000
	source.quilibrium.com/quilibrium/monorepo/nekryptology v0.0.0-00010101000000-000000000000
	source.quilibrium.com/quilibrium/monorepo/protobufs v0.0.0-00010101000000-000000000000
	source.quilibrium.com/quilibrium/monorepo/types v0.0.0-00010101000000-000000000000
	source.quilibrium.com/quilibrium/monorepo/utils v0.0.0-00010101000000-000000000000
	source.quilibrium.com/quilibrium/monorepo/rpm v0.0.0-00010101000000-000000000000
	source.quilibrium.com/quilibrium/monorepo/vdf v0.0.0-00010101000000-000000000000
	source.quilibrium.com/quilibrium/monorepo/verenc v0.0.0-00010101000000-000000000000
)

require (
	filippo.io/edwards25519 v1.0.0-rc.1 // indirect
	github.com/cockroachdb/fifo v0.0.0-20240606204812-0bbfbd93a7ce // indirect
	github.com/deiu/gon3 v0.0.0-20241212124032-93153c038193 // indirect
	github.com/deiu/rdf2go v0.0.0-20241212211204-b661ba0dfd25 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.1.0 // indirect
	github.com/libp2p/go-libp2p-routing-helpers v0.7.2 // indirect
	github.com/libp2p/go-yamux/v5 v5.0.1 // indirect
	github.com/linkeddata/gojsonld v0.0.0-20170418210642-4f5db6791326 // indirect
	github.com/markkurossi/tabulate v0.0.0-20230223130100-d4965869b123 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pion/datachannel v1.5.10 // indirect
	github.com/pion/dtls/v2 v2.2.12 // indirect
	github.com/pion/dtls/v3 v3.0.6 // indirect
	github.com/pion/ice/v4 v4.0.10 // indirect
	github.com/pion/interceptor v0.1.40 // indirect
	github.com/pion/logging v0.2.3 // indirect
	github.com/pion/mdns/v2 v2.0.7 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.15 // indirect
	github.com/pion/rtp v1.8.19 // indirect
	github.com/pion/sctp v1.8.39 // indirect
	github.com/pion/sdp/v3 v3.0.13 // indirect
	github.com/pion/srtp/v3 v3.0.6 // indirect
	github.com/pion/stun v0.6.1 // indirect
	github.com/pion/stun/v3 v3.0.0 // indirect
	github.com/pion/transport/v2 v2.2.10 // indirect
	github.com/pion/transport/v3 v3.0.7 // indirect
	github.com/pion/turn/v4 v4.0.2 // indirect
	github.com/pion/webrtc/v4 v4.1.2 // indirect
	github.com/rychipman/easylex v0.0.0-20160129204217-49ee7767142f // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/txaty/go-merkletree v0.2.2 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel v1.34.0 // indirect
	go.opentelemetry.io/otel/metric v1.34.0 // indirect
	go.opentelemetry.io/otel/trace v1.34.0 // indirect
	go.uber.org/mock v0.5.2 // indirect
	golang.org/x/time v0.12.0 // indirect
	source.quilibrium.com/quilibrium/monorepo/ferret v0.0.0-00010101000000-000000000000 // indirect
)

require (
	github.com/DataDog/zstd v1.4.5 // indirect
	github.com/btcsuite/btcd v0.21.0-beta.0.20201114000516-e9c7a5ac6401
	github.com/bwesterb/go-ristretto v1.2.3 // indirect
	github.com/cockroachdb/errors v1.11.3 // indirect
	github.com/cockroachdb/logtags v0.0.0-20230118201751-21c54148d20b // indirect
	github.com/cockroachdb/redact v1.1.5 // indirect
	github.com/cockroachdb/tokenbucket v0.0.0-20230807174530-cc333fc44b06 // indirect
	github.com/consensys/gnark-crypto v0.5.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/getsentry/sentry-go v0.27.0 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.26.3 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/multiformats/go-multiaddr v0.16.1
	github.com/pmezard/go-difflib v1.0.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250303144028-a0af3efb3deb // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250303144028-a0af3efb3deb // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/benbjohnson/clock v1.3.5 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.1
	github.com/davidlazar/go-crypto v0.0.0-20200604182044-b73af7476f6c // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/flynn/noise v1.1.0 // indirect
	github.com/francoispqt/gojay v1.2.13 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/google/wire v0.5.0
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/huin/goupnp v1.3.0 // indirect
	github.com/iden3/go-iden3-crypto v0.0.17
	github.com/ipfs/boxo v0.10.0 // indirect
	github.com/ipfs/go-cid v0.5.0 // indirect
	github.com/ipfs/go-datastore v0.8.2
	github.com/ipfs/go-log v1.0.5 // indirect
	github.com/ipfs/go-log/v2 v2.5.1 // indirect
	github.com/ipld/go-ipld-prime v0.20.0 // indirect
	github.com/jackpal/go-nat-pmp v1.0.2 // indirect
	github.com/jbenet/go-temp-err-catcher v0.1.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/koron/go-ssdp v0.0.6 // indirect
	github.com/libp2p/go-buffer-pool v0.1.0 // indirect
	github.com/libp2p/go-cidranger v1.1.0 // indirect
	github.com/libp2p/go-flow-metrics v0.2.0 // indirect
	github.com/libp2p/go-libp2p-asn-util v0.4.1 // indirect
	github.com/libp2p/go-libp2p-kbucket v0.6.3 // indirect
	github.com/libp2p/go-libp2p-record v0.2.0 // indirect
	github.com/libp2p/go-msgio v0.3.0 // indirect
	github.com/libp2p/go-netroute v0.2.2 // indirect
	github.com/libp2p/go-reuseport v0.4.0 // indirect
	github.com/marten-seemann/tcp v0.0.0-20210406111302-dfbc87cc63fd // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/miekg/dns v1.1.66 // indirect
	github.com/mikioh/tcpinfo v0.0.0-20190314235526-30a79bb1804b // indirect
	github.com/mikioh/tcpopt v0.0.0-20190314235656-172688c1accc // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/mr-tron/base58 v1.2.0
	github.com/multiformats/go-base32 v0.1.0 // indirect
	github.com/multiformats/go-base36 v0.2.0 // indirect
	github.com/multiformats/go-multiaddr-dns v0.4.1
	github.com/multiformats/go-multiaddr-fmt v0.1.0 // indirect
	github.com/multiformats/go-multibase v0.2.0 // indirect
	github.com/multiformats/go-multicodec v0.9.1 // indirect
	github.com/multiformats/go-multihash v0.2.3 // indirect
	github.com/multiformats/go-multistream v0.6.1 // indirect
	github.com/multiformats/go-varint v0.0.7 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/pbnjay/memory v0.0.0-20210728143218-7b4eea64cf58
	github.com/pkg/errors v0.9.1
	github.com/polydawn/refmt v0.89.0 // indirect
	github.com/prometheus/client_golang v1.22.0
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.64.0 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/quic-go/quic-go v0.54.0 // indirect
	github.com/quic-go/webtransport-go v0.9.0 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/stretchr/testify v1.10.0
	github.com/whyrusleeping/go-keyspace v0.0.0-20160322163242-5b898ac5add1 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.uber.org/dig v1.19.0 // indirect
	go.uber.org/fx v1.24.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.39.0
	golang.org/x/exp v0.0.0-20250606033433-dcc06ee1d476
	golang.org/x/mod v0.25.0 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sync v0.15.0
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	golang.org/x/tools v0.34.0 // indirect
	gonum.org/v1/gonum v0.13.0 // indirect
	google.golang.org/grpc v1.72.0
	lukechampine.com/blake3 v1.4.1 // indirect
)
