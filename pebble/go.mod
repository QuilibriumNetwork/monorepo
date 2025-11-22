module github.com/cockroachdb/pebble

replace github.com/cockroachdb/pebble => ../pebble

require (
	github.com/DataDog/zstd v1.4.5
	github.com/HdrHistogram/hdrhistogram-go v1.2.0
	github.com/cespare/xxhash/v2 v2.3.0
	github.com/cockroachdb/datadriven v1.0.3-0.20230413201302-be42291fc80f
	github.com/cockroachdb/errors v1.12.0
	github.com/cockroachdb/metamorphic v0.0.0-20231120015718-884f2746775a
	github.com/cockroachdb/redact v1.1.6
	github.com/cockroachdb/tokenbucket v0.0.0-20250429170803-42689b6311bb
	github.com/ghemawat/stream v0.0.0-20171120220530-696b145b53b9
	github.com/golang/snappy v1.0.0
	github.com/guptarohit/asciigraph v0.7.3
	github.com/klauspost/compress v1.18.1
	github.com/kr/pretty v0.3.1
	github.com/pkg/errors v0.9.1
	github.com/pmezard/go-difflib v1.0.0
	github.com/prometheus/client_golang v1.23.2
	github.com/prometheus/client_model v0.6.2
	github.com/spf13/cobra v1.10.1
	github.com/stretchr/testify v1.11.1
	golang.org/x/perf v0.0.0-20251112180420-cfbd823f7301
	golang.org/x/sync v0.18.0
	golang.org/x/sys v0.38.0
)

require (
	github.com/aclements/go-moremath v0.0.0-20241023150245-c8bbc672ef66 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cockroachdb/logtags v0.0.0-20241215232642-bb51bb14a506 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/getsentry/sentry-go v0.38.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/common v0.67.4 // indirect
	github.com/prometheus/procfs v0.19.2 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	golang.org/x/text v0.31.0 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

go 1.24.0
