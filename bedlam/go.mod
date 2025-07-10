module source.quilibrium.com/quilibrium/monorepo/bedlam

go 1.23.2

replace source.quilibrium.com/quilibrium/monorepo/ferret => ../ferret

require (
	github.com/markkurossi/tabulate v0.0.0-20230223130100-d4965869b123
	github.com/pkg/errors v0.9.1
	source.quilibrium.com/quilibrium/monorepo/ferret v0.0.0-00010101000000-000000000000
)

require golang.org/x/text v0.23.0 // indirect
