# Testing

Each project in the repository has an accompanying ./test.sh script. Ensure you
have the requisite dependencies installed, instructions available in the
README.md file.

## Dependency tests

The supporting libraries linking rust crates to go will perform native tests,
and must be run with ./test.sh to handle the required links:

    cd vdf
    ./test.sh ./...

## Node/QClient tests

Tests are separated into three categories, which can affect how they are run.
All of these are runnable with the accompanying ./test.sh script, however for
developers wanting to run at least the unit tests in their IDE, these tests
do not use native dependencies and can be run with `go test`.

### Unit tests

The collection of unit tests in the repository can be run with either:

    go test ./...

or

    ./test.sh ./...

in the node or client folder.

### Integration tests (native dependencies)

To allow integration tests to run, they must use the ./test.sh script. To avoid
unintentionally triggering them in the build process or in the IDE, where many
do not allow for the extra linker variables required to support native
dependencies, they have been tagged with `integrationtest`, and can be run with

    ./test.sh -tags=integrationtest ./... -short

Note the `-short` flag, there are very long running tests, mentioned in the next
section.

### Long-running integration tests

Our chaos test simulation runs on the order of hours, and is typically
undesirable to run without intent. To run those tests, you can run the above
command with `-short` omitted:

    ./test.sh -tags=integrationtest ./...

which will run with the other integration tests. To specifically target the long
running tests, run with the following:

    ./test.sh -tags=integrationtest -run Chaos ./...

Please note, these tests take hours to run, and are computationally expensive.

