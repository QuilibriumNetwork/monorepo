# Contributing

## Testing

See [TESTING.md](./TESTING.md) for testing instructions.

## Pull Requests

Contributions are welcome – a new network is rife with opportunities. We are
in the process of updating our JIRA board so that it can be made public. The
repository has basic coding guidelines:

- 80 character line limit, with the exception where gofmt or the syntax is
  impossible to achieve otherwise
- Error wrapping matching function names
- Interface composition and dependency injection with Wire

## Building release binaries

The following software is required to build release binaries (assuming MacOS
ARM):

- [Running from source](README.md#running-from-source) dependencies
- Docker
- [Taskfile](https://taskfile.dev/)

Then from the repo root use the following commands to build the release binaries
that statically link the [native VDF](./crates/vdf) for the supported platforms:

```shell
task build_node_arm64_macos
task build_node_arm64_linux
task build_node_amd64_linux
```

The output binaries will be in `node/build`.

