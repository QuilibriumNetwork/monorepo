# qclient

`qclient` is the Quilibrium command-line client. It manages Quilibrium nodes,
keys, tokens, messages, hypergraph data, deployments, and compute operations.

This README is written to be usable by both humans and AI coding agents. It
documents:

1. How to build and install `qclient`.
2. The full command tree (every subcommand with its purpose and usage string).
3. Configuration and on-disk layout.
4. How to build new clients/tooling on top of `qclient` (Go packages,
   wrapping the CLI, RPC reuse).

All command usage strings below are pulled directly from the Cobra command
definitions in [`client/cmd/`](./cmd). When in doubt, run
`qclient <cmd> --help`.

---

## 1. Build and install

### Install the latest release (no build required)

The simplest way to get `qclient` is the published installer script,
[`install-qclient.sh`](../install-qclient.sh). It detects your OS/arch,
downloads the matching signed release from
`https://releases.quilibrium.com`, installs under the platform default
install root (`/opt/quilibrium` on Linux, `/usr/local/quilibrium` on
macOS), and creates the `/usr/local/bin/qclient` symlink.

One-liner (requires `sudo`):

```bash
curl -sSL https://raw.githubusercontent.com/QuilibriumNetwork/ceremonyclient/refs/heads/develop/install-qclient.sh | sudo bash
```

Or run a local copy:

```bash
sudo ./install-qclient.sh
```

Use this path when you just want to run `qclient` and do not need to
modify or build from source.

### Build with Task (preferred for development)

Builds are driven by [Task](https://taskfile.dev) from the **repository root**,
not from `go build` inside this module — native builds require generated
artifacts and CGO libraries that only the root `Taskfile.yaml` wires up.

```bash
task --list

task build_qclient_amd64_linux
task build_qclient_arm64_linux
task build_qclient_amd64_darwin
task build_qclient_arm64_darwin

task build:release
task build:source
```

Outputs land in `client/build/<arch>_<os>/qclient` (e.g. `client/build/amd64_linux/qclient`).

### Install / link

```bash
qclient link           # symlink current binary into /usr/local/bin (sudo)
qclient update         # fetch and swap in a newer qclient release
qclient uninstall      # remove binaries, symlink, and client config
qclient version        # print version
qclient download-signatures
```

### Signature verification

By default `qclient` verifies its own binary against signed digests from the
configured signatories before every command. Controls:

- `--signature-check=false` — skip for this invocation.
- `-y, --yes` — auto-approve and bypass.
- `QUILIBRIUM_SIGNATURE_CHECK=false` — environment default.
- `qclient config signature-check false` — persistent.
- `qclient download-signatures` — fetch the `.dgst` + `.dgst.sig.N` files.

Running from `go run` / source will fail signature check — use
`--signature-check=false`.

### Dev mode (custom / locally-built qclient)

A custom-built `qclient` has no signatures and will otherwise trip the
signature check on every invocation. `qclient dev` applies a sane set of
defaults for that workflow in one shot:

```bash
qclient dev enable    # signatureCheck=false, quiet=true
qclient dev disable   # signatureCheck=true,  quiet=false
qclient dev           # toggle based on current state
```

After enabling, `qclient dev` also offers to symlink the current binary
into `/usr/local/bin/qclient` (equivalent to running `qclient link`), so
subsequent shells pick up your build without further setup. Decline the
prompt to skip linking; the config changes still apply.

### `qclient link` relocation menu

When the current binary is outside the standard install tree
(`/opt/quilibrium/bin/<version>/` on Linux,
`/usr/local/quilibrium/bin/<version>/` on macOS), `qclient link` offers a
menu:

1. Link the current file path as-is (recommended for dev builds).
2. Copy into the standard location, then link (non-destructive install).
3. Move into the standard location, then link.
4. Copy into a custom directory, then link.
5. Abort.

Options 2–4 also relocate any adjacent `.dgst` / `.dgst.sig.*` sidecar
files alongside the binary, so a signed build stays verifiable after the
move.

### Global flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--network <name>` | `$QUILIBRIUM_NETWORK` | Load `~/.quilibrium/configs/<name>/` as the active network config. |
| `--signature-check` | `true` or `$QUILIBRIUM_SIGNATURE_CHECK` | Verify the `qclient` binary signature. |
| `-y, --yes` | `false` | Auto-approve; implies `--signature-check=false`. |

---

## 2. Command reference

Root: `qclient` — *Quilibrium client. CLI for managing Quilibrium nodes.*

Top-level groups: `node`, `config`, `token`, `hypergraph`, `compute`,
`deploy`, `key`, `message`, `alias`, plus the standalone commands
`cross-mint`, `download-signatures`, `link`, `uninstall`, `update`,
`version`, `quiet`, `dev`.

### `qclient node` — Quilibrium node commands

| Command | Purpose |
| --- | --- |
| `install [version]` | Install Quilibrium node |
| `update [version] [--restart\|-r]` | Update the Quilibrium node version |
| `uninstall` | Uninstall Quilibrium node |
| `auto-update [enable\|disable\|status]` | Setup automatic update checks |
| `info [config-name]` | Get information about the Quilibrium node |
| `link` | Create a symlink for a specific node version |
| `clean` | Clean old node files |
| `service [command]` | Manage the Quilibrium node service (systemd/launchd) |
| `grpc enable` / `grpc disable` | Set/clear `listenGrpcMultiaddr` |
| `rest enable` / `rest disable` | Set/clear `listenRESTMultiaddr` |

#### `qclient node config` — Manage node configuration

| Command | Purpose |
| --- | --- |
| `create [name]` | Create a default configuration file set for a node |
| `import [name] [source_directory]` | Import `config.yml` and `keys.yml` from a source directory |
| `switch [name]` | Switch the config run by the node |
| `set [key] [value]` | Set a configuration value |
| `assign-rewards <config-name> [target-config-name]` | Assign rewards to a config |

#### `qclient node log`

| Command | Purpose |
| --- | --- |
| `view` | View node logs |
| `enable` | Enable file-based logging for the active node config |
| `disable` | Disable file-based logging for the active node config |
| `clean` | Clean node logs |

#### `qclient node prover` — prover/shard operations

| Command | Purpose |
| --- | --- |
| `status` | List prover status and shard allocations |
| `shards` | List shards with estimated per-frame reward |
| `shardinfo` | List all known shards with prover counts and estimated rewards |
| `join [filter...]` | Join the prover to the network |
| `leave [filter...]` | Initiate a prover leave |
| `pause [filter]` | Pause a prover |
| `resume [filter]` | Resume a prover |
| `confirm [filter...]` | Confirm prover shard allocations |
| `reject [filter...]` | Reject prover shard allocations |
| `merge` | Merge config data for prover seniority |
| `delegate <DelegateAddress>` | Delegate prover rewards |
| `manage` | Interactive prover shard management TUI |
| `alt-shard-update <vertex-adds-root> <vertex-removes-root> <hyperedge-adds-root> <hyperedge-removes-root>` | Submit an alternative shard state update |

### `qclient config` — QClient configuration

| Command | Purpose |
| --- | --- |
| `print` | Print the current configuration |
| `create-default` | Create a default configuration file |
| `service-name [name]` | Set the Linux systemd service name used by the node |
| `signature-check [true\|false]` | Set signature check setting |
| `public-rpc [true\|false]` | Set public RPC setting |
| `set-custom-rpc [url\|clear]` | Set custom RPC URL |

### `qclient token` — Token operations

| Command | Purpose |
| --- | --- |
| `account` | Show the account address of the managing account |
| `balance` | List the total balance of tokens in the managing account |
| `coins` | List all coins under control of the managing account |
| `mint <ProofHex> [<RecipientAccount>]` | Mint tokens from proof of work |
| `transfer <ToAccount> [RefundAccount] <OfCoin\|Amount>` | Create a transfer of coin |
| `split` | Split a coin into multiple coins |
| `merge [all\|<Coin Addresses>...]` | Merge multiple coins |
| `accept <PendingTransaction>` | Accept a pending transfer |
| `reject <PendingTransaction>` | Reject a pending transaction |

### `qclient key` — Key management

| Command | Purpose |
| --- | --- |
| `list` | List all available keys |
| `create <Name> <KeyType> [Purpose]` | Create a new key (purpose is informational) |
| `import <Name> <KeyType> <KeyBytesHex>` | Import a private key (hex) |
| `delete <Name>` | Delete a key |
| `sign <Name> <PayloadHex> [DomainHex]` | (DANGEROUS) Sign a raw payload |

### `qclient message` — Messaging

| Command | Purpose |
| --- | --- |
| `send <InboxKeyName> <RecipientInboxKeyAddress\|hex> <Message\|->` | Send a message (`-` reads stdin) |
| `retrieve [InboxKeyName]` | Retrieve messages |
| `show <InboxKeyName>` | Display stored messages |
| `delete <InboxKeyName> <MessageIdHex>` | Delete a message |

### `qclient hypergraph` — Hypergraph operations

| Command | Purpose |
| --- | --- |
| `get vertex <FullAddress\|Alias>` | Retrieve and display vertex data |
| `get hyperedge <FullAddress\|Alias>` | Retrieve and display hyperedge data |
| `put vertex [key=value...] [EncryptionKeyBytes]` | Insert or update vertex data |
| `put hyperedge <FullAddress\|Alias> [AtomAddresses\|Aliases...]` | Insert or update hyperedge data |
| `remove vertex <FullAddress\|Alias>` | Remove a vertex |
| `remove hyperedge <FullAddress\|Alias>` | Remove a hyperedge |

### `qclient deploy` — Deploy to the network

| Command | Purpose |
| --- | --- |
| `file <FileName> [EncryptionKeyBytes]` | Deploy a file to the hypergraph |
| `token [Key=Value...]` | Deploy a token |
| `hypergraph [Key=Value...] [RDFFileName]` | Deploy a hypergraph schema |
| `compute <QCLFileName> [RDFFileName]` | Deploy a QCL compute program |
| `update [Key=Value...]` | Update a deployed token configuration |
| `update [RDFFileName] [key=value...]` | Update a deployed hypergraph/compute configuration |
| `get <FullAddress\|Alias> <OutputPath> [DecryptionKey]` | Retrieve a deployed file |

### `qclient compute`

| Command | Purpose |
| --- | --- |
| `execute <FullAddress\|Alias> [Rendezvous] [PartyId] [ArgKey=ArgValue...]` | Execute a compute operation |

### `qclient alias` — Manage address aliases

| Command | Purpose |
| --- | --- |
| `list` | List all aliases |
| `add <alias> <address> [type]` | Add or update an alias |
| `remove <alias>` | Remove an alias |
| `get <alias>` | Get address for an alias |
| `find <address>` | Find alias for an address |
| `resolve <alias_or_address>` | Resolve an alias or address |

### Standalone

| Command | Purpose |
| --- | --- |
| `cross-mint` | Sign a payload from the Quilibrium bridge to mint tokens on Ethereum L1; prints result to stdout |
| `download-signatures` | Download signature files for the current qclient binary |
| `link` | Symlink the qclient binary into `/usr/local/bin` (sudo) |
| `uninstall` | Uninstall qclient (binaries, symlink, client config) |
| `update [version]` | Update qclient version |
| `version` | Display the qclient version |
| `quiet [enable\|disable]` | Hide informational output when signature verification succeeds |
| `dev [enable\|disable]` | Apply sane defaults for custom/locally-built binaries (`signatureCheck=false`, `quiet=true`); offers to symlink the current binary |

---

## 3. Configuration and on-disk layout

### QClient config

Created automatically on first run (or via `qclient config create-default`).
Manage interactively with the `qclient config` subcommands. Inspect with
`qclient config print`.

Key fields include: `SignatureCheck`, `Quiet`, custom RPC URL, public RPC
preference, and active network. See
[`client/utils/clientConfig.go`](./utils/clientConfig.go) for the full
struct.

### Network configs

Selected with `--network <name>` or `QUILIBRIUM_NETWORK`. Resolved to
`~/.quilibrium/configs/<name>/`.

### Node install paths

Defined in [`client/utils/paths.go`](./utils/paths.go):

| Platform | Install dir | State dir | Symlink dir |
| --- | --- | --- | --- |
| Linux (FHS) | `/opt/quilibrium` | `/var/lib/quilibrium` | `/usr/local/bin` |
| macOS | `/usr/local/quilibrium` | `/usr/local/var/quilibrium` | `/usr/local/bin` |

Node configs live under `~/.quilibrium/configs/` by default; file logs go
in `.logs/` inside each config dir when enabled.

Legacy installs under `/var/quilibrium` are detected for migration warnings
only and should not be used for new installs.

---

## 4. Developing on top of qclient

There are three supported integration shapes.

### (a) Wrap the CLI

Most automation should shell out to `qclient`. Tips for agents:

- Use `-y` to bypass interactive prompts, or `QUILIBRIUM_SIGNATURE_CHECK=false`
  for non-interactive environments where signatures are not available.
- Use `qclient config print` to discover the active configuration.
- Many `token`, `hypergraph`, `deploy`, and `compute` commands print
  machine-parseable output to stdout; prefer parsing that over scraping
  help text.
- `qclient cross-mint` prints only the signed payload to stdout, making it
  safe to pipe.

### (b) Import the Go packages

The client is a Go module at `source.quilibrium.com/quilibrium/monorepo/client`.
Useful internal packages:

| Package | Purpose |
| --- | --- |
| [`client/utils`](./utils) | Client config loading, paths, RPC client, downloads, node helpers, file utils, types, user input. |
| [`client/utils/rpc.go`](./utils/rpc.go) | `GetGRPCClient(...)` — construct a gRPC client against the configured/custom/public RPC. |
| [`client/utils/clientConfig.go`](./utils/clientConfig.go) | `ClientConfig`, `LoadClientConfig`, `CreateDefaultConfig`, `GetConfigPath`. |
| [`client/utils/paths.go`](./utils/paths.go) | Platform-aware install, state, and symlink directories. |
| [`client/hypergraph`](./hypergraph) | Remote hypergraph helpers (see `remote.go`). |
| [`client/pkg/yamlutil`](./pkg/yamlutil) | YAML helpers used by node/nodeconfig commands. |
| [`client/cmd/...`](./cmd) | Cobra commands — useful as references for how to call RPC + keys + tokens. |

Pattern for adding a new subcommand (mirrors everything already in `cmd/`):

1. Create `client/cmd/<group>/<name>.go` exposing a `var FooCmd = &cobra.Command{...}`.
2. Register it from the parent group's `init()` via `parent.AddCommand(FooCmd)`.
3. New top-level groups are wired in from
   [`client/cmd/root.go`](./cmd/root.go) in `init()`.
4. Use `utils.LoadClientConfig()` and `utils.GetGRPCClient(...)` rather than
   re-implementing RPC setup.
5. Never bypass the root `PersistentPreRun` signature check logic — it runs
   automatically for all subcommands except `help` and `download-signatures`.

### (c) Reuse only the RPC layer

If you only need to talk to a node, construct a gRPC client via
`utils.GetGRPCClient` with a loaded `ClientConfig`. The generated gRPC stubs
live in the sibling `node/` module of this monorepo — see the root
`go.work` and top-level README for how the node's protobuf definitions are
exposed.

---

## Quick reference for agents

- To install a release without building: `curl -sSL https://raw.githubusercontent.com/QuilibriumNetwork/ceremonyclient/refs/heads/develop/install-qclient.sh | sudo bash` (or `sudo ./install-qclient.sh` from a checkout).
- To build from source, prefer `task build_qclient_<arch>_<os>` from the repo root.
- Always pass `-y` in non-interactive automation.
- Config lives at the path returned by `utils.GetConfigPath()`; node configs
  live under `~/.quilibrium/configs/<name>/`.
- Every command supports `--help`; treat that as the source of truth.
- For new functionality, add a Cobra command under `client/cmd/<group>/`
  and register it — do not fork `main.go`.
