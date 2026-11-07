# qagent

qagent is an MCP server for the Quilibrium node on this computer. An assistant can see whether the node is up, what the balance totals are, and what to do next. It cannot see addresses. It cannot spend.

You approve any send yourself, on this computer. Asking for a quote does not send. Today the quote tools stop before a preview exists, so they answer `quote unavailable` and nothing is sent. Reads work.

## Setup

Build from the repository root. On Linux:

```
task build_qagent_amd64_linux
```

The binary is `crates/quil-agent/build/amd64_linux/qagent`. On an Apple Silicon Mac, build on that Mac with `task build_qagent_arm64_macos`. The binary is `crates/quil-agent/build/arm64_macos/qagent`.

Point qagent at the same node config the node is using. Inside that file, `key.keyManagerFile.path` must be an absolute path. Then start it and leave the terminal open:

```
qagent --node-config /home/you/.quilibrium/configs/NAME/config.yml
```

The first start creates `~/.quilibrium/qagent.yaml` and writes two keys if they are missing: `operator` (full) and `read-only`. The terminal prints the listen address, the key names, and the node config. It listens on `127.0.0.1:8350`. Restart qagent after you rebuild it. The process that is already running keeps the old binary.

Print the read-only key once. Do not paste it into the assistant's chat:

```
qagent --print-read-only-api-key
```

Put that key in the assistant's MCP config. For Cursor, that is `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "qagent": {
      "url": "http://127.0.0.1:8350/mcp",
      "headers": {
        "Authorization": "Bearer <the read-only key>"
      }
    }
  }
}
```

Use the read-only key there. Leave the operator key out. See the key names without printing the secrets with `qagent key list`. Give one assistant its own read-only key with `qagent key issue laptop --read-only`.

`~/.quilibrium/qagent.yaml` is readable by its owner. Any program you run as that user on this computer can read the operator secret and call qagent as the operator, even when the assistant was only given a read-only key. A process running as another user, or a client on another machine, cannot read the file.

The first full key is named `operator`. A missing full key or read-only key is created the next time qagent starts. The log names the key used for each request. It does not log the secret.

## What a read-only key can do

A read-only key, and any full key other than the first one, sees the node the way a diagnostics health report does. It is not shown the peer id. No key is given `peerPrivKey`, the keystore encryption key, or the contents of `keys.yml`. A result that would have included them is refused.

`node_info` returns worker counts, the head frame, the epoch, and whether the node is reachable, then short health sentences: workers that are held and why, whether store reads are slow, and up to four active health conditions. If the node does not serve the report, the counts are still returned, with one sentence saying the report was not served. The health section lists at most eight workers that are not simply serving, in the order the node reported them. A blocked worker later in that list can be left out. The version field is the node's three version bytes, not a readable version string.

`balance` returns totals and counts. It takes no arguments and returns no addresses. A live wallet also includes the scan's progress lines, and the scan can take about a minute.

`next_step` says what to do next. It reports a quote already waiting by its action and QUIL amount, says `mint_quote` when claimable rewards are ready, or says `shield_quote` when unshielded coins are waiting. It does not include an address or a confirmation id. It reads the balance again, so it takes about as long as `balance`.

## Asking for a send

Keep the operator key out of the assistant. A full key can call the quote tools. A quote is not a send, and the assistant is not given the confirmation id.

The quote tools take amounts in QUIL. `1` is one QUIL. `0.5` is half a QUIL. Do not type `8000000000`. That number is the base-unit size of one QUIL, not an amount to pass.

Those tools are `transfer_quote`, `mint_quote`, `shield_quote`, `merge_quote`, `split_quote`, `pay_quote`, and `accept_quote`. `token_prepare` is the advanced form and takes base units. A read-only key cannot call any of them.

There is no preview that stops before a send. Until that exists, a quote tool answers `quote unavailable` and does not send. `next_step` can still name `mint_quote` or `shield_quote`. That names the next action. It does not mean the quote tool can complete it.

When a preview exists, the quote, the fee in QUIL and in base units, and the confirmation id are printed on the qagent terminal. The assistant is told only that a quote is waiting. In another terminal on the same computer:

```
qagent status
qagent confirm <the id printed on the qagent terminal>
```

If the fee has moved too far, confirm prints a new quote and does not send. If you did not ask for the send, do nothing. A quote expires after 10 minutes.

## When something fails

The assistant says "balance unavailable", "node info unavailable", or "quote unavailable", then up to five recent warn or error lines from the node log. Those lines are redacted the same way a diagnostics log export redacts them: paths, peer ids, addresses, and keys are removed, and a line that still looks like the keystore is dropped. Shard filter hex from the node's own log can remain. The warnings describe the node. They are not always the reason this call failed. The reason for the call is on the qagent terminal.

A message that mentions a file, a keystore, or a config means the node config qagent opened is not the one the node is using. Stop qagent and start it with that config:

```
qagent --node-config /home/you/.quilibrium/configs/NAME/config.yml
```

Inside that file, `key.keyManagerFile.path` must be an absolute path. A message that mentions a connection or a refused port means the node is not listening. It usually listens on `127.0.0.1:8337`.

## See this again

`qagent status` prints the same explanation and whether a quote is waiting. Run it while qagent is already running.
