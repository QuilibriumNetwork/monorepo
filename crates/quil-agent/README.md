# qagent

qagent lets an assistant look at your Quilibrium node. The assistant can see whether the node is up and what your balance totals are. It cannot see your addresses. It cannot spend.

You approve any send yourself, on the computer where qagent is running.

## Start

From the repository root:

```
task build_qagent_amd64_linux
```

Then:

```
qagent
```

Leave that terminal open. The first thing it prints is the address, which key to put in the assistant, and which node config it will use.

The assistant connects to `http://127.0.0.1:8350/mcp`. Send a read-only key on every request:

```
Authorization: Bearer <the read-only key>
```

Print that key once. Do not paste it into the assistant's chat:

```
qagent --print-read-only-api-key
```

See the key names without printing the secrets:

```
qagent key list
```

Give one assistant its own read-only key:

```
qagent key issue laptop --read-only
```

## What the assistant can do

With a read-only key:

- `node_info` checks workers, the head frame, and whether the node is reachable.
- `balance` returns totals and counts. It takes no arguments and returns no addresses.

## Asking for a send

Keep the full key (the one named `operator`) out of the assistant unless you want the assistant to be able to ask for a quote. A quote is not a send.

The quote tools take amounts in QUIL. `1` is one QUIL. `0.5` is half a QUIL. Do not type `8000000000`. That number is the base-unit size of one QUIL, not an amount to pass.

The quote, the fee in QUIL and in base units, and the confirmation id are printed on the qagent terminal. The assistant is told only that a quote is waiting.

In another terminal on the same computer:

```
qagent status
qagent confirm <the id printed on the qagent terminal>
```

If the fee has moved too far, confirm prints a new quote and does not send. If you did not ask for the send, do nothing. A quote expires after 10 minutes.

## When something fails

The assistant says "balance unavailable", "node info unavailable", or "quote unavailable". The reason, and what to do next, is on the qagent terminal.

The usual fix is to start qagent with the same config file you use for the node:

```
qagent --node-config /home/you/.quilibrium/configs/NAME/config.yml
```

Inside that file, `key.keyManagerFile.path` must be an absolute path.

## See this again

`qagent status` prints the same explanation and whether a quote is waiting. Run it while qagent is already running.
