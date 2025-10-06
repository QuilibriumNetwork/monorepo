# P2P Ping Tool

A libp2p client tool for testing peer connectivity by pinging multiple peers from a list of multiaddresses.

## Features

- **Batch ping testing**: Read multiaddresses from stdin and ping each once
- **DNS resolution**: Supports DNS-based multiaddresses (e.g., `/dns/example.com/...`)
- **Real-time reporting**: Shows success/failure for each address immediately
- **Summary statistics**: Displays overall success rate
- **Client-only**: Lightweight client that doesn't listen for incoming connections

## Usage

### From stdin (interactive)
```bash
go run .
# Enter multiaddresses one per line, then Ctrl+D
```

### From file
```bash
go run . < addresses.txt
```

### From command line
```bash
echo "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooW..." | go run .
```

### Multiple addresses
```bash
cat << EOF | go run . -timeout 5s
/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWExample1
/dns/bootstrap.example.com/udp/8336/quic-v1/p2p/12D3KooWExample2
/ip6/::1/tcp/4001/p2p/12D3KooWExample3
EOF
```

## Options

- `-timeout duration`: Connection and ping timeout (default: 10s)

## Output Format

```
P2P Ping Tool - Reading multiaddresses from stdin...
Client started (ID: 12D3KooW...)
=============================================================
[1] Testing: /ip4/127.0.0.1/tcp/4001/p2p/12D3KooWExample
    ✓ SUCCESS - RTT: 15ms

[2] Testing: /dns/unreachable.com/tcp/4001/p2p/12D3KooWBad
    ✗ FAILED - DNS resolution failed: lookup unreachable.com...

=============================================================
Summary: 2 addresses tested
Successful: 1/2 (50.0%)
```

## Supported Multiaddr Formats

- IPv4: `/ip4/127.0.0.1/tcp/4001/p2p/[PEER_ID]`
- IPv6: `/ip6/::1/tcp/4001/p2p/[PEER_ID]`
- DNS: `/dns/example.com/tcp/4001/p2p/[PEER_ID]`
- DNS with QUIC: `/dns/example.com/udp/8336/quic-v1/p2p/[PEER_ID]`

## Error Handling

The tool provides detailed error messages for common failure scenarios:

- **Invalid multiaddr**: Malformed multiaddress syntax
- **DNS resolution failed**: DNS hostname cannot be resolved
- **Connection failed**: Cannot establish connection to peer
- **Ping failed**: Connected but ping protocol failed
