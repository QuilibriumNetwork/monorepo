# Quilibrium Node: Build from Source & Deployment Guide

This guide covers the end-to-end process of building a Quilibrium (Q-Node) from source using Docker and optimizing it for hosting environments.

## 1. System Preparation

Before building, optimize the host network stack. Quilibrium relies on the QUIC protocol (UDP), which requires larger buffer sizes than the Linux default to prevent packet loss.

### Increase UDP Buffer Sizes
Run these commands on your server:

```bash
sudo sysctl -w net.core.rmem_max=7500000
sudo sysctl -w net.core.wmem_max=7500000
```

To make these changes permanent, add them to `/etc/sysctl.conf`.

### Configure Firewall (UFW)
Open the ports required for P2P, streaming, and worker communication:

```bash
sudo ufw allow 22/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8336:8338/udp
sudo ufw allow 8340/udp
sudo ufw allow 50000:50010/tcp
sudo ufw allow 50000:50010/udp
sudo ufw reload
```

## 2. Configuration Generation

Quilibrium nodes require a valid configuration and cryptographic keys to participate in the network. For containerized deployments, it is recommended to generate these separately from the main node execution.

### Why Separate Config Generation?
1. **Security**: Sensitive key generation is handled explicitly as a separate step.
2. **Immutability**: Pre-generated configurations can be mounted as read-only volumes, following container best practices.
3. **Stability**: Ensures consistent network settings (like UDP/QUIC-v1) before the node starts.

### Generating Config
You can use the `config-gen` utility included in the Docker image or build it from source.

**Using Docker:**
```bash
docker run --rm -v $(pwd)/.config:/root/.config quilibrium --target node-only config-gen --config /root/.config
```

## 3. Build from Source

Using `DOCKER_BUILDKIT`, we can build a highly optimized, slim image specifically for the node.

### The Build Command
Navigate to your monorepo directory and execute:

```bash
DOCKER_BUILDKIT=1 docker build \
  --target node-only \
  -f Dockerfile.source \
  --build-arg GIT_COMMIT=$(git log -1 --format=%h) \
  -t quilibrium \
  -t quilibrium:$(git describe --tags --abbrev=0 2>/dev/null || echo "latest") .
```

### Why these flags?
- `--target node-only`: Excludes unnecessary build tools from the final image.
- `--build-arg GIT_COMMIT`: Embeds the specific version hash into the binary for network identification.
- `-t quilibrium:tag`: Tags the image with a specific version for easy management and rollbacks.

## 4. Deployment

For servers with dedicated public IPs, **Host Networking** is the recommended deployment method. It eliminates Docker NAT overhead and ensures the node is easily reachable by peers.

### Run the Container
```bash
docker run -d --name q-node \
   --network host \
   --restart unless-stopped \
   -v $(pwd)/.config:/root/.config \
   quilibrium -signature-check=false
```

## 5. Managing the Container

| Action | Command |
| --- | --- |
| **Stop** | `docker stop q-node` |
| **Start** | `docker start q-node` |
| **Restart** | `docker restart q-node` |
| **Status** | `docker ps --filter "name=q-node"` |
| **Logs** | `docker logs -f q-node` |

## 6. Verification

### Check Connectivity
Wait 5–10 minutes for the node to initialize workers and sync. Look for the "Reachable" status:
```bash
docker logs -f q-node | grep "reachable"
```

### Monitor Performance
Check how much data your node is processing:
```bash
docker stats q-node
```

## 7. Troubleshooting

| Error | Meaning | Solution |
| --- | --- | --- |
| `connection refused ... :60000` | Master cannot talk to Workers. | Use `--network host`. |
| `YOUR NODE IS NOT REACHABLE` | External peers can't find you. | Ensure Ports 8336-8340 (UDP) are open. |
| `failed to increase buffer size` | UDP throttling. | Re-run the `sysctl` commands in Step 1. |
