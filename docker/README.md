# Quilibrium Docker Guide

This folder contains all the necessary files to build and run Quilibrium nodes using Docker.

## Prerequisites

### Required Tools
- **Docker** (v20.10+) with BuildKit support
- **Docker Compose** (v2.0+)
- **Task** (optional but recommended) - [taskfile.dev](https://taskfile.dev)

### Install Task
```bash
# macOS
brew install go-task

# Linux (script)
sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin

# Or via Go
go install github.com/go-task/task/v3/cmd/task@latest
```

### Docker Version Check
```bash
docker --version    # Should be 20.10+
docker compose version  # Should be v2.0+
```

## 1. System Preparation

Before building or running, optimize the host network stack. Quilibrium relies on the QUIC protocol (UDP), which requires larger buffer sizes than the Linux default.

### Increase UDP Buffer Sizes
```bash
sudo sysctl -w net.core.rmem_max=7500000
sudo sysctl -w net.core.wmem_max=7500000
```
To make these changes permanent, add them to `/etc/sysctl.conf`.

### Configure Firewall (UFW)
Open the ports required for P2P, gRPC, REST, and worker communication:

```bash
sudo ufw allow 22/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8336:8338/udp
sudo ufw allow 8340/udp
sudo ufw allow 50000:50010/tcp
sudo ufw allow 50000:50010/udp
sudo ufw reload
```

## 2. File Structure

| File | Purpose |
| --- | --- |
| `Dockerfile.source` | Main multi-stage build for node + qclient |
| `Dockerfile.sourceavx512` | Optimized build with AVX-512 instructions |
| `Dockerfile.release` | Build from pre-compiled release binaries |
| `Dockerfile.conntest.source` | Connection test utility build |
| `Dockerfile.vdf.*` | VDF performance analysis builds (various CPU optimizations) |
| `docker-compose.yml` | Container orchestration config |
| `Taskfile.yaml` | Task automation commands |
| `.env.example` | Environment variable template |
| `rustup-init.sh` | Rust installer for build stages |

## 3. Dockerfile Variants

### Production Dockerfiles

| Dockerfile | Use Case | Target Stages |
| --- | --- | --- |
| `Dockerfile.source` | Standard build from source | `node-only`, `node`, `qclient`, `final` |
| `Dockerfile.sourceavx512` | AVX-512 optimized (Intel Xeon, AMD Zen4+) | Same as above |
| `Dockerfile.release` | Build from release binaries (faster) | Single stage |

### Specialized Dockerfiles

| Dockerfile | Use Case |
| --- | --- |
| `Dockerfile.conntest.source` | Network connectivity testing |
| `Dockerfile.vdf.source` | VDF performance benchmarking |
| `Dockerfile.vdf.sourceavx512` | VDF with AVX-512 optimizations |
| `Dockerfile.vdf.sourcezen3` | VDF optimized for AMD Zen3 |
| `Dockerfile.vdf.sourcezen4` | VDF optimized for AMD Zen4 |

## 4. Build Targets & Cross-Compilation

### Available Build Tasks

| Task | Platform | Output |
| --- | --- | --- |
| `build_node_arm64_linux` | Linux ARM64 | `../node/build/arm64_linux/` |
| `build_node_amd64_linux` | Linux AMD64 | `../node/build/amd64_linux/` |
| `build_node_amd64_avx512_linux` | Linux AMD64 (AVX-512) | `../node/build/amd64_avx512_linux/` |
| `build_node_arm64_macos` | macOS ARM64 | `../node/build/arm64_macos/` |
| `build_qclient_arm64_linux` | Linux ARM64 | `../client/build/arm64_linux/` |
| `build_qclient_amd64_linux` | Linux AMD64 | `../client/build/amd64_linux/` |
| `build_qclient_amd64_avx512_linux` | Linux AMD64 (AVX-512) | `../client/build/amd64_avx512_linux/` |
| `build_qclient_arm64_macos` | macOS ARM64 | `../client/build/arm64_macos/` |

### Cross-Compilation Examples

**Build Linux ARM64 binary from any platform:**
```bash
task build_node_arm64_linux
```

**Build Linux AMD64 with AVX-512 optimizations:**
```bash
task build_node_amd64_avx512_linux
```

**Manual cross-compilation with Docker:**
```bash
# Build for ARM64
docker build --platform linux/arm64 -f Dockerfile.source --output ../node/build/arm64_linux --target=node ..

# Build for AMD64
docker build --platform linux/amd64 -f Dockerfile.source --output ../node/build/amd64_linux --target=node ..
```

## 5. Docker Images

### Build Images

```bash
# Full image (node + qclient)
task build:source

# Node-only optimized image
task build:node:source

# From release binaries (faster)
task build:release
```

### Image Tags

After building, images are tagged as:
- `quilibrium:2.1.0-source` / `quilibrium:source`
- `quilibrium:2.1.0-node-only` / `quilibrium:node-only`
- `quilibrium:2.1.0-release` / `quilibrium:release`

## 6. Configuration

### Configuration Directory
By default, the Docker configuration uses the `.config` directory at the **root of the repository** (`../.config`). This allows you to share configuration between native and containerized builds.

### Generating Config
```bash
task config:gen
```
This will generate the configuration in `../.config`.

## 7. Running a Node

### Quick Start (Docker Compose)
```bash
task up
```
Or:
```bash
docker compose up -d
```

### Host Networking (Recommended for Servers)
For servers with dedicated public IPs, host networking eliminates Docker NAT overhead:

```bash
task deploy:node
```
Or:
```bash
docker run -d --name q-node \
   --network host \
   --restart unless-stopped \
   -v $(pwd)/../.config:/root/.config \
   quilibrium:node-only -signature-check=false
```

### New Instance
If you are starting a brand new node, a `.config/` folder will be created at the repository root.

> [!IMPORTANT]
> Once the node is running (the `task node-info` command shows a balance), make sure you backup `config.yml` and `keys.yml`.

### Restore Previous Instance
1. Ensure your `config.yml` and `keys.yml` are in the `.config/` folder at the repository root.
2. Start the node: `task up`

## 8. gRPC & REST API Access

The node exposes two APIs for programmatic access:

| API | Port | Protocol | Binding |
| --- | --- | --- | --- |
| **gRPC** | 8337 | TCP | `127.0.0.1` (localhost only) |
| **REST** | 8338 | TCP | `127.0.0.1` (localhost only) |

### Using grpcurl
The container includes `grpcurl` for gRPC interaction:

```bash
# List available services
docker compose exec node grpcurl -plaintext localhost:8337 list

# Get node info
docker compose exec node grpcurl -plaintext localhost:8337 quilibrium.node.node.pb.NodeService/GetNodeInfo

# Get token balance
docker compose exec node grpcurl -plaintext localhost:8337 quilibrium.node.node.pb.NodeService/GetTokenInfo
```

### Using qclient (inside container)
```bash
docker compose exec node qclient help
docker compose exec node qclient token balance
docker compose exec node qclient token info
```

### Exposing APIs Externally
By default, APIs are bound to localhost for security. To expose externally, modify `docker-compose.override.yml`:

```yaml
services:
  node:
    ports:
      - '0.0.0.0:8337:8337/tcp'  # gRPC (use with caution)
      - '0.0.0.0:8338:8338/tcp'  # REST (use with caution)
```

> [!WARNING]
> Exposing gRPC/REST externally can be a security risk. Use a reverse proxy with authentication if needed.

## 9. Management Commands

| Action | Task Command | Docker Command |
| --- | --- | --- |
| **Status** | `task status` | N/A |
| **Logs** | `task logs` | `docker compose logs -f` |
| **Stop** | `task down` | `docker compose down` |
| **Shell** | `task shell` | `docker compose exec -it node sh` |
| **Node Info** | `task node-info` | `docker compose exec node node -node-info` |
| **Backup** | `task backup` | N/A |
| **Restore** | `task restore` | N/A |
| **Update** | `task update` | Pull + restart |
| **Test Port** | `task test:port` | Requires `NODE_PUBLIC_NAME` |

The `backup` task creates a `backup.tar.gz` archive in this `docker/` folder containing `config.yml` and `keys.yml` from `../.config`. Copy this file to a safe location.

### Customizing Configuration
Create a `.env` file based on [.env.example](.env.example):

| Variable | Default | Description |
| --- | --- | --- |
| `QUILIBRIUM_IMAGE_NAME` | `quilibrium` | Docker image name |
| `QUILIBRIUM_CONFIG_DIR` | `../.config` | Configuration directory |
| `QUILIBRIUM_P2P_PORT` | `8336` | P2P UDP port |
| `QUILIBRIUM_GRPC_PORT` | `8337` | gRPC TCP port |
| `QUILIBRIUM_REST_PORT` | `8338` | REST TCP port |
| `NODE_PUBLIC_NAME` | (none) | Public DNS/IP for port testing |

## 10. Verification

### Check Connectivity
Wait 5–10 minutes for the node to initialize. Look for the "Reachable" status:
```bash
docker logs -f q-node | grep "reachable"
```

### Test Port Visibility
```bash
NODE_PUBLIC_NAME=your.server.ip task test:port
```

### Monitor Performance
```bash
docker stats q-node
```

## 11. Troubleshooting

| Issue | Solution |
| --- | --- |
| **Node Not Reachable** | Ensure ports 8336-8340 (UDP) are open in your firewall. |
| **Buffer Size Errors** | Re-run the `sysctl` commands in Step 1. |
| **Config Not Found** | Verify that `../.config` exists and contains your keys. |
| **Backup Fails** | Ensure `../.config/config.yml` and `../.config/keys.yml` exist. |
| **Connection Refused :60000** | Use `--network host` for worker communication. |
| **grpcurl not found** | Use the full image (`build:source`) not `node-only`. |
| **Build fails on Apple Silicon** | Use `--platform linux/amd64` for cross-compilation. |
