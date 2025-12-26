# Quilibrium Docker Guide

This folder contains all the necessary files to build and run Quilibrium nodes using Docker.


## 1. System Preparation

For system preparation follow this [guide](https://docs.quilibrium.com/). 

If you have issues with connecting to others consider opening up additonal ports 50000+ and 60000+


## 2. Configuration

### Configuration Directory
By default, the Docker configuration uses the `.config` directory at the **root of the repository** (`../.config`). This allows you to share configuration between native and containerized builds.

### Generating Config
```bash
task config:gen
```
This will generate the configuration in `../.config`.

## 3. Running a Node

### Quick Start (Docker Compose)
```bash
task up
```
Or:

```bash
docker compose up -d
```

### New Instance
If you are starting a brand new node, a `.config/` folder will be created at the repository root.

> [!IMPORTANT]
> Once the node is running (the `task node-info` command shows a balance), make sure you backup `config.yml` and `keys.yml`.

### Restore Previous Instance
1. Ensure your `config.yml` and `keys.yml` are in the `.config/` folder at the repository root.
2. Start the node: `task up`


## 4. Management Commands

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
