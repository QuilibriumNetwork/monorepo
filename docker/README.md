# Quilibrium Docker Guide

This folder contains the Dockerfiles and related resources for Quilibrium. All commands should be executed from the **root of the repository** using `task`.

## 1. System Preparation

For system preparation follow the official [Quilibrium Guide](https://docs.quilibrium.com/). 

## 2. Configuration

### Generating Config
The configuration directory `.config` is located at the root of the repository.

```bash
task config:gen
```
This will generate `config.yml` and `keys.yml` in the `.config/` folder.

## 3. Workflow Options

You have two primary ways to use Docker with Quilibrium:

### Option A: Build Binary via Docker (for Native Run)
If you prefer to run the node natively but don't want to set up the full Go build environment, you can use Docker to compile the binary for your specific platform.

1. **Build and Export Binary**:
   Run the task corresponding to your OS/Architecture:
   - **Linux AMD64**: `task build_node_amd64_linux`
   - **Linux ARM64**: `task build_node_arm64_linux`
   - **MacOS ARM**: `task build_node_arm64_macos`

2. **Run Binary**:
   The binary will be exported to `node/build/`. You can then run it directly:
   ```bash
   ./node/build/[platform]/node
   ```

### Option B: Run Entirely via Docker
The node runs inside a Docker container.

1. **Build the Image**:
   ```bash
   task build:node:source
   ```
2. **Deploy the Node**:
   ```bash
   task deploy:node
   ```

   and then you can use the standard docker commands to manage the node.

## 4. Maintenance & Backup

> [!IMPORTANT]
> Always backup your `.config/` directory. It contains your unique node identity and balance information.

- **Backup**: `task backup`
- **Restore**: `task restore`
- **Check Status**: `task status`
