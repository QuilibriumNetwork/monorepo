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
