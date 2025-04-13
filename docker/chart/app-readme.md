# Quilibrium-node chart

## How to use

Run in docker dir

``` bash
helm install -n default -f chart/values.yaml quilibrium-node chart
```

## Storage Configuration Guide

### 1. `emptyDir` (Temporary Storage)

- An `emptyDir` volume is created when a Pod is assigned to a node
- Data persists only for the Pod's lifetime (deleted when the Pod is removed)
- Storage is backed by:
  - Node's default medium (disk/SSD) by default
  - RAM if `emptyDir.medium: Memory` is set

---

### 2. `hostPath` (Node-Local Storage)

- Binds a directory from the host node's filesystem into the Pod
- Data persists even if the Pod is deleted
- Tied to the node's lifecycle

#### ⚠️ Warnings
- `replicaCount` must be set to `1`
- Not suitable for multi-node clusters
- Potential security risks (host system access)

---

### 3. `PVC` (PersistentVolumeClaim - Production Storage)

- Dynamically provisions a PersistentVolume (PV) per Pod via `volumeClaimTemplates`
- Each Pod gets independent volume (e.g., `pvc-quilibrium-node-0`, `pvc-quilibrium-node-1`)
- Data survives:
  - Pod restarts
  - Rescheduling (if storage backend supports it)


### Comparison Table

| Feature          | emptyDir            | hostPath             | PVC                  |
|------------------|---------------------|----------------------|----------------------|
| Persistence      | ❌ Ephemeral        | ✅ Node-persistent   | ✅ Cluster-persistent|
| Multi-Node       | ✅ Supported        | ❌ Single-node only  | ✅ Supported         |
| Production Ready | ❌ No               | ❌ No               | ✅ Yes              |
| Performance      | High                | Highest              | Storage-dependent    |
| Data Safety      | Low                 | Medium               | High                |