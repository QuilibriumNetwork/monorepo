//! Conservative node-source provenance; this is not a binary attestation.
//!
//! Traverse local normal/build dependencies for every target and optional
//! feature, plus every local workspace patch/replacement. This deliberately
//! over-approximates a particular Cargo invocation without spawning Cargo
//! inside a build script or maintaining an exclusion list.

use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    error::Error,
    fs,
    path::{Path, PathBuf},
};
use toml::Value;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn manifest(path: &Path) -> Result<Value> {
    Ok(toml::from_str(&fs::read_to_string(path)?)?)
}

fn local_path(base: &Path, dependency: &Value) -> Option<PathBuf> {
    dependency
        .get("path")
        .and_then(Value::as_str)
        .map(|path| base.join(path))
}

fn dependencies(
    table: &Value,
    base: &Path,
    root: &Path,
    workspace: &Value,
    pending: &mut Vec<PathBuf>,
) -> Result<()> {
    for kind in ["dependencies", "build-dependencies"] {
        let Some(entries) = table.get(kind).and_then(Value::as_table) else {
            continue;
        };
        for (name, dependency) in entries {
            let inherited = dependency.get("workspace").and_then(Value::as_bool) == Some(true);
            let (dependency, base) = if inherited {
                let definition = workspace
                    .get("workspace")
                    .and_then(|v| v.get("dependencies"))
                    .and_then(|v| v.get(name))
                    .ok_or_else(|| format!("missing inherited dependency {name}"))?;
                (definition, root)
            } else {
                (dependency, base)
            };
            if let Some(path) = local_path(base, dependency) {
                pending.push(path);
            }
        }
    }
    Ok(())
}

fn inherited_workspace(root: &Path, package: &Path, value: &Value) -> Result<(PathBuf, Value)> {
    let explicit = value
        .get("package")
        .and_then(|p| p.get("workspace"))
        .and_then(Value::as_str);
    let paths = if let Some(path) = explicit {
        vec![package.join(path)]
    } else {
        package
            .ancestors()
            .take_while(|p| p.starts_with(root))
            .map(Path::to_owned)
            .collect()
    };
    for path in paths {
        let path = path.canonicalize()?;
        if !path.starts_with(root) {
            return Err(
                "node fingerprint requires inherited workspaces inside the source tree".into(),
            );
        }
        let manifest_path = path.join("Cargo.toml");
        if !manifest_path.exists() {
            continue;
        }
        let value = manifest(&manifest_path)?;
        if value.get("workspace").is_some() {
            return Ok((path, value));
        }
    }
    Err("missing workspace for inherited dependency".into())
}

pub fn source_packages(
    root: &Path,
    node: &Path,
    mut workspace_manifest: impl FnMut(&Path),
) -> Result<BTreeSet<PathBuf>> {
    let root = root.canonicalize()?;
    let workspace = manifest(&root.join("Cargo.toml"))?;
    let mut pending = vec![node.to_path_buf()];
    // Include all local overrides, even if inactive in this build. A registry
    // dependency can reach them indirectly, outside the local manifest graph.
    if let Some(sources) = workspace.get("patch").and_then(Value::as_table) {
        for patches in sources.values().filter_map(Value::as_table) {
            for dependency in patches.values() {
                if let Some(path) = local_path(&root, dependency) {
                    pending.push(path);
                }
            }
        }
    }
    if let Some(replacements) = workspace.get("replace").and_then(Value::as_table) {
        for dependency in replacements.values() {
            if let Some(path) = local_path(&root, dependency) {
                pending.push(path);
            }
        }
    }
    let mut packages = BTreeSet::new();
    while let Some(path) = pending.pop() {
        let path = path.canonicalize()?;
        if !path.starts_with(&root) {
            return Err(
                "node fingerprint requires local dependencies inside the source tree".into(),
            );
        }
        if !packages.insert(path.clone()) {
            continue;
        }
        let package = manifest(&path.join("Cargo.toml"))?;
        let (workspace_root, package_workspace) = inherited_workspace(&root, &path, &package)?;
        workspace_manifest(&workspace_root.join("Cargo.toml"));
        dependencies(
            &package,
            &path,
            &workspace_root,
            &package_workspace,
            &mut pending,
        )?;
        if let Some(targets) = package.get("target").and_then(Value::as_table) {
            for target in targets.values() {
                dependencies(
                    target,
                    &path,
                    &workspace_root,
                    &package_workspace,
                    &mut pending,
                )?;
            }
        }
    }
    Ok(packages)
}

fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn hash_tree(
    root: &Path,
    path: &Path,
    hash: &mut Sha256,
    watch: &mut impl FnMut(&Path),
    data: bool,
) -> Result<()> {
    if path.is_symlink() {
        // Silently skipping linked source would identify different inputs as
        // the same build. Fail rather than claim incomplete provenance.
        return Err("node fingerprint does not support symlinked source inputs".into());
    }
    if !path.exists() {
        return Ok(());
    }
    if path.is_dir() {
        watch(path);
        let mut entries = fs::read_dir(path)?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort();
        for entry in entries {
            let name = entry.file_name().unwrap().to_string_lossy();
            if name.starts_with('.')
                || matches!(name.as_ref(), "target" | "node_modules" | "worker-store")
            {
                continue;
            }
            hash_tree(root, &entry, hash, watch, data)?;
        }
    } else if data
        || path.file_name().and_then(|name| name.to_str()) == Some("CMakeLists.txt")
        || matches!(
            path.extension().and_then(|e| e.to_str()),
            Some(
                "rs" | "toml"
                    | "lock"
                    | "proto"
                    | "udl"
                    | "c"
                    | "cc"
                    | "cpp"
                    | "cxx"
                    | "h"
                    | "hpp"
                    | "inc"
                    | "s"
                    | "S"
                    | "cmake"
                    | "json"
            )
        )
    {
        watch(path);
        let name = path.strip_prefix(root)?.to_string_lossy();
        field(hash, name.as_bytes());
        field(hash, &fs::read(path)?);
    }
    Ok(())
}

pub fn fingerprint(
    root: &Path,
    node: &Path,
    mut settings: Vec<(String, String)>,
    compiler: &[u8],
    mut watch: impl FnMut(&Path),
) -> Result<[u8; 32]> {
    let root = root.canonicalize()?;
    let mut workspace_manifests = BTreeSet::new();
    let packages = source_packages(&root, node, |path| {
        workspace_manifests.insert(path.to_owned());
    })?;
    let mut hash = Sha256::new();
    // Different meaning from the old whole-workspace source fingerprint.
    hash.update(b"quilibrium/node-source-build/v2");
    for path in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "protobufs",
        "emp-ot",
        "emp-tool",
    ] {
        hash_tree(&root, &root.join(path), &mut hash, &mut watch, false)?;
    }
    for manifest in workspace_manifests {
        if manifest != root.join("Cargo.toml")
            && !packages.iter().any(|package| manifest.starts_with(package))
        {
            hash_tree(&root, &manifest, &mut hash, &mut watch, false)?;
        }
    }
    for package in packages {
        hash_tree(&root, &package, &mut hash, &mut watch, false)?;
    }
    // Execution embeds these tables outside its own package directory.
    hash_tree(
        &root,
        &root.join("node/execution/intrinsics/global/compat"),
        &mut hash,
        &mut watch,
        true,
    )?;
    settings.sort();
    for (key, value) in settings {
        field(&mut hash, key.as_bytes());
        field(&mut hash, value.as_bytes());
    }
    field(&mut hash, compiler);
    Ok(hash.finalize().into())
}
