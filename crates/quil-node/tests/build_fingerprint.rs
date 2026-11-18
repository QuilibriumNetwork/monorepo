#[path = "../build_support/fingerprint.rs"]
mod fingerprint;

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};
use tempfile::TempDir;

struct Source {
    _dir: TempDir,
    root: PathBuf,
}

impl Source {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let source = Self {
            root: dir.path().canonicalize().unwrap(),
            _dir: dir,
        };
        source.write("Cargo.toml", "[workspace]\n");
        source.write("Cargo.lock", "version = 4\n");
        source.package("node", "[dependencies]\nshared = { path = '../shared' }\n");
        source.package("shared", "");
        source.package("client", "");
        source
    }

    fn root(&self) -> &Path {
        &self.root
    }
    fn node(&self) -> PathBuf {
        self.root().join("crates/node")
    }
    fn write(&self, path: &str, content: &str) {
        let path = self.root().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }
    fn package(&self, name: &str, dependencies: &str) {
        let package_name = name.rsplit('/').next().unwrap();
        self.write(
            &format!("crates/{name}/Cargo.toml"),
            &format!("[package]\nname = '{package_name}'\nversion = '0.1.0'\n{dependencies}"),
        );
        self.write(
            &format!("crates/{name}/src/lib.rs"),
            "pub fn answer() -> u32 { 42 }\n",
        );
    }
    fn identity(&self) -> ([u8; 32], BTreeSet<PathBuf>) {
        let mut watched = BTreeSet::new();
        let digest = fingerprint::fingerprint(
            self.root(),
            &self.node(),
            vec![],
            b"compiler version",
            |p| {
                watched.insert(p.to_owned());
            },
        )
        .unwrap();
        (digest, watched)
    }
}

#[test]
fn client_only_edits_and_new_files_do_not_change_or_watch_node_inputs() {
    let source = Source::new();
    let before = source.identity();
    source.write(
        "crates/client/src/lib.rs",
        "pub fn answer() -> u32 { 43 }\n",
    );
    source.write("crates/client/src/new.rs", "// untracked client source\n");
    source.package("unrelated", "");
    let after = source.identity();
    assert_eq!(before, after);
    assert!(
        !after.1.contains(&source.root().join("crates")),
        "watching the parent would recursively invalidate on client edits"
    );
    assert!(!after
        .1
        .iter()
        .any(|p| p.starts_with(source.root().join("crates/client"))));
}

#[test]
fn dirty_and_new_transitive_sources_change_identity() {
    let source = Source::new();
    let before = source.identity().0;
    source.write(
        "crates/shared/src/lib.rs",
        "pub fn answer() -> u32 { 43 }\n",
    );
    let dirty = source.identity().0;
    assert_ne!(before, dirty);
    source.write("crates/shared/src/new.rs", "// untracked shared source\n");
    assert_ne!(dirty, source.identity().0);
}

#[test]
fn future_dependency_is_discovered_from_changed_manifest() {
    let source = Source::new();
    source.package("future", "");
    let before = source.identity().0;
    source.package(
        "shared",
        "[dependencies]\nfuture = { path = '../future' }\n",
    );
    let with_dependency = source.identity();
    assert_ne!(before, with_dependency.0);
    assert!(with_dependency
        .1
        .contains(&source.root().join("crates/future/src/lib.rs")));
    source.write(
        "crates/future/src/lib.rs",
        "// changed newly reachable source\n",
    );
    assert_ne!(with_dependency.0, source.identity().0);
}

#[test]
fn follows_inherited_build_optional_and_foreign_target_dependencies() {
    let source = Source::new();
    source.write("Cargo.toml", "[workspace]\n[workspace.dependencies]\nalias = { package = 'shared', path = 'crates/shared' }\n");
    source.package("node", "[dependencies]\nalias.workspace = true\noptional = { path = '../optional', optional = true }\n[target.'cfg(windows)'.build-dependencies]\nbuilder = { path = '../builder' }\n[dev-dependencies]\nclient = { path = '../client' }\n");
    source.package("optional", "");
    source.package(
        "builder",
        "[build-dependencies]\nhelper = { path = '../helper' }\n",
    );
    source.package("helper", "");
    let packages = fingerprint::source_packages(source.root(), &source.node(), |_| {}).unwrap();
    for name in ["node", "shared", "optional", "builder", "helper"] {
        assert!(packages.contains(&source.root().join(format!("crates/{name}"))));
    }
    assert!(!packages.contains(&source.root().join("crates/client")));
    let before = source.identity().0;
    source.write(
        "crates/builder/src/lib.rs",
        "// foreign target build dependency\n",
    );
    assert_ne!(before, source.identity().0);
}

#[test]
fn follows_all_local_patch_and_replacement_roots_and_their_dependencies() {
    let source = Source::new();
    source.package(
        "patched",
        "[dependencies]\nshared = { path = '../shared' }\n",
    );
    source.package("replacement", "");
    source.write("Cargo.toml", "[workspace]\n[patch.crates-io]\npatched = { path = 'crates/patched' }\n[patch.'https://example.com/repository']\nother = { path = 'crates/shared' }\n[replace]\n'replacement:0.1.0' = { path = 'crates/replacement' }\n");
    let before = source.identity();
    for name in ["patched", "replacement", "shared"] {
        assert!(before
            .1
            .contains(&source.root().join(format!("crates/{name}/src/lib.rs"))));
    }
    source.write(
        "crates/patched/src/lib.rs",
        "// dirty patched registry dependency\n",
    );
    assert_ne!(before.0, source.identity().0);
}

#[test]
fn ignores_dependency_dev_sources_and_generated_output() {
    let source = Source::new();
    source.package(
        "shared",
        "[dev-dependencies]\nclient = { path = '../client' }\n",
    );
    let before = source.identity().0;
    source.write(
        "crates/client/src/lib.rs",
        "// dependency's dev-only source\n",
    );
    source.write("crates/shared/target/generated.rs", "// generated output\n");
    assert_eq!(before, source.identity().0);
}

#[test]
fn native_proto_toolchain_lock_and_compat_changes_are_identified() {
    let source = Source::new();
    for path in [
        "emp-tool/primitive.cpp",
        "emp-tool/CMakeLists.txt",
        "emp-ot/primitive.h",
        "crates/shared/parameters.json",
        "crates/shared/adapter.cc",
        "protobufs/frame.proto",
        "rust-toolchain.toml",
        "Cargo.lock",
        "node/execution/intrinsics/global/compat/table.json",
    ] {
        source.write(path, "first input\n");
        let before = source.identity();
        assert!(before.1.contains(&source.root().join(path)));
        source.write(path, "second input\n");
        assert_ne!(before.0, source.identity().0, "{path}");
    }
}

#[test]
fn compiler_and_feature_profile_settings_affect_identity_deterministically() {
    let source = Source::new();
    let identify = |settings, compiler: &[u8]| {
        fingerprint::fingerprint(source.root(), &source.node(), settings, compiler, |_| {}).unwrap()
    };
    let settings = vec![
        ("TARGET".into(), "target-one".into()),
        ("CARGO_FEATURE_NATIVE_PROOF".into(), "1".into()),
    ];
    let before = identify(settings.clone(), b"compiler-one");
    let mut reordered = settings.clone();
    reordered.reverse();
    assert_eq!(before, identify(reordered, b"compiler-one"));
    assert_ne!(before, identify(settings.clone(), b"compiler-two"));
    let mut changed = settings.clone();
    changed[0].1 = "target-two".into();
    assert_ne!(before, identify(changed, b"compiler-one"));
    let mut override_settings = settings;
    override_settings.push(("CARGO_PROFILE_RELEASE_LTO".into(), "fat".into()));
    assert_ne!(before, identify(override_settings, b"compiler-one"));
}

#[test]
fn invalid_or_missing_inherited_manifest_inputs_fail_instead_of_truncating_scope() {
    let source = Source::new();
    source.package("node", "[dependencies]\nmissing.workspace = true\n");
    assert!(fingerprint::source_packages(source.root(), &source.node(), |_| {}).is_err());
    source.package(
        "node",
        "[dependencies]\nmissing = { path = '../missing' }\n",
    );
    assert!(fingerprint::source_packages(source.root(), &source.node(), |_| {}).is_err());
    source.write("crates/node/Cargo.toml", "not valid TOML !!");
    assert!(fingerprint::source_packages(source.root(), &source.node(), |_| {}).is_err());
}

#[cfg(unix)]
#[test]
fn external_dependencies_and_linked_sources_cannot_silently_escape_scope() {
    let source = Source::new();
    let outside = tempfile::tempdir().unwrap();
    fs::write(
        outside.path().join("Cargo.toml"),
        "[package]\nname = 'outside'\nversion = '0.1.0'\n",
    )
    .unwrap();
    source.package(
        "node",
        &format!(
            "[dependencies]\noutside = {{ path = '{}' }}\n",
            outside.path().display()
        ),
    );
    assert!(fingerprint::source_packages(source.root(), &source.node(), |_| {}).is_err());
    source.package("node", "");
    std::os::unix::fs::symlink(
        source.root().join("crates/shared/src/lib.rs"),
        source.node().join("src/linked.rs"),
    )
    .unwrap();
    assert!(
        fingerprint::fingerprint(source.root(), &source.node(), vec![], b"compiler", |_| {})
            .is_err()
    );
}

#[test]
fn nested_workspace_inheritance_uses_and_tracks_its_own_manifest() {
    let source = Source::new();
    source.package("root-shared", "");
    source.write(
        "Cargo.toml",
        "[workspace]\n[workspace.dependencies]\nalias = { package = 'root-shared', path = 'crates/root-shared' }\n",
    );
    source.package(
        "node",
        "[dependencies]\nnested = { package = 'dependency', path = '../nested/dependency' }\n",
    );
    source.package(
        "nested/dependency",
        "[dependencies]\nalias.workspace = true\n",
    );
    source.package("nested/shared", "");
    source.write(
        "crates/nested/Cargo.toml",
        "[workspace]\n[workspace.dependencies]\nalias = { package = 'shared', path = 'shared' }\n",
    );
    let before = source.identity();
    assert!(before
        .1
        .contains(&source.root().join("crates/nested/Cargo.toml")));
    assert!(before
        .1
        .contains(&source.root().join("crates/nested/shared/src/lib.rs")));
    assert!(!before
        .1
        .iter()
        .any(|p| p.starts_with(source.root().join("crates/root-shared"))));
    source.write(
        "crates/nested/shared/src/lib.rs",
        "// changed nested workspace source\n",
    );
    assert_ne!(before.0, source.identity().0);
    source.write("crates/nested/dependency/Cargo.toml", "[package]\nname = 'dependency'\nversion = '0.1.0'\nworkspace = '../../..'\n[dependencies]\nalias.workspace = true\n");
    let explicit = source.identity();
    assert!(explicit
        .1
        .contains(&source.root().join("crates/root-shared/src/lib.rs")));
    assert!(!explicit
        .1
        .contains(&source.root().join("crates/nested/shared/src/lib.rs")));
}
