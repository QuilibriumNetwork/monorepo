//! Address alias store — YAML-backed map of name → (address, type).
//!
//! Port of the Go `alias` package (`alias/store.go`). The on-disk format
//! is byte-compatible: a top-level `aliases:` map whose values are either
//! a scalar hex string (address only) or a mapping `{address, type}`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

/// A single alias entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alias {
    pub address: Vec<u8>,
    pub typ: String,
}

impl Serialize for Alias {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Always emit the mapping form `{address: hex, type?: …}`,
        // matching Go's `Alias` marshaling (type omitted when empty).
        let mut len = 1;
        if !self.typ.is_empty() {
            len += 1;
        }
        let mut map = s.serialize_map(Some(len))?;
        map.serialize_entry("address", &hex::encode(&self.address))?;
        if !self.typ.is_empty() {
            map.serialize_entry("type", &self.typ)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Alias {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct AliasVisitor;

        impl<'de> Visitor<'de> for AliasVisitor {
            type Value = Alias;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a hex address string or an {address, type} mapping")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Alias, E> {
                let address = parse_address_literal(v).map_err(de::Error::custom)?;
                Ok(Alias {
                    address,
                    typ: String::new(),
                })
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Alias, M::Error> {
                let mut address: Option<String> = None;
                let mut typ: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "address" => address = Some(map.next_value()?),
                        "type" => typ = Some(map.next_value()?),
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                let address = address
                    .ok_or_else(|| de::Error::missing_field("address"))
                    .and_then(|h| parse_address_literal(&h).map_err(de::Error::custom))?;
                Ok(Alias {
                    address,
                    typ: typ.unwrap_or_default(),
                })
            }
        }

        d.deserialize_any(AliasVisitor)
    }
}

/// The YAML file shape (`type File`).
#[derive(Debug, Default, Serialize, Deserialize)]
struct AliasFile {
    #[serde(default)]
    aliases: BTreeMap<String, Alias>,
}

/// In-memory, file-backed alias store.
pub struct Store {
    data: AliasFile,
    path: Option<PathBuf>,
}

impl Store {
    /// Load a store from `path` (autosave enabled).
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let data: AliasFile = serde_yaml::from_str(&contents)?;
        Ok(Self {
            data,
            path: Some(path.to_path_buf()),
        })
    }

    /// Create (or load) a file-backed store, creating an empty file if
    /// missing. Port of `NewOnDisk`.
    pub fn new_on_disk(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            return Self::load(path);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let store = Self {
            data: AliasFile::default(),
            path: Some(path.to_path_buf()),
        };
        store.save()?;
        Ok(store)
    }

    fn save(&self) -> anyhow::Result<()> {
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no path set for autosave"))?;
        let yaml = serde_yaml::to_string(&self.data)?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, yaml)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Sorted alias names (`List`).
    pub fn list(&self) -> Vec<String> {
        self.data.aliases.keys().cloned().collect()
    }

    /// `Get` → (addr, type).
    pub fn get(&self, name: &str) -> Option<(Vec<u8>, String)> {
        self.data
            .aliases
            .get(name)
            .map(|a| (a.address.clone(), a.typ.clone()))
    }

    /// Insert or replace an alias and autosave (`Put`).
    pub fn put(&mut self, name: &str, addr: &[u8], type_hint: &str) -> anyhow::Result<()> {
        self.data.aliases.insert(
            name.to_string(),
            Alias {
                address: addr.to_vec(),
                typ: type_hint.to_string(),
            },
        );
        self.save()
    }

    /// Delete an alias; returns whether it existed (`Delete`).
    pub fn delete(&mut self, name: &str) -> anyhow::Result<bool> {
        if self.data.aliases.remove(name).is_some() {
            self.save()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// `FindByAddress` → (name, type) for an exact byte match.
    pub fn find_by_address(&self, addr: &[u8]) -> Option<(String, String)> {
        self.data
            .aliases
            .iter()
            .find(|(_, v)| v.address == addr)
            .map(|(k, v)| (k.clone(), v.typ.clone()))
    }

    /// `Resolve` — alias name → (addr, type), else parse literal hex.
    pub fn resolve(&self, key: &str) -> Option<(Vec<u8>, String)> {
        if let Some(r) = self.get(key) {
            return Some(r);
        }
        parse_address_literal(key).ok().map(|b| (b, String::new()))
    }
}

/// Minimal view of the node config's alias-file settings.
#[derive(Debug, Deserialize)]
struct AliasCfgFile {
    alias: Option<AliasCfg>,
}
#[derive(Debug, Deserialize)]
struct AliasCfg {
    #[serde(rename = "aliasFile")]
    alias_file: Option<AliasFileCfg>,
}
#[derive(Debug, Deserialize)]
struct AliasFileCfg {
    #[serde(default)]
    path: String,
    #[serde(rename = "createIfMissing", default)]
    create_if_missing: bool,
}

/// Resolve `(path, create_if_missing)` for the alias file of a node config
/// directory, mirroring Go's `AliasConfig.WithDefaults` (default
/// `<config_dir>/alias.yml`, create-if-missing).
pub fn alias_file_config(config_dir: &Path) -> (PathBuf, bool) {
    let cfg_yaml = config_dir.join("config.yml");
    if let Ok(contents) = std::fs::read_to_string(&cfg_yaml) {
        if let Ok(parsed) = serde_yaml::from_str::<AliasCfgFile>(&contents) {
            if let Some(af) = parsed.alias.and_then(|a| a.alias_file) {
                if !af.path.is_empty() {
                    return (PathBuf::from(af.path), af.create_if_missing);
                }
            }
        }
    }
    (config_dir.join("alias.yml"), true)
}

/// Load (or create-if-missing) the alias store for a node config dir.
/// Port of the `alias` command's `PersistentPreRunE`.
pub fn load_for_config_dir(config_dir: &Path) -> anyhow::Result<Store> {
    let (path, create_if_missing) = alias_file_config(config_dir);
    match Store::load(&path) {
        Ok(s) => Ok(s),
        Err(_) if create_if_missing => Store::new_on_disk(&path),
        Err(e) => Err(e),
    }
}

/// Best-effort load (returns `None` on any error). Port of
/// `utils.LoadAliasStore` used by the hypergraph command.
pub fn try_load_for_config_dir(config_dir: &Path) -> Option<Store> {
    load_for_config_dir(config_dir).ok()
}

/// `parseAddressLiteral` — trim + hex-decode.
pub fn parse_address_literal(s: &str) -> anyhow::Result<Vec<u8>> {
    let t = s.trim();
    if t.is_empty() {
        anyhow::bail!("empty address");
    }
    // Accept an optional 0x prefix for convenience; Go used bare hex.
    let t = t.strip_prefix("0x").unwrap_or(t);
    Ok(hex::decode(t)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scalar_and_mapping_forms() {
        let yaml = "aliases:\n  a: aabbcc\n  b:\n    address: ddee\n    type: vertex\n";
        let file: AliasFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(file.aliases["a"].address, vec![0xaa, 0xbb, 0xcc]);
        assert_eq!(file.aliases["a"].typ, "");
        assert_eq!(file.aliases["b"].address, vec![0xdd, 0xee]);
        assert_eq!(file.aliases["b"].typ, "vertex");
    }

    #[test]
    fn round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alias.yml");
        let mut s = Store::new_on_disk(&path).unwrap();
        s.put("foo", &[1, 2, 3], "hyperedge").unwrap();
        s.put("bar", &[9], "").unwrap();

        let s2 = Store::load(&path).unwrap();
        assert_eq!(s2.list(), vec!["bar".to_string(), "foo".to_string()]);
        assert_eq!(s2.get("foo").unwrap(), (vec![1, 2, 3], "hyperedge".into()));
        assert_eq!(s2.find_by_address(&[9]).unwrap().0, "bar");
    }

    #[test]
    fn resolve_falls_back_to_literal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alias.yml");
        let s = Store::new_on_disk(&path).unwrap();
        assert_eq!(s.resolve("00ff").unwrap().0, vec![0x00, 0xff]);
        assert!(s.resolve("not-hex-!!").is_none());
    }
}
