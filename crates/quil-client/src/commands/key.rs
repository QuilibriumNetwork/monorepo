//! `qclient key …` — keystore management.
//!
//! Port of `client/cmd/key/key.go`. Operates on the node's `keys.yml` via
//! `FileKeyManager`. Key-type parsing gains `falcon`/`falcon512` (KeyType 8),
//! the post-quantum signing key type.

use clap::Subcommand;

use quil_types::crypto::Signer;

use crate::alias_store::{self, Store};
use crate::context::{Context, GlobalArgs};

#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// List all available keys.
    List,
    /// Create a new key: `<name> <keyType> [purpose]`.
    Create {
        name: String,
        key_type: String,
        purpose: Option<String>,
    },
    /// Delete a key.
    Delete { name: String },
    /// Import a private key (hex): `<name> <keyType> <keyBytesHex>`.
    Import {
        name: String,
        key_type: String,
        key_hex: String,
    },
    /// (DANGEROUS) Sign a raw payload: `<name> <payloadHex> [domainHex]`.
    Sign {
        name: String,
        payload_hex: String,
        domain_hex: Option<String>,
    },
}

struct KeyCtx {
    key_manager: std::sync::Arc<quil_keys::FileKeyManager>,
    alias_store: Option<Store>,
}

impl KeyCtx {
    fn load(global: GlobalArgs) -> anyhow::Result<Self> {
        let ctx = Context::load(global)?;
        let (node_config, dir) = ctx.load_node_config("default")?;
        let key_manager = ctx.key_manager(&node_config, &dir)?;
        let alias_store = alias_store::try_load_for_config_dir(&dir);
        Ok(Self {
            key_manager,
            alias_store,
        })
    }
}

pub fn run(global: GlobalArgs, cmd: &KeyCommand) -> anyhow::Result<()> {
    let mut kc = KeyCtx::load(global)?;
    match cmd {
        KeyCommand::List => list(&kc),
        KeyCommand::Create {
            name,
            key_type,
            purpose,
        } => create(&mut kc, name, key_type, purpose.as_deref()),
        KeyCommand::Delete { name } => delete(&kc, name),
        KeyCommand::Import {
            name,
            key_type,
            key_hex,
        } => import(&kc, name, key_type, key_hex),
        KeyCommand::Sign {
            name,
            payload_hex,
            domain_hex,
        } => sign(&kc, name, payload_hex, domain_hex.as_deref()),
    }
}

fn list(kc: &KeyCtx) -> anyhow::Result<()> {
    let keys = kc.key_manager.list_keys();
    if keys.is_empty() {
        println!("No keys found.");
        return Ok(());
    }
    println!("{:<18}  {:<18}  {:<66}  {}", "ID", "TYPE", "PUBLIC KEY", "ALIAS");
    for k in keys {
        let mut pub_hex = hex::encode(&k.public_key);
        if pub_hex.len() > 64 {
            pub_hex = format!("{}…", &pub_hex[..64]);
        }
        let alias_name = kc
            .alias_store
            .as_ref()
            .and_then(|s| s.find_by_address(&k.public_key))
            .map(|(n, _)| n)
            .unwrap_or_default();
        println!(
            "{:<18}  {:<18}  {:<66}  {}",
            k.id,
            key_type_name(k.key_type),
            pub_hex,
            alias_name
        );
    }
    Ok(())
}

fn create(kc: &mut KeyCtx, name: &str, key_type: &str, purpose: Option<&str>) -> anyhow::Result<()> {
    let kt = parse_key_type(key_type)?;
    let pubkey = kc
        .key_manager
        .create_signing_key(name, kt)
        .map_err(|e| anyhow::anyhow!("create key: {e}"))?;

    println!("Created key {name:?} ({})", key_type_name(kt));
    if !pubkey.is_empty() {
        println!("Public key: {}", hex::encode(&pubkey));
        if let (Some(store), Some(p)) = (kc.alias_store.as_mut(), purpose) {
            if !p.is_empty() {
                match store.put(name, &pubkey, p) {
                    Ok(()) => println!("Created alias {name:?} for this key"),
                    Err(e) => println!("Warning: failed to create alias: {e}"),
                }
            }
        }
    }
    if let Some(p) = purpose {
        if !p.is_empty() {
            println!("Purpose: {p}");
        }
    }
    Ok(())
}

fn delete(kc: &KeyCtx, name: &str) -> anyhow::Result<()> {
    if kc
        .key_manager
        .delete_key(name)
        .map_err(|e| anyhow::anyhow!("delete key: {e}"))?
    {
        println!("Deleted key {name:?}");
    } else {
        anyhow::bail!("key {name:?} not found");
    }
    Ok(())
}

fn import(kc: &KeyCtx, name: &str, key_type: &str, key_hex: &str) -> anyhow::Result<()> {
    let kt = parse_key_type(key_type)?;
    let data = hex::decode(key_hex.strip_prefix("0x").unwrap_or(key_hex))
        .map_err(|e| anyhow::anyhow!("decode key hex: {e}"))?;
    let pubkey = kc
        .key_manager
        .import_signing_key(name, kt, &data)
        .map_err(|e| anyhow::anyhow!("import key: {e}"))?;

    if !pubkey.is_empty() {
        println!(
            "Imported key {name:?} ({})\nPublic key: {}",
            key_type_name(kt),
            hex::encode(&pubkey)
        );
    } else {
        println!("Imported key {name:?} ({})", key_type_name(kt));
    }
    Ok(())
}

fn sign(kc: &KeyCtx, name: &str, payload_hex: &str, domain_hex: Option<&str>) -> anyhow::Result<()> {
    let signer: Box<dyn Signer> = kc
        .key_manager
        .get_signer_by_id(name)
        .map_err(|_| anyhow::anyhow!("key {name:?} not found"))?;
    let payload = hex::decode(payload_hex.strip_prefix("0x").unwrap_or(payload_hex))
        .map_err(|e| anyhow::anyhow!("decode payload hex: {e}"))?;
    let domain = match domain_hex {
        Some(d) if !d.is_empty() => {
            hex::decode(d.strip_prefix("0x").unwrap_or(d)).map_err(|e| anyhow::anyhow!("decode domain hex: {e}"))?
        }
        _ => Vec::new(),
    };
    let sig = signer
        .sign_with_domain(&payload, &domain)
        .map_err(|e| anyhow::anyhow!("sign payload: {e}"))?;
    println!("Signature: {}", hex::encode(&sig));
    Ok(())
}

/// Map a key-type string to its byte discriminant (`parseKeyType` +
/// Falcon-512).
fn parse_key_type(s: &str) -> anyhow::Result<u8> {
    match s.trim().to_lowercase().as_str() {
        "ed448" => Ok(0),
        "x448" => Ok(1),
        "decaf448" | "decaf" => Ok(4),
        "bls" | "bls48581" | "bls48" | "bls48581g1" | "bls-g1" | "g1" => Ok(2),
        "bls48581g2" | "bls-g2" | "g2" => Ok(3),
        "ed25519" => Ok(7),
        "secp256k1-sha256" | "secp256k1/sha256" | "k1-sha256" => Ok(5),
        "secp256k1-sha3" | "secp256k1/sha3" | "k1-sha3" => Ok(6),
        "falcon" | "falcon512" | "falcon-512" => Ok(8),
        other => anyhow::bail!(
            "unsupported key type {other:?} (supported: ed448, x448, decaf448, bls48581[g1|g2], falcon512)"
        ),
    }
}

/// Human-readable key-type label (`getKeyTypeName` + Falcon-512).
fn key_type_name(kt: u8) -> &'static str {
    match kt {
        0 => "Ed448",
        1 => "X448",
        2 => "BLS48-581 G1",
        3 => "BLS48-581 G2",
        4 => "Decaf448",
        5 => "secp256k1/SHA-256",
        6 => "secp256k1/SHA-3",
        7 => "Ed25519",
        8 => "Falcon-512",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_type_round_trip() {
        assert_eq!(parse_key_type("falcon512").unwrap(), 8);
        assert_eq!(parse_key_type("ed448").unwrap(), 0);
        assert_eq!(parse_key_type("decaf").unwrap(), 4);
        assert_eq!(key_type_name(8), "Falcon-512");
        assert!(parse_key_type("nope").is_err());
    }
}
