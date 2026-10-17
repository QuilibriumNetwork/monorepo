//! `qclient alias …` — address alias management (local YAML store).
//!
//! Port of `client/cmd/alias/alias.go`. The alias-file path comes from the
//! node config's `alias.aliasFile.path`, defaulting to `<config>/alias.yml`
//! (`config/alias.go` `WithDefaults`).

use clap::Subcommand;

use crate::alias_store::{self, parse_address_literal, Store};
use crate::context::{Context, GlobalArgs};

#[derive(Debug, Subcommand)]
pub enum AliasCommand {
    /// List all aliases.
    List,
    /// Add or update an alias: `<alias> <address> [type]`.
    Add {
        alias: String,
        address: String,
        #[arg(default_value = "")]
        r#type: String,
    },
    /// Remove an alias.
    #[command(alias = "rm", alias = "delete")]
    Remove { alias: String },
    /// Get address for an alias.
    Get { alias: String },
    /// Resolve an alias or hex address.
    Resolve { alias_or_address: String },
    /// Find alias for an address.
    Find { address: String },
}

fn load_store(global: GlobalArgs) -> anyhow::Result<Store> {
    let ctx = Context::load(global)?;
    let (_cfg, dir) = ctx.load_node_config("default")?;
    alias_store::load_for_config_dir(&dir)
}

pub fn run(global: GlobalArgs, cmd: &AliasCommand) -> anyhow::Result<()> {
    let mut store = load_store(global)?;
    match cmd {
        AliasCommand::List => list(&store),
        AliasCommand::Add {
            alias,
            address,
            r#type,
        } => add(&mut store, alias, address, r#type),
        AliasCommand::Remove { alias } => remove(&mut store, alias),
        AliasCommand::Get { alias } => get(&store, alias),
        AliasCommand::Resolve { alias_or_address } => resolve(&store, alias_or_address),
        AliasCommand::Find { address } => find(&store, address),
    }
}

fn list(store: &Store) -> anyhow::Result<()> {
    let names = store.list();
    if names.is_empty() {
        println!("No aliases found.");
        return Ok(());
    }
    println!("{:<20}  {:<66}  {}", "ALIAS", "ADDRESS", "TYPE");
    for name in names {
        if let Some((addr, typ)) = store.get(&name) {
            let mut addr_hex = hex::encode(&addr);
            if addr_hex.len() > 64 {
                addr_hex = format!("{}…", &addr_hex[..64]);
            }
            let typ = if typ.is_empty() { "-".to_string() } else { typ };
            println!("{name:<20}  {addr_hex:<66}  {typ}");
        }
    }
    Ok(())
}

fn add(store: &mut Store, name: &str, address: &str, type_str: &str) -> anyhow::Result<()> {
    let addr = parse_address_literal(address).map_err(|e| anyhow::anyhow!("invalid address hex: {e}"))?;
    store.put(name, &addr, type_str)?;
    println!("Added alias {name:?} for address {}", hex::encode(&addr));
    if !type_str.is_empty() {
        println!("Type: {type_str}");
    }
    Ok(())
}

fn remove(store: &mut Store, name: &str) -> anyhow::Result<()> {
    if store.delete(name)? {
        println!("Removed alias {name:?}");
    } else {
        println!("Alias {name:?} not found");
    }
    Ok(())
}

fn get(store: &Store, name: &str) -> anyhow::Result<()> {
    let (addr, typ) = store
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("alias {name:?} not found"))?;
    println!("Alias: {name}");
    println!("Address: {}", hex::encode(&addr));
    if !typ.is_empty() {
        println!("Type: {typ}");
    }
    Ok(())
}

fn resolve(store: &Store, input: &str) -> anyhow::Result<()> {
    let (addr, typ) = store
        .resolve(input)
        .ok_or_else(|| anyhow::anyhow!("could not resolve {input:?} as alias or address"))?;
    println!("Resolved to: {}", hex::encode(&addr));
    if !typ.is_empty() {
        println!("Type: {typ}");
    }
    if let Some((name, _)) = store.find_by_address(&addr) {
        if name != input {
            println!("This address has alias: {name}");
        }
    }
    Ok(())
}

fn find(store: &Store, address: &str) -> anyhow::Result<()> {
    let addr = parse_address_literal(address).map_err(|e| anyhow::anyhow!("invalid address hex: {e}"))?;
    match store.find_by_address(&addr) {
        None => println!("No alias found for address {}", hex::encode(&addr)),
        Some((name, typ)) => {
            println!("Alias: {name}");
            println!("Address: {}", hex::encode(&addr));
            if !typ.is_empty() {
                println!("Type: {typ}");
            }
        }
    }
    Ok(())
}
