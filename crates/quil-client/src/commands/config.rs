//! `qclient config …` — client config management (local file only).
//!
//! Port of `client/cmd/config/*.go`.

use clap::Subcommand;

use crate::config;

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Print the current configuration.
    Print,
    /// Create a default configuration file.
    CreateDefault,
    /// Set public RPC setting (`true`/`false`, toggles if omitted).
    PublicRpc { value: Option<String> },
    /// Set custom RPC URL (`domain:port`, or `clear`).
    SetCustomRpc { value: Option<String> },
    /// Set signature check setting (`enable`/`disable`, toggles if omitted).
    SignatureCheck { value: Option<String> },
}

pub fn run(cmd: &ConfigCommand) -> anyhow::Result<()> {
    match cmd {
        ConfigCommand::Print => print(),
        ConfigCommand::CreateDefault => config::create_default(),
        ConfigCommand::PublicRpc { value } => public_rpc(value.as_deref()),
        ConfigCommand::SetCustomRpc { value } => set_custom_rpc(value.as_deref()),
        ConfigCommand::SignatureCheck { value } => signature_check(value.as_deref()),
    }
}

fn print() -> anyhow::Result<()> {
    let cfg = config::load()?;
    println!("Data Directory: {}", cfg.data_dir);
    println!("Symlink Path: {}", cfg.symlink_path);
    println!("Signature Check: {}", cfg.signature_check);
    println!("Public RPC: {}", cfg.public_rpc);
    Ok(())
}

fn public_rpc(value: Option<&str>) -> anyhow::Result<()> {
    let mut cfg = config::load()?;
    match value.map(|v| v.to_lowercase()) {
        Some(v) if v == "true" => cfg.public_rpc = true,
        Some(v) if v == "false" => cfg.public_rpc = false,
        Some(v) => anyhow::bail!("Invalid value '{v}'. Please use 'true' or 'false'."),
        None => cfg.public_rpc = !cfg.public_rpc,
    }
    config::save(&cfg)?;
    let status = if cfg.public_rpc { "enabled" } else { "disabled" };
    println!(
        "Public RPC has been set to {status} and will be persisted across future commands unless reset."
    );
    Ok(())
}

fn set_custom_rpc(value: Option<&str>) -> anyhow::Result<()> {
    let mut cfg = config::load()?;
    let value = value.ok_or_else(|| {
        anyhow::anyhow!(
            "No argument provided. Please provide a valid URL or 'clear' to clear the custom RPC setting."
        )
    })?;

    if value == "clear" {
        cfg.custom_rpc = String::new();
    } else {
        validate_custom_rpc(value)?;
        cfg.custom_rpc = value.to_string();
    }

    config::save(&cfg)?;
    if value == "clear" {
        println!("Custom RPC URL cleared.");
    } else {
        println!("Custom RPC URL set to: {value}");
    }
    println!("Custom RPC setting will be persisted across future commands unless reset.");
    Ok(())
}

/// Port of `ValidateCustomRpc` — requires `domain:port` shape.
fn validate_custom_rpc(custom_rpc: &str) -> anyhow::Result<()> {
    if custom_rpc.is_empty() {
        anyhow::bail!("custom RPC URL cannot be empty");
    }
    if !custom_rpc.contains('.') || !custom_rpc.contains(':') {
        anyhow::bail!("custom RPC URL must be in format domain:port (e.g. example.com:8080)");
    }
    Ok(())
}

fn signature_check(value: Option<&str>) -> anyhow::Result<()> {
    let mut cfg = config::load()?;
    match value.map(|v| v.to_lowercase()) {
        Some(v) if v == "enable" => cfg.signature_check = true,
        Some(v) if v == "disable" => cfg.signature_check = false,
        Some(v) => anyhow::bail!("Invalid value '{v}'. Please use 'enable' or 'disable'."),
        None => cfg.signature_check = !cfg.signature_check,
    }
    config::save(&cfg)?;
    let status = if cfg.signature_check {
        "enabled"
    } else {
        "disabled"
    };
    println!(
        "Signature check has been set to {status} and will be persisted across future commands unless reset."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_custom_rpc_shape() {
        assert!(validate_custom_rpc("example.com:8080").is_ok());
        assert!(validate_custom_rpc("nodots").is_err());
        assert!(validate_custom_rpc("no.colon").is_err());
        assert!(validate_custom_rpc("").is_err());
    }
}
