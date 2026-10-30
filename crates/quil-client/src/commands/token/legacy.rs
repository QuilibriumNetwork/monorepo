//! `qclient token legacy` — legacy (pre-2.1) coins of one or more identities.
//!
//! Legacy coins are transparent: owner, amount and origin are public, so the
//! node is asked for them by owner. A shield accepts either owner form a key
//! has, `poseidon(Ed448 public key)` or `poseidon(peer-id multihash)`, so
//! both are listed. Only archives keep the owner index; the node asked
//! forwards there.
//!
//! A listing needs no private key and never reads keys.yml: an identity is
//! the Ed448 public key in a node config, an Ed448 public key or peer ID
//! given on the command line, or one owner address.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use clap::Args;
use quil_types::proto::global::ListLegacyCoinsRequest;
use quil_types::proto::node::node_service_client::NodeServiceClient;
use tonic::transport::Channel;

use super::{NodeSource, ReadNode, TokenCommonArgs, TokenCtx};
use crate::context::{Context, GlobalArgs};
use crate::rpc::ConnectOpts;

type Client = NodeServiceClient<Channel>;

// Identities and output of `token legacy`. Not a doc comment: the command's
// help is the `Legacy` variant's.
#[derive(Debug, Clone, Default, Args)]
pub struct LegacyArgs {
    /// Also list every node config one level below DIR (DIR/*/.config) and
    /// DIR/.config itself. Repeatable.
    #[arg(long = "configs-under", value_name = "DIR")]
    pub configs_under: Vec<PathBuf>,
    /// List an Ed448 public key (57 bytes of hex) under both owner forms,
    /// with no config or private key. Repeatable.
    #[arg(long = "ed448-pub", value_name = "HEX")]
    pub ed448_pub: Vec<String>,
    /// List a pre-2.1 Ed448 peer ID (base58, Qm…) under its peer-id owner
    /// form. The ID is a hash of the key, so the key form is not checked:
    /// give --ed448-pub for that. Repeatable.
    #[arg(long = "peer-id", value_name = "PEER_ID")]
    pub peer_id: Vec<String>,
    /// List one owner address (0x and 32 bytes of hex). Repeatable.
    #[arg(long, value_name = "ADDRESS")]
    pub owner: Vec<String>,
    /// Leave out the per-coin lines.
    #[arg(long)]
    pub summary: bool,
    /// Print one JSON object on stdout (schema in --help); progress and
    /// errors go to stderr.
    #[arg(long)]
    pub json: bool,
}

/// `token legacy --help`: what the output means, and the JSON schema.
pub(super) const AFTER_HELP: &str = "\
Output: one line per coin (address, QUIL, base units, owner form), then the
unshielded total; for several identities, a block of coins per identity, one
row per identity and a total. \"none\" means the node answered with no coins;
\"unavailable\" means it gave no answer, and the command then exits non-zero
after listing the other identities. Identities with the same owner addresses
are listed once. Shielding says from which GLOBAL frame shields of these
coins are admitted; shield-all submits batches of up to 96 coins from one
shard each.

--json prints one object:
  schema                 \"qclient.token.legacy/1\"
  network                network id the shield rule is for (0: mainnet)
  global_head_frame      GLOBAL head of the first node that answered, or null
  global_head_error      why it is null, or null
  shield                 null when the rule is unknown for the network; else
    shield_from_frame      first GLOBAL frame admitting `token shield`
    shield_all_from_frame  first GLOBAL frame admitting `token shield-all`
    active                 head >= shield_all_from_frame, null without a head
  identities[]           one per identity, in the order given
    label                node directory name, or the flag it came from
    config_dir           config directory read, or null
    peer_id_tail         last 6 characters of the Ed448 peer ID, or null
    owners[]             {form: key | peer_id | address, address: 0x…}
    status               listed | none | no_key | duplicate | unavailable
    error                why it is unavailable, else null
    duplicate_of         label of the identity listed instead, else null
    note                 what its listing does not cover, or null
    unshielded_count     integer
    unshielded_base_units, unshielded_quil   decimal strings
    shielded_count       integer
    coins[]              {address, base_units, quil, owner_form, shielded};
                         empty with --summary
    shield_batches       batches shield-all would submit, or null
    shield_batches_exact false when estimated without the node's shard list
    outside_live_shards  coins no live shard covers, left for a later run
    next_command         the command that shields them, or null
  total
    identities, listed, none, no_key, unavailable, duplicates   integers
    unshielded_count, shielded_count                            integers
    unshielded_base_units, unshielded_quil                      decimal strings
Amounts are strings: base units exceed what JSON numbers hold exactly.";

/// The form an owner address was derived in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OwnerForm {
    /// `poseidon(Ed448 public key)`.
    Key,
    /// `poseidon(peer-id multihash)`.
    PeerId,
    /// An address given as is (`--owner`).
    Address,
}

impl OwnerForm {
    fn text(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::PeerId => "peer-id",
            Self::Address => "given",
        }
    }
}

fn poseidon(bytes: &[u8]) -> anyhow::Result<[u8; 32]> {
    quil_crypto::poseidon::hash_bytes_to_32(bytes)
        .map_err(|e| anyhow::anyhow!("owner address: {e}"))
}

/// The two owner addresses of an Ed448 public key, derived as a shield's
/// admission derives them from its signing key.
pub(crate) fn key_owners(public: &[u8; 57]) -> anyhow::Result<Vec<(OwnerForm, [u8; 32])>> {
    Ok(vec![
        (OwnerForm::Key, poseidon(public)?),
        (
            OwnerForm::PeerId,
            poseidon(&quil_crypto::peer_id_multihash_from_ed448_pubkey(public))?,
        ),
    ])
}

/// The Ed448 public key of a config's `p2p.peerPrivKey`: the 57-byte seed
/// then the 57-byte public key, in hex. Only the public half is decoded.
/// `None` when the config has no Ed448 key (a node created after 2.1).
pub(crate) fn config_public_key(peer_priv_key: &str) -> Option<[u8; 57]> {
    if peer_priv_key.len() != 228 || !peer_priv_key.is_ascii() {
        return None;
    }
    hex::decode(&peer_priv_key[114..]).ok()?.try_into().ok()
}

/// `--ed448-pub`: 57 bytes of hex, `0x` optional. The value is never echoed:
/// a mistaken paste may be a private key.
pub(crate) fn parse_ed448_pub(value: &str) -> anyhow::Result<[u8; 57]> {
    let digits = value.trim();
    let digits = digits.strip_prefix("0x").unwrap_or(digits);
    let bytes = hex::decode(digits).map_err(|e| anyhow::anyhow!("--ed448-pub is not hex: {e}"))?;
    match bytes.len() {
        57 => Ok(bytes.try_into().expect("57 bytes")),
        114 => anyhow::bail!(
            "--ed448-pub takes the 57-byte public key, and this is 114 bytes, as long as a \
             config's peerPrivKey (private seed, then public key): pass only its last 114 hex \
             digits, and keep private keys off command lines"
        ),
        n => anyhow::bail!("--ed448-pub must be 57 bytes (an Ed448 public key), not {n}"),
    }
}

/// `--peer-id`: its multihash bytes and base58 form.
pub(crate) fn parse_peer_id(value: &str) -> anyhow::Result<(Vec<u8>, String)> {
    let peer = quil_p2p::PeerId::from_str(value.trim())
        .map_err(|e| anyhow::anyhow!("--peer-id {value}: not a peer ID: {e}"))?;
    Ok((peer.to_bytes(), peer.to_base58()))
}

/// `--owner`: `0x` and 32 bytes of hex.
pub(crate) fn parse_owner(value: &str) -> anyhow::Result<[u8; 32]> {
    let digits = value.trim();
    let digits = digits.strip_prefix("0x").unwrap_or(digits);
    hex::decode(digits)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("--owner {value}: must be 0x and 32 bytes of hex"))
}

/// The Ed448 public key an identity-multihash peer ID embeds. libp2p embeds
/// keys of at most 42 encoded bytes, so an Ed448 peer ID (a 57-byte key) is
/// a SHA2-256 hash and embeds none; this finds one only in a hand-made ID.
pub(crate) fn embedded_ed448_key(multihash: &[u8]) -> Option<[u8; 57]> {
    // Identity code, length, then PublicKey { Type: 4 (Ed448), Data: key }.
    match multihash {
        [0x00, length, 0x08, 0x04, 0x12, 57, key @ ..]
            if usize::from(*length) == multihash.len() - 2 =>
        {
            key.try_into().ok()
        }
        _ => None,
    }
}

/// The last six characters of a peer ID, the only part shown.
fn tail(peer_id: &str) -> String {
    let chars: Vec<char> = peer_id.chars().collect();
    chars[chars.len().saturating_sub(6)..].iter().collect()
}

/// The shown tail of an Ed448 public key's peer ID.
fn key_tail(public: &[u8; 57]) -> Option<String> {
    let multihash = quil_crypto::peer_id_multihash_from_ed448_pubkey(public);
    quil_p2p::PeerId::from_bytes(&multihash)
        .ok()
        .map(|peer| tail(&peer.to_base58()))
}

/// One identity to list.
#[derive(Clone, Debug)]
pub(crate) struct Identity {
    /// Its name in the output: the node directory, or the flag it came from.
    pub label: String,
    /// The config directory it was read from.
    pub config_dir: Option<PathBuf>,
    /// The `--config` value that names it again (`None`: the default).
    pub config_arg: Option<String>,
    /// The network of its config.
    pub network: Option<u8>,
    /// The last six characters of its Ed448 peer ID, when known.
    pub peer_tail: Option<String>,
    /// Its owner addresses (none: no Ed448 key), or why it cannot be listed.
    pub owners: Result<Vec<(OwnerForm, [u8; 32])>, String>,
    /// What its listing does not cover.
    pub note: Option<String>,
    /// The node asked for its coins.
    pub node: ReadNode,
}

impl Identity {
    /// An identity given by key, peer ID or owner, without a config.
    fn keyed(
        label: String,
        peer_tail: Option<String>,
        owners: Vec<(OwnerForm, [u8; 32])>,
        node: ReadNode,
    ) -> Self {
        Self {
            label,
            config_dir: None,
            config_arg: None,
            network: None,
            peer_tail,
            owners: Ok(owners),
            note: None,
            node,
        }
    }
}

/// The name a config directory goes by: its node directory's name for a
/// `.config` directory, else its own.
fn dir_label(dir: &Path) -> String {
    let real = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let named = if real.file_name().is_some_and(|name| name == ".config") {
        real.parent()
    } else {
        Some(real.as_path())
    };
    named
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| dir.display().to_string())
}

/// The node config directories under `root`: `root/.config`, then
/// `root/*/.config` in name order, each holding config.yml.
pub(crate) fn configs_under(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let entries = std::fs::read_dir(root)
        .map_err(|e| anyhow::anyhow!("--configs-under {}: {e}", root.display()))?;
    let mut found = Vec::new();
    if root.join(".config").join("config.yml").is_file() {
        found.push(root.join(".config"));
    }
    let mut below = Vec::new();
    for entry in entries {
        let candidate = entry?.path().join(".config");
        if candidate.join("config.yml").is_file() {
            below.push(candidate);
        }
    }
    below.sort();
    found.extend(below);
    anyhow::ensure!(
        !found.is_empty(),
        "--configs-under {}: no .config/config.yml in it or one level below",
        root.display()
    );
    Ok(found)
}

/// How the node to ask is chosen: `--read-rpc` for every identity, else
/// each config's own node, and for identities without a config the default
/// node config's node, else the node default.
struct NodeChoice<'a> {
    ctx: &'a Context,
    public_rpc: bool,
    read_rpc: Option<ConnectOpts>,
    /// The default node config, when it exists.
    default: Option<(quil_config::Config, PathBuf)>,
}

impl<'a> NodeChoice<'a> {
    fn new(ctx: &'a Context, common: &TokenCommonArgs) -> anyhow::Result<Self> {
        let read_rpc = common
            .read_rpc
            .as_deref()
            .map(|multiaddr| super::read_rpc_opts(multiaddr, common.insecure_read_rpc))
            .transpose()?;
        let default = crate::nodeconfig::default_node_config_dir(ctx.network_override())
            .ok()
            .and_then(|dir| {
                crate::nodeconfig::load_existing_node_config(&dir, false)
                    .ok()
                    .map(|config| (config, dir))
            });
        Ok(Self {
            ctx,
            public_rpc: common.public_rpc,
            read_rpc,
            default,
        })
    }

    /// The default node config's listener, suggested when a node is down.
    fn default_listener(&self) -> Option<&str> {
        self.default
            .as_ref()
            .map(|(config, _)| config.effective_listen_grpc_multiaddr())
    }

    fn for_config(&self, config: &quil_config::Config, dir: &Path) -> ReadNode {
        match &self.read_rpc {
            Some(opts) => ReadNode {
                opts: opts.clone(),
                source: NodeSource::ReadRpc,
            },
            None => ReadNode {
                opts: self.ctx.connect_opts(config, self.public_rpc),
                source: NodeSource::Config(dir.to_path_buf()),
            },
        }
    }

    fn for_keys(&self) -> ReadNode {
        if let Some(opts) = &self.read_rpc {
            return ReadNode {
                opts: opts.clone(),
                source: NodeSource::ReadRpc,
            };
        }
        if let Some((config, dir)) = &self.default {
            return self.for_config(config, dir);
        }
        ReadNode {
            opts: ConnectOpts {
                public_rpc: self.public_rpc || self.ctx.client_config.public_rpc,
                custom_rpc: self.ctx.client_config.custom_rpc.clone(),
                listen_grpc_multiaddr: String::new(),
            },
            source: NodeSource::Default,
        }
    }
}

/// The identity of the node config in `dir`, from its Ed448 public key.
fn config_identity(
    config: &quil_config::Config,
    dir: &Path,
    config_arg: Option<String>,
    node: ReadNode,
) -> Identity {
    let public = config_public_key(&config.p2p.peer_priv_key);
    Identity {
        label: dir_label(dir),
        config_dir: Some(dir.to_path_buf()),
        config_arg,
        network: Some(config.p2p.network),
        peer_tail: public.as_ref().and_then(key_tail),
        owners: match public {
            Some(public) => key_owners(&public).map_err(|e| format!("{e:#}")),
            None => Ok(Vec::new()),
        },
        note: None,
        node,
    }
}

/// The identities of `--ed448-pub`, `--peer-id` and `--owner`, in that
/// order, each read from `node()`. A malformed value fails at once.
fn keyed_identities(
    args: &LegacyArgs,
    node: impl Fn() -> ReadNode,
) -> anyhow::Result<Vec<Identity>> {
    let numbered = |flag: &str, index: usize, count: usize| {
        if count > 1 {
            format!("{flag} #{}", index + 1)
        } else {
            flag.to_string()
        }
    };
    let mut identities = Vec::new();
    for (index, value) in args.ed448_pub.iter().enumerate() {
        let public = parse_ed448_pub(value)?;
        identities.push(Identity::keyed(
            numbered("ed448-pub", index, args.ed448_pub.len()),
            key_tail(&public),
            key_owners(&public)?,
            node(),
        ));
    }
    for (index, value) in args.peer_id.iter().enumerate() {
        let (multihash, base58) = parse_peer_id(value)?;
        let label = numbered("peer-id", index, args.peer_id.len());
        let mut identity = match embedded_ed448_key(&multihash) {
            Some(public) => {
                Identity::keyed(label, Some(tail(&base58)), key_owners(&public)?, node())
            }
            None => Identity::keyed(
                label,
                Some(tail(&base58)),
                vec![(OwnerForm::PeerId, poseidon(&multihash)?)],
                node(),
            ),
        };
        if identity
            .owners
            .as_ref()
            .is_ok_and(|owners| owners.len() == 1)
        {
            identity.note = Some(
                "only the peer-id owner form was checked: the peer ID is a hash of the key, so \
                 give --ed448-pub to check the key form too"
                    .to_string(),
            );
        }
        identities.push(identity);
    }
    for value in &args.owner {
        let owner = parse_owner(value)?;
        identities.push(Identity::keyed(
            format!("owner 0x{}…", hex::encode(&owner[..4])),
            None,
            vec![(OwnerForm::Address, owner)],
            node(),
        ));
    }
    Ok(identities)
}

/// The identities the arguments name, in order: configs, configs under
/// directories, then keys, peer IDs and owners; with none, the default node
/// config. A config that cannot be read becomes an unavailable identity, so
/// the others are still listed.
fn identities(
    choice: &NodeChoice,
    configs: &[String],
    args: &LegacyArgs,
) -> anyhow::Result<Vec<Identity>> {
    let keyed = keyed_identities(args, || choice.for_keys())?;
    let mut named: Vec<Option<String>> = configs
        .iter()
        .map(|config| (!config.is_empty() && config != "default").then(|| config.clone()))
        .collect();
    for root in &args.configs_under {
        named.extend(
            configs_under(root)?
                .into_iter()
                .map(|dir| Some(dir.display().to_string())),
        );
    }
    if named.is_empty() && keyed.is_empty() {
        named.push(None);
    }
    let mut identities = Vec::with_capacity(named.len() + keyed.len());
    for config_arg in named {
        let loaded = match &config_arg {
            Some(dir) => crate::nodeconfig::load_existing_node_config(Path::new(dir), true)
                .map(|config| (config, PathBuf::from(dir))),
            None => crate::nodeconfig::load_node_config("", choice.ctx.network_override()),
        };
        identities.push(match loaded {
            Ok((config, dir)) => {
                let node = choice.for_config(&config, &dir);
                config_identity(&config, &dir, config_arg, node)
            }
            Err(error) => Identity {
                owners: Err(format!("{error:#}")),
                ..Identity::keyed(
                    config_arg.unwrap_or_else(|| "default".to_string()),
                    None,
                    Vec::new(),
                    choice.for_keys(),
                )
            },
        });
    }
    identities.extend(keyed);
    Ok(identities)
}

/// One legacy coin of an identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Coin {
    pub address: [u8; 32],
    pub amount: u128,
    /// GLOBAL has recorded it consumed by a shield.
    pub shielded: bool,
    /// The owner form it was listed under.
    pub form: OwnerForm,
}

/// The unshielded total and the counts of some coins.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Tally {
    pub units: u128,
    pub unshielded: usize,
    pub shielded: usize,
}

impl Tally {
    pub(crate) fn of(coins: &[Coin]) -> anyhow::Result<Self> {
        let mut tally = Self::default();
        for coin in coins {
            if coin.shielded {
                tally.shielded += 1;
            } else {
                tally.unshielded += 1;
                tally.units = tally
                    .units
                    .checked_add(coin.amount)
                    .ok_or_else(|| anyhow::anyhow!("legacy total overflows u128"))?;
            }
        }
        Ok(tally)
    }

    fn add(&mut self, other: Self) -> anyhow::Result<()> {
        self.units = self
            .units
            .checked_add(other.units)
            .ok_or_else(|| anyhow::anyhow!("legacy total overflows u128"))?;
        self.unshielded += other.unshielded;
        self.shielded += other.shielded;
        Ok(())
    }
}

/// Every legacy coin of `owner`, ascending by address, as
/// `(address, amount, shielded)`. `progress` gets the running count after
/// each page that more pages follow.
async fn list_owner(
    client: &Client,
    application: &[u8; 32],
    owner: &[u8; 32],
    pages: &mut usize,
    mut progress: impl FnMut(usize),
) -> anyhow::Result<Vec<([u8; 32], u128, bool)>> {
    let mut coins = Vec::new();
    let mut after: Vec<u8> = Vec::new();
    loop {
        let page = match client
            .clone()
            .list_legacy_coins(ListLegacyCoinsRequest {
                domain: application.to_vec(),
                owner: owner.to_vec(),
                after: after.clone(),
            })
            .await
        {
            Ok(page) => page.into_inner(),
            Err(status) if status.code() == tonic::Code::Unimplemented => {
                anyhow::bail!("the node asked cannot list legacy coins; upgrade it")
            }
            Err(status) => anyhow::bail!("legacy coins: {}", status.message()),
        };
        *pages += 1;
        for coin in &page.coins {
            let amount = u128::from_le_bytes(
                coin.amount
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("malformed legacy coin amount"))?,
            );
            let address: [u8; 32] = coin
                .address
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("malformed legacy coin address"))?;
            anyhow::ensure!(coin.address > after, "legacy coins out of order");
            coins.push((address, amount, coin.shielded));
            after = coin.address.clone();
        }
        if !page.has_more {
            break;
        }
        anyhow::ensure!(
            !page.coins.is_empty(),
            "legacy coin listing did not advance"
        );
        progress(coins.len());
    }
    Ok(coins)
}

/// Every coin of `owners`. A long listing shows its progress on one line
/// of a terminal's stderr, rewritten after each page and cleared once the
/// listing ends; piped or redirected output gets none.
async fn list_owners(
    client: &Client,
    application: &[u8; 32],
    owners: &[(OwnerForm, [u8; 32])],
    label: &str,
    pages: &mut usize,
) -> anyhow::Result<Vec<Coin>> {
    use std::io::{IsTerminal, Write};
    let terminal = std::io::stderr().is_terminal();
    let mut coins = Vec::new();
    for (form, owner) in owners {
        let mut shown = false;
        let listed = list_owner(client, application, owner, pages, |count| {
            if terminal {
                eprint!(
                    "\r{label}: {count} legacy coins listed under the {} owner, more follow",
                    form.text()
                );
                let _ = std::io::stderr().flush();
                shown = true;
            }
        })
        .await;
        if shown {
            eprint!("\r\x1b[K");
            let _ = std::io::stderr().flush();
        }
        let listed = listed?;
        coins.extend(listed.into_iter().map(|(address, amount, shielded)| Coin {
            address,
            amount,
            shielded,
            form: *form,
        }));
    }
    Ok(coins)
}

/// Every legacy coin of this node's identity, both owner forms.
#[cfg(feature = "confidential-tokens")]
pub(crate) async fn list(
    tc: &TokenCtx,
    client: &Client,
    application: &[u8; 32],
) -> anyhow::Result<Vec<Coin>> {
    let public = config_public_key(&tc.node_config.p2p.peer_priv_key).ok_or_else(|| {
        anyhow::anyhow!("this node has no Ed448 identity, so it holds no legacy coins")
    })?;
    list_owners(
        client,
        application,
        &key_owners(&public)?,
        "this identity",
        &mut 0,
    )
    .await
}

/// This identity's legacy coins tallied for `token balance`, as
/// `(unshielded total, unshielded, shielded)`, or `None` when the node has
/// no Ed448 identity and so holds none. `pages` counts the pages read.
#[cfg(feature = "confidential-tokens")]
pub(crate) async fn unshielded(
    tc: &TokenCtx,
    client: &Client,
    application: &[u8; 32],
    pages: &mut usize,
) -> anyhow::Result<Option<(u128, usize, usize)>> {
    let Some(public) = config_public_key(&tc.node_config.p2p.peer_priv_key) else {
        return Ok(None);
    };
    let owners = key_owners(&public)?;
    let tally =
        Tally::of(&list_owners(client, application, &owners, "this identity", pages).await?)?;
    Ok(Some((tally.units, tally.unshielded, tally.shielded)))
}

/// What to ask for an identity, given the owners listed for earlier ones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    /// These owners, and a note when some others were listed before.
    Ask(Vec<(OwnerForm, [u8; 32])>, Option<String>),
    /// Every owner was listed for this earlier identity.
    Duplicate(String),
    /// No Ed448 key: no legacy coins.
    NoKey,
    /// The identity could not be read.
    Failed(String),
}

/// Owner addresses already listed, so an identity read twice (two
/// directories with one key) counts once. Only a successful listing
/// records its owners: a key whose first node did not answer is asked again.
#[derive(Debug, Default)]
pub(crate) struct Dedup {
    listed: HashMap<[u8; 32], String>,
}

impl Dedup {
    pub(crate) fn plan(&self, identity: &Identity) -> Plan {
        let owners = match &identity.owners {
            Err(error) => return Plan::Failed(error.clone()),
            Ok(owners) if owners.is_empty() => return Plan::NoKey,
            Ok(owners) => owners,
        };
        let (fresh, repeated): (Vec<_>, Vec<_>) = owners
            .iter()
            .partition(|(_, owner)| !self.listed.contains_key(owner));
        if fresh.is_empty() {
            return Plan::Duplicate(self.listed[&owners[0].1].clone());
        }
        let note = repeated.first().map(|(form, owner)| {
            format!(
                "its {} owner was listed for {}, and is counted there",
                form.text(),
                self.listed[owner]
            )
        });
        Plan::Ask(fresh, note)
    }

    pub(crate) fn record(&mut self, owners: &[(OwnerForm, [u8; 32])], label: &str) {
        for (_, owner) in owners {
            self.listed
                .entry(*owner)
                .or_insert_with(|| label.to_string());
        }
    }
}

/// What the listing of one identity found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The node answered with these coins; none is an answer too.
    Listed(Vec<Coin>),
    /// No Ed448 key, so no legacy coins.
    NoKey,
    /// Listed as this earlier identity.
    Duplicate(String),
    /// No answer, or the identity could not be read.
    Unavailable(String),
}

impl Outcome {
    fn status(&self) -> &'static str {
        match self {
            Self::Listed(coins) if coins.is_empty() => "none",
            Self::Listed(_) => "listed",
            Self::NoKey => "no_key",
            Self::Duplicate(_) => "duplicate",
            Self::Unavailable(_) => "unavailable",
        }
    }
}

/// When a network admits shields of its legacy coins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ShieldRule {
    /// First GLOBAL frame admitting a single-coin shield (`token shield`).
    pub shield_from: u64,
    /// First GLOBAL frame admitting `token shield-all`'s batches.
    pub shield_all_from: u64,
}

/// This build's batch shields: legacy coins per batch and mainnet's batch
/// shield frame. `None` without confidential tokens, whose build has no
/// shield commands.
#[cfg(feature = "confidential-tokens")]
const BATCH_SHIELDS: Option<(usize, u64)> = Some((
    quil_lattice_ct::confidential::shield::MAX_SHIELD_SOURCES,
    quil_execution::token_intrinsic::global_commit::MAINNET_BATCH_SHIELD_FRAME,
));
#[cfg(not(feature = "confidential-tokens"))]
const BATCH_SHIELDS: Option<(usize, u64)> = None;

/// The shield rule of `network`, known only on mainnet, where both frames
/// are fixed; elsewhere they are node settings qclient cannot see. Every
/// mainnet legacy coin came from the migration, which wrote its owner in
/// migrated form, and admission matches that form only from
/// `MAINNET_MIGRATED_OWNER_FRAME` (`shield::check_sources`): before it,
/// every such shield fails with "source owner mismatch". Batches also need
/// the batch shield frame.
pub(crate) fn shield_rule(network: u8) -> Option<ShieldRule> {
    let (_, batch_frame) = BATCH_SHIELDS?;
    let migrated = quil_execution::token_intrinsic::legacy_migration::MAINNET_MIGRATED_OWNER_FRAME;
    (network == 0).then_some(ShieldRule {
        shield_from: migrated,
        shield_all_from: migrated.max(batch_frame),
    })
}

/// The GLOBAL head the node reports.
async fn global_head(client: &Client) -> Result<u64, String> {
    match client
        .clone()
        .get_node_info(quil_types::proto::node::GetNodeInfoRequest::default())
        .await
    {
        Ok(info) => match info.into_inner().last_global_head_frame {
            0 => Err("the node reports no GLOBAL head yet".into()),
            frame => Ok(frame),
        },
        Err(status) => Err(format!("node info: {}", status.message())),
    }
}

/// Refuse to prove shields that admission would refuse at the node's GLOBAL
/// head: the proving is wasted, and a refused batch also keeps its coins out
/// of the next run for an hour. Without a known rule or head, go ahead.
#[cfg(feature = "native-proof")]
pub(crate) async fn ensure_shields_active(
    client: &Client,
    network: u8,
    batch: bool,
) -> anyhow::Result<()> {
    let Some(rule) = shield_rule(network) else {
        return Ok(());
    };
    let Ok(head) = global_head(client).await else {
        return Ok(());
    };
    let from = if batch {
        rule.shield_all_from
    } else {
        rule.shield_from
    };
    anyhow::ensure!(
        head >= from,
        "shields of legacy coins are admitted from GLOBAL frame {}, and the node's GLOBAL head \
         is {} ({} frames before it): admission would refuse them (\"source owner mismatch\"); \
         run this again once the head reaches that frame (`qclient token legacy` shows it)",
        grouped(from),
        grouped(head),
        grouped(from - head)
    );
    Ok(())
}

/// The bit paths of `application`'s live shards (any active prover).
pub(crate) async fn live_shard_paths(
    client: &Client,
    application: &[u8; 32],
) -> anyhow::Result<Vec<Vec<bool>>> {
    let shards = client
        .clone()
        .get_shard_info(quil_types::proto::node::GetShardInfoRequest { include_all: true })
        .await
        .map_err(|e| anyhow::anyhow!("shard list: {}", e.message()))?
        .into_inner()
        .shards;
    Ok(shards
        .iter()
        .filter(|shard| shard.filter.starts_with(application) && shard.active_provers > 0)
        .filter_map(|shard| {
            quil_forest::decode_shard_filter_or_root(&shard.filter, 32).map(|(_, bits)| bits)
        })
        .collect())
}

/// The deepest of `shards` (bit paths) covering `address`: the shard whose
/// members verify a shield of it.
pub(crate) fn deepest_shard<'a>(
    shards: &'a [Vec<bool>],
    address: &[u8; 32],
) -> Option<&'a Vec<bool>> {
    let covers = |path: &[bool]| {
        path.iter()
            .enumerate()
            .all(|(i, bit)| (address[i / 8] & (0x80 >> (i % 8)) != 0) == *bit)
    };
    shards
        .iter()
        .filter(|path| covers(path))
        .max_by_key(|path| path.len())
}

/// The batches `token shield-all` cuts `addresses` into (up to `max` from
/// one shard each, as `shield_batches` does), and how many addresses no
/// shard covers.
pub(crate) fn count_batches(
    addresses: &[[u8; 32]],
    shards: &[Vec<bool>],
    max: usize,
) -> (usize, usize) {
    let mut groups: BTreeMap<&Vec<bool>, usize> = BTreeMap::new();
    let mut outside = 0;
    for address in addresses.iter().collect::<BTreeSet<_>>() {
        match deepest_shard(shards, address) {
            Some(path) => *groups.entry(path).or_default() += 1,
            None => outside += 1,
        }
    }
    let batches = groups
        .values()
        .map(|coins| coins.div_ceil(max.max(1)))
        .sum();
    (batches, outside)
}

/// How `token shield-all` would shield one identity's unshielded coins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ShieldPlan {
    pub batches: usize,
    /// False when counted without the shard list: batches never span
    /// shards, so there may be more.
    pub exact: bool,
    /// Coins no live shard covers, left for a later run.
    pub outside: usize,
}

/// The shield plan for `coins`, or `None` with nothing to shield or no
/// shield commands in this build.
pub(crate) fn shield_plan(coins: &[Coin], shards: Option<&[Vec<bool>]>) -> Option<ShieldPlan> {
    let (max, _) = BATCH_SHIELDS?;
    let unshielded: Vec<[u8; 32]> = coins
        .iter()
        .filter(|coin| !coin.shielded)
        .map(|coin| coin.address)
        .collect();
    if unshielded.is_empty() {
        return None;
    }
    Some(match shards {
        Some(shards) => {
            let (batches, outside) = count_batches(&unshielded, shards, max);
            ShieldPlan {
                batches,
                exact: true,
                outside,
            }
        }
        None => ShieldPlan {
            batches: unshielded.len().div_ceil(max),
            exact: false,
            outside: 0,
        },
    })
}

/// One identity's line of the report.
#[derive(Clone, Debug)]
pub(crate) struct Row {
    pub identity: Identity,
    pub outcome: Outcome,
    pub note: Option<String>,
    pub plan: Option<ShieldPlan>,
}

/// Everything `token legacy` found.
#[derive(Clone, Debug)]
pub(crate) struct Report {
    pub network: u8,
    pub head: Result<u64, String>,
    pub rule: Option<ShieldRule>,
    pub rows: Vec<Row>,
    /// `--read-rpc` and `--public-rpc` as given, repeated in next commands.
    pub read_args: String,
}

/// Counts over every row; duplicates add nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Totals {
    pub tally: Tally,
    pub listed: usize,
    pub none: usize,
    pub no_key: usize,
    pub unavailable: usize,
    pub duplicates: usize,
}

impl Report {
    pub(crate) fn totals(&self) -> anyhow::Result<Totals> {
        let mut totals = Totals::default();
        for row in &self.rows {
            match &row.outcome {
                Outcome::Listed(coins) if coins.is_empty() => totals.none += 1,
                Outcome::Listed(coins) => {
                    totals.listed += 1;
                    totals.tally.add(Tally::of(coins)?)?;
                }
                Outcome::NoKey => totals.no_key += 1,
                Outcome::Duplicate(_) => totals.duplicates += 1,
                Outcome::Unavailable(_) => totals.unavailable += 1,
            }
        }
        Ok(totals)
    }

    /// Whether shield-all is admitted now: `None` without a rule or head.
    fn active(&self) -> Option<bool> {
        let head = *self.head.as_ref().ok()?;
        Some(head >= self.rule?.shield_all_from)
    }

    /// The command that shields `row`'s coins, for an identity read from a
    /// config, whose Ed448 private key signs the shields.
    fn next_command(&self, row: &Row) -> Option<String> {
        if row.plan.is_none() || row.identity.config_dir.is_none() {
            return None;
        }
        let mut command = "qclient token shield-all".to_string();
        if let Some(config) = &row.identity.config_arg {
            command.push_str(" --config ");
            command.push_str(&shell_word(config));
        }
        command.push_str(&self.read_args);
        Some(command)
    }

    /// The shielding line, printed when any coin is left to shield.
    fn shielding_line(&self) -> String {
        let Some(rule) = self.rule else {
            return format!(
                "Shielding: the admission frames of network {} are node settings this client \
                 cannot see",
                self.network
            );
        };
        let from = if rule.shield_from == rule.shield_all_from {
            format!("from GLOBAL frame {}", grouped(rule.shield_all_from))
        } else {
            format!(
                "from GLOBAL frame {} (`token shield`) and {} (`token shield-all`)",
                grouped(rule.shield_from),
                grouped(rule.shield_all_from)
            )
        };
        match &self.head {
            Ok(head) if *head >= rule.shield_all_from => format!(
                "Shielding: active: shields of these coins are admitted {from}; the GLOBAL head \
                 is {}",
                grouped(*head)
            ),
            Ok(head) => format!(
                "Shielding: not yet: shields of these coins are admitted {from}; the GLOBAL \
                 head is {} ({} frames to go)",
                grouped(*head),
                grouped(rule.shield_all_from - head)
            ),
            Err(error) => {
                format!("Shielding: admitted {from}; the GLOBAL head is unknown ({error})")
            }
        }
    }

    fn plan_line(&self, plan: &ShieldPlan, unshielded: usize) -> String {
        let mut line = format!(
            "{}{} shield-all batch{} for {unshielded} unshielded coin{}, up to {} from one \
             shard each",
            if plan.exact { "" } else { "at least " },
            plan.batches,
            if plan.batches == 1 { "" } else { "es" },
            if unshielded == 1 { "" } else { "s" },
            BATCH_SHIELDS.map_or(0, |(max, _)| max),
        );
        if !plan.exact {
            line.push_str(" (the node's shard list was unavailable to count them exactly)");
        }
        if plan.outside > 0 {
            line.push_str(&format!(
                "; {} lie in no live shard and are left for a later run",
                plan.outside
            ));
        }
        line
    }

    fn next_line(&self, row: &Row) -> Option<String> {
        let command = self.next_command(row)?;
        Some(match (self.active(), self.rule) {
            (Some(false), Some(rule)) => format!(
                "Next, from GLOBAL frame {}: {command}",
                grouped(rule.shield_all_from)
            ),
            _ => format!("Next: {command}"),
        })
    }

    /// The text output.
    pub(crate) fn text(&self, summary: bool) -> anyhow::Result<String> {
        let mut out = String::new();
        let single = self.rows.len() == 1;
        for row in &self.rows {
            let Outcome::Listed(coins) = &row.outcome else {
                continue;
            };
            if summary || coins.is_empty() {
                continue;
            }
            if !single {
                writeln!(out, "{}{}:", row.identity.label, peer_suffix(row))?;
            }
            for coin in coins {
                writeln!(out, "{}", coin_line(coin))?;
            }
        }
        if single {
            let row = &self.rows[0];
            writeln!(out, "{}", single_line(row)?)?;
            if let Some(note) = &row.note {
                writeln!(out, "Note: {note}")?;
            }
        } else {
            self.table(&mut out)?;
        }
        if self.totals()?.tally.unshielded > 0 && BATCH_SHIELDS.is_some() {
            writeln!(out, "{}", self.shielding_line())?;
            for row in &self.rows {
                let (Some(plan), Outcome::Listed(coins)) = (&row.plan, &row.outcome) else {
                    continue;
                };
                let line = self.plan_line(plan, Tally::of(coins)?.unshielded);
                if single {
                    writeln!(out, "Shield plan: {line}.")?;
                } else {
                    writeln!(out, "{}: {line}.", row.identity.label)?;
                }
                match self.next_line(row) {
                    Some(next) => writeln!(out, "{next}")?,
                    None => writeln!(
                        out,
                        "To shield them, run `qclient token shield-all` with the node config \
                         holding this key: its Ed448 private key signs the shields"
                    )?,
                }
            }
        }
        Ok(out)
    }

    fn table(&self, out: &mut String) -> anyhow::Result<()> {
        let label_width = self
            .rows
            .iter()
            .map(|row| row.identity.label.chars().count())
            .chain([8])
            .max()
            .unwrap_or(8);
        let totals = self.totals()?;
        let mut quil_width = quil(totals.tally.units).len();
        for row in &self.rows {
            if let Outcome::Listed(coins) = &row.outcome {
                quil_width = quil_width.max(quil(Tally::of(coins)?.units).len());
            }
        }
        writeln!(
            out,
            "{:<label_width$}  {:<7}  {:>10}  {:>quil_width$}  {:>8}",
            "Identity", "Peer ID", "Unshielded", "QUIL", "Shielded"
        )?;
        for row in &self.rows {
            let label = &row.identity.label;
            let peer = row
                .identity
                .peer_tail
                .as_ref()
                .map_or("-".to_string(), |tail| format!("…{tail}"));
            let state = match &row.outcome {
                Outcome::Listed(coins) if coins.is_empty() => {
                    "none: the listing has no coin for it".to_string()
                }
                Outcome::Listed(coins) => {
                    let tally = Tally::of(coins)?;
                    writeln!(
                        out,
                        "{label:<label_width$}  {peer:<7}  {:>10}  {:>quil_width$}  {:>8}",
                        tally.unshielded,
                        quil(tally.units),
                        tally.shielded
                    )?;
                    continue;
                }
                Outcome::NoKey => "none: config.yml has no Ed448 key".to_string(),
                Outcome::Duplicate(of) => format!("same owners as {of}: counted once"),
                Outcome::Unavailable(error) => format!("unavailable: {error}"),
            };
            writeln!(out, "{label:<label_width$}  {peer:<7}  {state}")?;
        }
        writeln!(
            out,
            "{:<label_width$}  {:<7}  {:>10}  {:>quil_width$}  {:>8}",
            "Total",
            "",
            totals.tally.unshielded,
            quil(totals.tally.units),
            totals.tally.shielded
        )?;
        let mut counted = format!(
            "{} of {} identities listed",
            totals.listed + totals.none + totals.no_key,
            self.rows.len()
        );
        if totals.unavailable > 0 {
            counted.push_str(&format!(
                "; {} unavailable and left out of the total",
                totals.unavailable
            ));
        }
        if totals.duplicates > 0 {
            counted.push_str(&format!(
                "; {} with owners listed for another, counted once",
                totals.duplicates
            ));
        }
        writeln!(out, "{counted}.")?;
        for row in &self.rows {
            if let Some(note) = &row.note {
                writeln!(out, "{}: {note}", row.identity.label)?;
            }
        }
        Ok(())
    }

    /// The `--json` output (schema [`JSON_SCHEMA`], documented in --help).
    pub(crate) fn json(&self, summary: bool) -> anyhow::Result<serde_json::Value> {
        let totals = self.totals()?;
        let mut identities = Vec::new();
        for row in &self.rows {
            let coins: &[Coin] = match &row.outcome {
                Outcome::Listed(coins) => coins,
                _ => &[],
            };
            let tally = Tally::of(coins)?;
            let owners = match &row.identity.owners {
                Ok(owners) => owners
                    .iter()
                    .map(|(form, address)| JsonOwner {
                        form: *form,
                        address: format!("0x{}", hex::encode(address)),
                    })
                    .collect(),
                Err(_) => Vec::new(),
            };
            identities.push(JsonIdentity {
                label: row.identity.label.clone(),
                config_dir: row
                    .identity
                    .config_dir
                    .as_ref()
                    .map(|dir| dir.display().to_string()),
                peer_id_tail: row.identity.peer_tail.clone(),
                owners,
                status: row.outcome.status(),
                error: match &row.outcome {
                    Outcome::Unavailable(error) => Some(error.clone()),
                    _ => None,
                },
                duplicate_of: match &row.outcome {
                    Outcome::Duplicate(of) => Some(of.clone()),
                    _ => None,
                },
                note: row.note.clone(),
                unshielded_count: tally.unshielded,
                unshielded_base_units: tally.units.to_string(),
                unshielded_quil: quil(tally.units),
                shielded_count: tally.shielded,
                coins: if summary {
                    Vec::new()
                } else {
                    coins
                        .iter()
                        .map(|coin| JsonCoin {
                            address: format!("0x{}", hex::encode(coin.address)),
                            base_units: coin.amount.to_string(),
                            quil: quil(coin.amount),
                            owner_form: coin.form,
                            shielded: coin.shielded,
                        })
                        .collect()
                },
                shield_batches: row.plan.map(|plan| plan.batches),
                shield_batches_exact: row.plan.is_some_and(|plan| plan.exact),
                outside_live_shards: row.plan.map_or(0, |plan| plan.outside),
                next_command: self.next_command(row),
            });
        }
        let report = JsonReport {
            schema: JSON_SCHEMA,
            network: self.network,
            global_head_frame: self.head.as_ref().ok().copied(),
            global_head_error: self.head.as_ref().err().cloned(),
            shield: self.rule.map(|rule| JsonShield {
                shield_from_frame: rule.shield_from,
                shield_all_from_frame: rule.shield_all_from,
                active: self.active(),
            }),
            identities,
            total: JsonTotal {
                identities: self.rows.len(),
                listed: totals.listed,
                none: totals.none,
                no_key: totals.no_key,
                unavailable: totals.unavailable,
                duplicates: totals.duplicates,
                unshielded_count: totals.tally.unshielded,
                unshielded_base_units: totals.tally.units.to_string(),
                unshielded_quil: quil(totals.tally.units),
                shielded_count: totals.tally.shielded,
            },
        };
        Ok(serde_json::to_value(report)?)
    }

    /// The command's result: an error naming every unavailable identity.
    fn result(&self) -> anyhow::Result<()> {
        let unavailable: Vec<&str> = self
            .rows
            .iter()
            .filter(|row| matches!(row.outcome, Outcome::Unavailable(_)))
            .map(|row| row.identity.label.as_str())
            .collect();
        anyhow::ensure!(
            unavailable.is_empty(),
            "legacy coins unavailable for {} of {} identities: {}",
            unavailable.len(),
            self.rows.len(),
            unavailable.join(", ")
        );
        Ok(())
    }
}

/// `--json`'s schema name; a change that breaks a reader bumps it.
pub(crate) const JSON_SCHEMA: &str = "qclient.token.legacy/1";

#[derive(serde::Serialize)]
struct JsonReport {
    schema: &'static str,
    network: u8,
    global_head_frame: Option<u64>,
    global_head_error: Option<String>,
    shield: Option<JsonShield>,
    identities: Vec<JsonIdentity>,
    total: JsonTotal,
}

#[derive(serde::Serialize)]
struct JsonShield {
    shield_from_frame: u64,
    shield_all_from_frame: u64,
    active: Option<bool>,
}

#[derive(serde::Serialize)]
struct JsonIdentity {
    label: String,
    config_dir: Option<String>,
    peer_id_tail: Option<String>,
    owners: Vec<JsonOwner>,
    status: &'static str,
    error: Option<String>,
    duplicate_of: Option<String>,
    note: Option<String>,
    unshielded_count: usize,
    unshielded_base_units: String,
    unshielded_quil: String,
    shielded_count: usize,
    coins: Vec<JsonCoin>,
    shield_batches: Option<usize>,
    shield_batches_exact: bool,
    outside_live_shards: usize,
    next_command: Option<String>,
}

#[derive(serde::Serialize)]
struct JsonOwner {
    form: OwnerForm,
    address: String,
}

#[derive(serde::Serialize)]
struct JsonCoin {
    address: String,
    base_units: String,
    quil: String,
    owner_form: OwnerForm,
    shielded: bool,
}

#[derive(serde::Serialize)]
struct JsonTotal {
    identities: usize,
    listed: usize,
    none: usize,
    no_key: usize,
    unavailable: usize,
    duplicates: usize,
    unshielded_count: usize,
    unshielded_base_units: String,
    unshielded_quil: String,
    shielded_count: usize,
}

/// `units` of QUIL as a decimal QUIL amount with 12 decimals.
fn quil(units: u128) -> String {
    crate::util::float_string_12(
        &num_bigint::BigInt::from(units),
        &crate::util::conversion_factor(),
    )
}

/// A frame number with thousands separators.
fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// A value as one shell word.
fn shell_word(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./~+=:,@".contains(c))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', r"'\''"))
    }
}

fn peer_suffix(row: &Row) -> String {
    row.identity
        .peer_tail
        .as_ref()
        .map_or(String::new(), |tail| format!(" (peer ID …{tail})"))
}

/// One coin: address, QUIL, base units, owner form and shielded state.
fn coin_line(coin: &Coin) -> String {
    format!(
        "0x{} {} QUIL ({} base units, {} owner{})",
        hex::encode(coin.address),
        quil(coin.amount),
        coin.amount,
        coin.form.text(),
        if coin.shielded { ", shielded" } else { "" }
    )
}

/// The result line of a single identity.
fn single_line(row: &Row) -> anyhow::Result<String> {
    Ok(match &row.outcome {
        Outcome::Listed(coins) if coins.is_empty() => {
            let forms: Vec<&str> = match &row.identity.owners {
                Ok(owners) => owners.iter().map(|(form, _)| form.text()).collect(),
                Err(_) => Vec::new(),
            };
            format!(
                "Legacy coins: none (the listing has no coin under the {} owner{})",
                forms.join(" or "),
                if forms.len() == 1 { "" } else { "s" }
            )
        }
        Outcome::Listed(coins) => {
            let tally = Tally::of(coins)?;
            format!(
                "{} QUIL ({} base units) across {} unshielded legacy coins ({} already shielded)",
                quil(tally.units),
                tally.units,
                tally.unshielded,
                tally.shielded
            )
        }
        Outcome::NoKey => "Legacy coins: none (config.yml has no Ed448 key, so this identity \
                           holds no legacy coins)"
            .to_string(),
        Outcome::Duplicate(of) => format!("Legacy coins: listed as {of}"),
        Outcome::Unavailable(error) => format!("Legacy coins: unavailable ({error})"),
    })
}

/// List `identities` and print the report. One identity that cannot be
/// listed does not stop the others; the command then fails.
async fn report(
    identities: Vec<Identity>,
    application: &[u8; 32],
    args: &LegacyArgs,
    default_listener: Option<&str>,
    read_args: String,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        application == &quil_execution::domains::QUIL_TOKEN,
        "only QUIL has legacy coins"
    );
    let report = list_all(identities, application, default_listener, read_args).await;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report.json(args.summary)?)?
        );
    } else if let [Row {
        outcome: Outcome::Unavailable(error),
        ..
    }] = report.rows.as_slice()
    {
        // One identity and no answer: the error says it all.
        anyhow::bail!("legacy coins unavailable: {error}");
    } else {
        print!("{}", report.text(args.summary)?);
    }
    report.result()
}

/// Ask each identity's node for its coins, once per owner address, then the
/// first node that answered for the GLOBAL head and the shard list.
pub(crate) async fn list_all(
    identities: Vec<Identity>,
    application: &[u8; 32],
    default_listener: Option<&str>,
    read_args: String,
) -> Report {
    let network = identities
        .iter()
        .find_map(|identity| identity.network)
        .unwrap_or(0);
    let count = identities.len();
    let mut clients: HashMap<String, Result<Client, String>> = HashMap::new();
    let mut dedup = Dedup::default();
    let mut first: Option<Client> = None;
    let mut rows = Vec::with_capacity(count);
    for (index, identity) in identities.into_iter().enumerate() {
        if count > 1 {
            eprintln!(
                "[{}/{count}] {}: listing legacy coins",
                index + 1,
                identity.label
            );
        }
        let mut note = identity.note.clone();
        let outcome = match dedup.plan(&identity) {
            Plan::Failed(error) => Outcome::Unavailable(error),
            Plan::NoKey => Outcome::NoKey,
            Plan::Duplicate(of) => Outcome::Duplicate(of),
            Plan::Ask(owners, overlap) => {
                note = match (note, overlap) {
                    (Some(note), Some(overlap)) => Some(format!("{note}; {overlap}")),
                    (note, overlap) => note.or(overlap),
                };
                let key = identity.node.endpoint_key();
                if !clients.contains_key(&key) {
                    let client = identity
                        .node
                        .connect(default_listener)
                        .await
                        .map_err(|e| format!("{e:#}"));
                    clients.insert(key.clone(), client);
                }
                match &clients[&key] {
                    Err(error) => Outcome::Unavailable(error.clone()),
                    Ok(client) => {
                        if first.is_none() {
                            first = Some(client.clone());
                        }
                        match list_owners(client, application, &owners, &identity.label, &mut 0)
                            .await
                        {
                            Ok(coins) => {
                                dedup.record(&owners, &identity.label);
                                Outcome::Listed(coins)
                            }
                            Err(error) => Outcome::Unavailable(format!("{error:#}")),
                        }
                    }
                }
            }
        };
        rows.push(Row {
            identity,
            outcome,
            note,
            plan: None,
        });
    }
    let to_shield = rows.iter().any(|row| match &row.outcome {
        Outcome::Listed(coins) => coins.iter().any(|coin| !coin.shielded),
        _ => false,
    });
    let (head, shards) = match &first {
        Some(client) => (
            global_head(client).await,
            if to_shield && BATCH_SHIELDS.is_some() {
                live_shard_paths(client, application).await.ok()
            } else {
                None
            },
        ),
        None => (Err("no node answered".to_string()), None),
    };
    for row in &mut rows {
        if let Outcome::Listed(coins) = &row.outcome {
            row.plan = shield_plan(coins, shards.as_deref());
        }
    }
    Report {
        network,
        head,
        rule: shield_rule(network),
        rows,
        read_args,
    }
}

/// `--read-rpc` and `--public-rpc` as the next command repeats them.
fn read_args(common: &TokenCommonArgs) -> String {
    let mut args = String::new();
    if let Some(multiaddr) = &common.read_rpc {
        args.push_str(" --read-rpc ");
        args.push_str(&shell_word(multiaddr));
        if common.insecure_read_rpc {
            args.push_str(" --insecure-read-rpc");
        }
    }
    if common.public_rpc {
        args.push_str(" --public-rpc");
    }
    args
}

/// `qclient token legacy`: no keystore is opened.
pub(super) async fn run(
    global: GlobalArgs,
    common: &TokenCommonArgs,
    application: &[u8; 32],
    args: &LegacyArgs,
) -> anyhow::Result<()> {
    let ctx = Context::load(global)?;
    let choice = NodeChoice::new(&ctx, common)?;
    let identities = identities(&choice, &common.config, args)?;
    report(
        identities,
        application,
        args,
        choice.default_listener(),
        read_args(common),
    )
    .await
}

/// `token legacy` for an already loaded token context: its identity, then
/// any keys, peer IDs and owners given, all read from its node.
pub(super) async fn run_loaded(
    tc: &TokenCtx,
    application: &[u8; 32],
    args: &LegacyArgs,
) -> anyhow::Result<()> {
    let node = ReadNode {
        opts: tc.connect_opts.clone(),
        source: NodeSource::Config(tc.config_dir.clone()),
    };
    let mut identities = vec![config_identity(
        &tc.node_config,
        &tc.config_dir,
        None,
        node.clone(),
    )];
    identities.extend(keyed_identities(args, || node.clone())?);
    report(identities, application, args, None, String::new()).await
}

#[cfg(test)]
#[path = "legacy_tests.rs"]
mod tests;
