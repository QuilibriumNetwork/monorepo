//! Keys of an operator's config that the node does not use.
//!
//! Unknown keys never fail the parse, so a setting of an earlier release or
//! a misspelt key would otherwise go unnoticed. [`unused_keys`] replays the
//! typed [`Config`] parse over the file's YAML and records every mapping key
//! that a config struct does not declare; serde's own field lists decide,
//! so renames and aliases count as known without a separate key list.
//! Maps (`logger.logFilters`) and lists are not inspected.

use std::cell::RefCell;

use serde::de::{DeserializeSeed, Deserializer, MapAccess, Visitor};
use serde::Deserialize;
use serde_yaml::Value;

use crate::Config;

/// Keys of earlier releases, mostly of the Go node, that this node ignores.
/// Matched case-insensitively against the full dotted path, which also
/// covers the camelCase spellings the Rust config wrote for them.
const RETIRED_KEYS: &[&str] = &[
    "listenRESTMultiaddr",
    "logFile",
    "key.keyManagerType",
    "engine.filter",
    "engine.pendingCommitWorkers",
    "engine.minimumPeersRequired",
    "engine.statsMultiaddr",
    "engine.dataWorkerMemoryLimit",
    "engine.syncTimeout",
    "engine.syncTimeoutMs",
    "engine.syncCandidates",
    "engine.syncMessageLimits",
    "engine.rewardsAddress",
    "engine.framePublish",
    "engine.allowExcessiveGOMAXPROCS",
    "engine.autoMergeCoins",
    "engine.dataWorkerBaseListenPort",
    "engine.dataWorkerMultiaddrs",
    "engine.difficulty",
    "engine.fullProver",
    "engine.maxFrames",
    "engine.rebuildStart",
    "engine.rebuildEnd",
    "db.inMemoryDONOTUSE",
    "p2p.d",
    "p2p.dHi",
    "p2p.dScore",
    "p2p.dOut",
    "p2p.dLazy",
    "p2p.gossipRetransmission",
    "p2p.prunePeers",
    "p2p.connectors",
    "p2p.maxPendingConnections",
    "p2p.connectionTimeout",
    "p2p.connectionTimeoutMs",
    "p2p.directConnectTicks",
    "p2p.directConnectInitialDelay",
    "p2p.directConnectInitialDelayMs",
    "p2p.opportunisticGraftTicks",
    "p2p.opportunisticGraftPeers",
    "p2p.graftFloodThreshold",
    "p2p.graftFloodThresholdMs",
    "p2p.maxIHaveLength",
    "p2p.maxIHaveMessages",
    "p2p.maxIDontWantMessages",
    "p2p.iDontWantMessageTTL",
    "p2p.traceLogFile",
    "p2p.traceLogStdout",
    "p2p.lowWatermarkConnections",
    "p2p.highWatermarkConnections",
    "p2p.grpcServerRateLimit",
    "p2p.minPeers",
    "p2p.minBootstrapPeers",
    "p2p.bootstrapParallelism",
    "p2p.discoveryParallelism",
    "p2p.discoveryPeerLookupLimit",
    "p2p.pingTimeout",
    "p2p.pingTimeoutMs",
    "p2p.pingPeriod",
    "p2p.pingPeriodMs",
    "p2p.pingAttempts",
    "p2p.validateQueueSize",
    "p2p.validateWorkers",
    "p2p.subscriptionQueueSize",
    "p2p.peerOutboundQueueSize",
    "p2p.peerReconnectCheckInterval",
    "p2p.peerReconnectCheckIntervalMs",
];

/// Top-level sections that other tools keep in the node's config:
/// qclient reads `alias.aliasFile`.
const OTHER_TOOLS_KEYS: &[&str] = &["alias"];

/// The most unknown keys [`unknown_keys_warning`] lists; the rest are
/// counted. [`retired_keys_notice`] lists every retired key, which
/// [`RETIRED_KEYS`] bounds.
const MAX_LISTED_UNKNOWN_KEYS: usize = 20;

/// The longest key path a line shows; longer ones are cut with `…`.
const MAX_KEY_CHARS: usize = 64;

/// A config key the node does not use, by its dotted path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnusedKey {
    /// A setting of an earlier release that has no effect in this node.
    Retired(String),
    /// A key this node does not know: likely a typo or a misplaced setting.
    Unknown(String),
}

/// The keys of the config file `contents` that the node does not use, in
/// file order. Contents that do not parse as a config yield none: the
/// typed parse reports those.
pub fn unused_keys(contents: &str) -> Vec<UnusedKey> {
    let Ok(value) = serde_yaml::from_str::<Value>(contents) else {
        return Vec::new();
    };
    let found = RefCell::new(Vec::new());
    if Config::deserialize(Probe { value, path: String::new(), found: &found }).is_err() {
        return Vec::new();
    }
    let mut keys: Vec<UnusedKey> = Vec::new();
    for path in found.into_inner() {
        if OTHER_TOOLS_KEYS.contains(&path.as_str()) {
            continue;
        }
        let key = if RETIRED_KEYS.iter().any(|retired| retired.eq_ignore_ascii_case(&path)) {
            UnusedKey::Retired(path)
        } else {
            UnusedKey::Unknown(path)
        };
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    keys
}

/// The startup warning naming the unknown keys among `keys`, at most
/// [`MAX_LISTED_UNKNOWN_KEYS`] of them; `None` when there are none.
pub fn unknown_keys_warning(keys: &[UnusedKey]) -> Option<String> {
    let unknown: Vec<&str> =
        keys.iter().filter_map(|key| if let UnusedKey::Unknown(path) = key { Some(path.as_str()) } else { None }).collect();
    let listed = listing(&unknown, MAX_LISTED_UNKNOWN_KEYS)?;
    Some(if unknown.len() == 1 {
        format!("1 config key is not a known setting (typo?): {listed}")
    } else {
        format!("{} config keys are not known settings (typo?): {listed}", unknown.len())
    })
}

/// The startup notice naming every retired key among `keys`; `None` when
/// there are none.
pub fn retired_keys_notice(keys: &[UnusedKey]) -> Option<String> {
    let retired: Vec<&str> =
        keys.iter().filter_map(|key| if let UnusedKey::Retired(path) = key { Some(path.as_str()) } else { None }).collect();
    let listed = listing(&retired, retired.len())?;
    Some(if retired.len() == 1 {
        format!("1 setting of an earlier release has no effect in this node; remove it from config.yml when convenient: {listed}; run `qclient node config clean` to comment it out")
    } else {
        format!(
            "{} settings of earlier releases have no effect in this node; remove them from config.yml when convenient: {listed}; run `qclient node config clean` to comment them out",
            retired.len()
        )
    })
}

/// The first `max` paths, each cut to [`MAX_KEY_CHARS`], and a count of
/// the rest; `None` for no paths.
fn listing(paths: &[&str], max: usize) -> Option<String> {
    if paths.is_empty() {
        return None;
    }
    let shown = paths.len().min(max);
    let mut text = paths[..shown].iter().map(|path| shortened(path)).collect::<Vec<_>>().join(", ");
    if shown < paths.len() {
        text.push_str(&format!(" (+{} more)", paths.len() - shown));
    }
    Some(text)
}

fn shortened(path: &str) -> String {
    if path.chars().count() <= MAX_KEY_CHARS {
        path.to_string()
    } else {
        let mut cut: String = path.chars().take(MAX_KEY_CHARS - 1).collect();
        cut.push('…');
        cut
    }
}

/// Deserializes a YAML value like `serde_yaml::Value` does, recording the
/// keys of every mapping read as a struct that the struct does not declare,
/// by their dotted path.
struct Probe<'a> {
    value: Value,
    path: String,
    found: &'a RefCell<Vec<String>>,
}

macro_rules! forward_to_value {
    ($($method:ident)*) => {
        $(
            fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, serde_yaml::Error> {
                self.value.$method(visitor)
            }
        )*
    };
}

impl<'de> Deserializer<'de> for Probe<'_> {
    type Error = serde_yaml::Error;

    forward_to_value! {
        deserialize_any deserialize_bool deserialize_i8 deserialize_i16 deserialize_i32 deserialize_i64
        deserialize_i128 deserialize_u8 deserialize_u16 deserialize_u32 deserialize_u64 deserialize_u128
        deserialize_f32 deserialize_f64 deserialize_char deserialize_bytes deserialize_byte_buf
        deserialize_unit deserialize_seq deserialize_map deserialize_ignored_any
    }

    // The typed parse reads a bare number or boolean into a string field;
    // read them as their text here too.
    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, serde_yaml::Error> {
        self.deserialize_string(visitor)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, serde_yaml::Error> {
        match self.value {
            Value::Number(number) => visitor.visit_string(number.to_string()),
            Value::Bool(flag) => visitor.visit_string(flag.to_string()),
            other => other.deserialize_string(visitor),
        }
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, serde_yaml::Error> {
        self.deserialize_string(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, serde_yaml::Error> {
        match self.value {
            Value::Null => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, serde_yaml::Error> {
        self.value.deserialize_unit_struct(name, visitor)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, serde_yaml::Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, serde_yaml::Error> {
        self.value.deserialize_tuple(len, visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, serde_yaml::Error> {
        self.value.deserialize_tuple_struct(name, len, visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, serde_yaml::Error> {
        self.value.deserialize_enum(name, variants, visitor)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, serde_yaml::Error> {
        let mapping = match self.value {
            Value::Mapping(mapping) => mapping,
            other => return other.deserialize_struct(name, fields, visitor),
        };
        let mut entries = Vec::with_capacity(mapping.len());
        for (key, value) in mapping {
            // A non-string key (`1: x`, `true: x`) reads as its text, as in
            // the typed parse.
            let name = match key {
                Value::String(name) => name,
                other => serde_yaml::to_string(&other).unwrap_or_default().trim().to_string(),
            };
            let path = if self.path.is_empty() { name.clone() } else { format!("{}.{name}", self.path) };
            let declared = fields.contains(&name.as_str());
            entries.push((name, value, path, declared));
        }
        visitor.visit_map(ProbeMap { entries: entries.into_iter(), next_value: None, found: self.found })
    }
}

/// The entries of a mapping read as a struct, each value probed in turn
/// and each key the struct does not declare recorded as it is read.
struct ProbeMap<'a> {
    entries: std::vec::IntoIter<(String, Value, String, bool)>,
    next_value: Option<(Value, String)>,
    found: &'a RefCell<Vec<String>>,
}

impl<'de> MapAccess<'de> for ProbeMap<'_> {
    type Error = serde_yaml::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>, serde_yaml::Error> {
        let Some((key, value, path, declared)) = self.entries.next() else {
            return Ok(None);
        };
        if !declared {
            self.found.borrow_mut().push(path.clone());
        }
        self.next_value = Some((value, path));
        seed.deserialize(Value::String(key)).map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, serde_yaml::Error> {
        let (value, path) = self
            .next_value
            .take()
            .ok_or_else(|| <serde_yaml::Error as serde::de::Error>::custom("value requested before its key"))?;
        seed.deserialize(Probe { value, path, found: self.found })
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retired(path: &str) -> UnusedKey {
        UnusedKey::Retired(path.to_string())
    }

    fn unknown(path: &str) -> UnusedKey {
        UnusedKey::Unknown(path.to_string())
    }

    /// Known keys, including aliases, renames and the qclient section, raise
    /// nothing; a retired key and a typo are named once each, a retired
    /// section at its root.
    #[test]
    fn unused_keys_name_retired_settings_and_typos() {
        let yaml = r#"
alias:
  aliasFile:
    path: alias.yml
    createIfMissing: true
key:
  keyManagerType: file
  keyManagerFile:
    path: keys.yml
    createIfMissing: false
    encryptionKey: "00"
p2p:
  network: 1
  dLo: 6
  heartbeatInterval: 700ms
  iWantFollowupTime: 3s
  maxIHaveLength: 5000
  connectionTimeoutMs: 0
  bootstrapPeer: /ip4/192.0.2.1/udp/8336/quic-v1
engine:
  dataWorkerBaseP2PPort: 25000
  archiveBlacklistTtl: -1
  dataWorkerMemoryLimit: 0
  framePublish:
    mode: full
    fragmentation:
      algorithm: reed-solomon
  archiveModes: true
logger:
  logFilters:
    anything: debug
diagnostics:
  healthReport:
    enabled: false
    enable: true
listenGRPCMultiaddr: /ip4/127.0.0.1/tcp/8337
listenRESTMultiaddr: /ip4/127.0.0.1/tcp/8338
"#;
        assert_eq!(
            unused_keys(yaml),
            vec![
                retired("key.keyManagerType"),
                retired("p2p.maxIHaveLength"),
                retired("p2p.connectionTimeoutMs"),
                unknown("p2p.bootstrapPeer"),
                retired("engine.dataWorkerMemoryLimit"),
                retired("engine.framePublish"),
                unknown("engine.archiveModes"),
                unknown("diagnostics.healthReport.enable"),
                retired("listenRESTMultiaddr"),
            ]
        );
    }

    /// A config of known keys only, in their written, alias or Go spelling,
    /// and the config the node itself writes raise no warning.
    #[test]
    fn a_clean_config_has_no_unused_keys() {
        let yaml = r#"
alias: null
key:
  keyManagerFile:
    path: keys.yml
p2p:
  network: 0
  dLo: 6
  historyLength: 9
  heartbeatInitialDelay: 100ms
  fanoutTTL: 60s
  pruneBackoff: 60s
  unsubscribeBackoffMs: 10000
  iDontWantMessageThreshold: 1024
  bootstrapPeers: []
  listenMultiaddr: /ip4/0.0.0.0/udp/8336/quic-v1
  streamListenMultiaddr: /ip4/0.0.0.0/tcp/8340
  directPeers: []
  disableOnionRouting: false
engine:
  dataWorkerBaseP2pPort: 25000
  dataWorkerP2PMultiaddrs: []
  dataWorkerAnnounceP2PMultiaddrs: []
  archiveBlacklistTtlSecs: 60
  consensusCommittee: []
db:
  path: store
  noticePercentage: 70
logger: null
listenGrpcMultiaddr: /ip4/127.0.0.1/tcp/8337
proofWorker:
  maxConcurrent: 2
diagnostics:
  logRequests:
    enabled: false
"#;
        assert_eq!(unused_keys(yaml), Vec::new());
        assert_eq!(unused_keys("listenGRPCMultiaddr: /ip4/127.0.0.1/tcp/8337\n"), Vec::new());
        let written = serde_yaml::to_string(&Config::default()).unwrap();
        assert_eq!(unused_keys(&written), Vec::new());
        assert_eq!(unknown_keys_warning(&unused_keys(&written)), None);
        assert_eq!(retired_keys_notice(&unused_keys(&written)), None);
        assert_eq!(unused_keys("not: [valid"), Vec::new());
    }

    /// Every key the Go node's config ever had is either still read or
    /// named as retired, never as a typo.
    #[test]
    fn go_node_keys_are_known_or_retired() {
        let yaml = r#"
logFile: node.log
key:
  keyManagerType: file
  keyManagerFile: {path: keys.yml, createIfMissing: false, encryptionKey: "00"}
p2p:
  d: 0
  dLo: 0
  dHi: 0
  dScore: 0
  dOut: 0
  historyLength: 0
  historyGossip: 0
  dLazy: 0
  gossipFactor: 0
  gossipRetransmission: 0
  heartbeatInitialDelay: 0s
  heartbeatInterval: 0s
  fanoutTTL: 0s
  prunePeers: 0
  pruneBackoff: 0s
  unsubscribeBackoff: 0s
  connectors: 0
  maxPendingConnections: 0
  connectionTimeout: 0s
  directConnectTicks: 0
  directConnectInitialDelay: 0s
  opportunisticGraftTicks: 0
  opportunisticGraftPeers: 0
  graftFloodThreshold: 0s
  maxIHaveLength: 0
  maxIHaveMessages: 0
  maxIDontWantMessages: 0
  iWantFollowupTime: 0s
  iDontWantMessageThreshold: 0
  iDontWantMessageTTL: 0
  bootstrapPeers: []
  listenMultiaddr: ""
  streamListenMultiaddr: ""
  announceListenMultiaddr: ""
  announceStreamListenMultiaddr: ""
  peerPrivKey: ""
  traceLogFile: ""
  traceLogStdout: false
  network: 0
  lowWatermarkConnections: 0
  highWatermarkConnections: 0
  directPeers: []
  grpcServerRateLimit: 0
  minPeers: 0
  minBootstrapPeers: 0
  bootstrapParallelism: 0
  discoveryParallelism: 0
  discoveryPeerLookupLimit: 0
  pingTimeout: 0s
  pingPeriod: 0s
  pingAttempts: 0
  validateQueueSize: 0
  validateWorkers: 0
  subscriptionQueueSize: 0
  peerOutboundQueueSize: 0
  peerReconnectCheckInterval: 0s
engine:
  provingKeyId: default-proving-key
  filter: ""
  genesisSeed: ""
  pendingCommitWorkers: 0
  minimumPeersRequired: 0
  statsMultiaddr: ""
  dataWorkerBaseListenMultiaddr: ""
  dataWorkerBaseListenPort: 0
  dataWorkerBaseP2PPort: 0
  dataWorkerBaseStreamPort: 0
  dataWorkerMemoryLimit: 0
  dataWorkerMultiaddrs: []
  dataWorkerP2PMultiaddrs: []
  dataWorkerStreamMultiaddrs: []
  dataWorkerAnnounceP2PMultiaddrs: []
  dataWorkerAnnounceStreamMultiaddrs: []
  dataWorkerCount: 0
  dataWorkerFilters: []
  multisigProverEnrollmentPaths: []
  syncTimeout: 0s
  syncCandidates: 0
  syncMessageLimits: {maxRecvMsgSize: 0, maxSendMsgSize: 0}
  enableMasterProxy: false
  rewardStrategy: ""
  archiveMode: false
  delegateAddress: ""
  rewardsAddress: ""
  allowExcessiveGOMAXPROCS: false
  archiveEndpoints: []
  blacklist: []
  alertKey: ""
  autoMergeCoins: false
  difficulty: 0
  fullProver: false
  maxFrames: 0
  rebuildstart: ""
  rebuildend: ""
  framePublish: {mode: full}
db:
  path: store
  inmemorydonotuse: false
  workerPathPrefix: worker-store/%d
  workerPaths: []
  noticePercentage: 0
  warnPercentage: 0
  terminatePercentage: 0
logger:
  path: ""
  maxSize: 0
  maxBackups: 0
  maxAge: 0
  compress: false
  logFilters: {}
listenGrpcMultiaddr: ""
listenRESTMultiaddr: ""
"#;
        let keys = unused_keys(yaml);
        assert_eq!(keys.iter().filter(|key| matches!(key, UnusedKey::Unknown(_))).count(), 0, "{keys:?}");
        assert_eq!(keys.len(), 60, "{keys:?}");
    }

    /// Unknown keys get a warning listing at most twenty; retired keys a
    /// separate notice listing all of them, so neither hides the other.
    #[test]
    fn unknown_and_retired_keys_get_separate_lines() {
        assert_eq!(unknown_keys_warning(&[]), None);
        assert_eq!(retired_keys_notice(&[]), None);
        let keys = [retired("p2p.d"), unknown("p2p.bootstrapPeer"), retired("engine.framePublish")];
        assert_eq!(
            unknown_keys_warning(&keys).unwrap(),
            "1 config key is not a known setting (typo?): p2p.bootstrapPeer"
        );
        assert_eq!(
            retired_keys_notice(&keys).unwrap(),
            "2 settings of earlier releases have no effect in this node; remove them from config.yml when convenient: \
             p2p.d, engine.framePublish; run `qclient node config clean` to comment them out"
        );
        assert_eq!(
            retired_keys_notice(&[retired("p2p.d")]).unwrap(),
            "1 setting of an earlier release has no effect in this node; remove it from config.yml when convenient: p2p.d; run `qclient node config clean` to comment it out"
        );
        assert_eq!(unknown_keys_warning(&[retired("p2p.d")]), None);

        let mut many: Vec<UnusedKey> = (0..25).map(|n| unknown(&format!("engine.typo{n}"))).collect();
        many.extend((0..40).map(|n| retired(&format!("p2p.old{n}"))));
        let warning = unknown_keys_warning(&many).unwrap();
        assert!(warning.starts_with("25 config keys are not known settings (typo?): engine.typo0, "), "{warning}");
        assert!(warning.ends_with("engine.typo19 (+5 more)"), "{warning}");
        let notice = retired_keys_notice(&many).unwrap();
        assert!(notice.starts_with("40 settings of earlier releases"), "{notice}");
        assert!(notice.contains("p2p.old38, p2p.old39; run `qclient node config clean`"), "{notice}");

        let long = format!("engine.{}", "x".repeat(80));
        let warning = unknown_keys_warning(&[unknown(&long)]).unwrap();
        let shown = warning.rsplit(": ").next().unwrap();
        assert_eq!(shown.chars().count(), 64, "{warning}");
        assert!(shown.ends_with('…') && shown.starts_with("engine.xxx"), "{warning}");
    }

    /// The probe reads scalars as leniently as the typed parse: a string
    /// setting written as a bare number or boolean and a non-string key
    /// still give the right notices.
    #[test]
    fn bare_scalars_and_non_string_keys_are_read_like_the_typed_parse() {
        let yaml = "p2p:\n  network: 1\n  peerPrivKey: 1234\n  listenMultiaddr: true\n  d: 8\n  7: x\nengine:\n  delegateAddress: 99\n  true: y\n";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!((config.p2p.peer_priv_key.as_str(), config.engine.delegate_address.as_str()), ("1234", "99"));
        assert_eq!(unused_keys(yaml), vec![retired("p2p.d"), unknown("p2p.7"), unknown("engine.true")]);
    }
}
