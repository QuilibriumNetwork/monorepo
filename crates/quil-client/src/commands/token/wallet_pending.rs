//! This wallet's recent spends, kept in its config directory: the keys each
//! submitted operation consumes (spend markers, shield sources' markers,
//! receipts), the coins they belong to, and a settlement's receipt.
//!
//! A regular node answers GLOBAL reads from a view it pulls from an archive,
//! which can trail GLOBAL by minutes, so a coin this wallet spent moments ago
//! can still read unspent there. Selection leaves such a coin out for
//! [`HOLD`] ([`RecipientWallet::hold_pending`]). A wait for a spend's outcome
//! reads its inputs' consumption records each poll ([`check_inputs`]): an
//! input another operation consumed means every node refuses this one on
//! arrival and the commit never decides it, so the wait ends then instead of
//! at its deadline.
//!
//! The journal is a hint: an unreadable one holds nothing, and two commands
//! writing at once may lose one entry, never corrupt the file. It is bounded
//! by [`MAX_SPENDS`] entries and [`KEEP`].
//!
//! Two older journals leave out coins for the same window
//! ([`SUBMITTED_EXCLUSION_SECS`](super::super::legacy::SUBMITTED_EXCLUSION_SECS)):
//! shield-all's, which lists legacy coin addresses for `token legacy` and the
//! node manager too, and the batch merge's, written before delivery so a
//! merge whose delivery result was lost stays out. This journal is written
//! once a delivery succeeded and keyed by what the commit consumes, so a
//! wait can read each input's consumer and a refusal can free its coins.
use super::{RecipientWallet, TokenCtx};
use quil_execution::token_intrinsic::global_commit;

type Client =
    quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>;

/// How long selection leaves out a coin this wallet spent while the node
/// still lists it unspent: the window shield-all and the batch merge leave
/// their submitted coins out for. A submitted operation commits with its
/// shard's next frame, which mainnet has held back about 30 min (a batch
/// shield committed 1,864 s after its submission;
/// `shield_pacing::DEFAULT_INCLUSION_TIMEOUT_SECS`), so a shorter hold
/// could select a coin whose spend still commits. A spend a wait shows
/// refused frees its coins at once, and a command naming a coin takes it.
pub(super) const HOLD: std::time::Duration =
    std::time::Duration::from_secs(super::super::legacy::SUBMITTED_EXCLUSION_SECS);

/// How long an entry is kept: a resumed settlement wait finds its inputs
/// within this.
const KEEP: std::time::Duration = std::time::Duration::from_secs(86_400);

/// Most entries kept; the oldest go first.
const MAX_SPENDS: usize = 256;

/// The journal's file in the wallet's config directory.
const FILE: &str = "wallet-pending-spends.txt";

/// One input of a submitted spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SpentInput {
    /// The key the global commit consumes for it (a spend marker, a shield
    /// source's marker, a receipt), whose GLOBAL consumption record names
    /// the operation that consumed it.
    pub(super) marker: [u8; 32],
    /// The coin, when this run selected it.
    pub(super) coin: Option<[u8; 32]>,
}

/// One submitted spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PendingSpend {
    pub(super) application: [u8; 32],
    /// The global commit's key for it: SHA3-256 of the operation bytes.
    pub(super) operation: [u8; 32],
    /// A settlement's receipt.
    pub(super) receipt: Option<[u8; 32]>,
    /// Unix seconds when it was submitted.
    pub(super) at: u64,
    pub(super) inputs: Vec<SpentInput>,
}

impl PendingSpend {
    /// The spend `bytes` of `application` makes: its inputs are what the
    /// global commit consumes for it
    /// ([`spend_entries::commit_needs`](quil_execution::token_intrinsic::spend_entries::commit_needs)):
    /// a spend's markers, a shield's legacy sources, a mint claim's or a
    /// custom mint's receipt. `coins` names an input's coin by marker. `None`
    /// for an operation that consumes nothing: an escrow claim, which spends
    /// its escrow record, and the QUIL reward mint, which GLOBAL executes.
    pub(super) fn of(
        network: &[u8; 32],
        application: &[u8; 32],
        bytes: &[u8],
        coins: &std::collections::HashMap<[u8; 32], [u8; 32]>,
        at: u64,
    ) -> Option<Self> {
        use quil_execution::token_intrinsic::{
            constants::TYPE_LATTICE_SETTLEMENT, settlement_record, spend_entries,
        };
        use quil_lattice_ct::confidential::settlement::Settlement;
        let kind = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?);
        let consumed = spend_entries::commit_needs(application, kind, bytes)?.consumptions;
        if consumed.is_empty() {
            return None;
        }
        let receipt = match kind {
            TYPE_LATTICE_SETTLEMENT => Some(
                settlement_record::receipt_address(
                    &Settlement::decode(bytes, network, application)
                        .ok()?
                        .statement,
                )
                .ok()?,
            ),
            _ => None,
        };
        Some(Self {
            application: *application,
            operation: global_commit::tx_id(bytes),
            receipt,
            at,
            inputs: consumed
                .into_iter()
                .map(|marker| SpentInput {
                    marker,
                    coin: coins.get(&marker).copied(),
                })
                .collect(),
        })
    }

    fn encode(&self) -> String {
        let mut line = format!(
            "{} {} {} {}",
            hex::encode(self.application),
            hex::encode(self.operation),
            self.receipt.map_or_else(|| "-".into(), hex::encode),
            self.at
        );
        for input in &self.inputs {
            line.push_str(&format!(
                " {}:{}",
                hex::encode(input.marker),
                input.coin.map_or_else(|| "-".into(), hex::encode)
            ));
        }
        line
    }

    fn decode(line: &str) -> Option<Self> {
        fn id(field: &str) -> Option<[u8; 32]> {
            hex::decode(field).ok()?.try_into().ok()
        }
        let mut fields = line.split_whitespace();
        let application = id(fields.next()?)?;
        let operation = id(fields.next()?)?;
        let receipt = match fields.next()? {
            "-" => None,
            receipt => Some(id(receipt)?),
        };
        let at = fields.next()?.parse().ok()?;
        let inputs = fields
            .map(|field| {
                let (marker, coin) = field.split_once(':')?;
                Some(SpentInput {
                    marker: id(marker)?,
                    coin: match coin {
                        "-" => None,
                        coin => Some(id(coin)?),
                    },
                })
            })
            .collect::<Option<Vec<_>>>()?;
        (!inputs.is_empty()).then_some(Self {
            application,
            operation,
            receipt,
            at,
            inputs,
        })
    }
}

/// The journal in one wallet config directory.
#[derive(Clone, Debug)]
pub(super) struct PendingSpends {
    path: std::path::PathBuf,
}

impl PendingSpends {
    pub(super) fn at(dir: &std::path::Path) -> Self {
        Self {
            path: dir.join(FILE),
        }
    }

    /// Its entries; none when it is missing or cannot be read.
    pub(super) fn read(&self) -> Vec<PendingSpend> {
        std::fs::read_to_string(&self.path)
            .map(|text| text.lines().filter_map(PendingSpend::decode).collect())
            .unwrap_or_default()
    }

    /// Keep the entries `keep` takes that are under [`KEEP`] old at `now`,
    /// the newest [`MAX_SPENDS`] of them.
    fn rewrite(&self, now: u64, keep: impl Fn(&PendingSpend) -> bool, add: Option<PendingSpend>) {
        let mut spends: Vec<PendingSpend> = self
            .read()
            .into_iter()
            .filter(|spend| now.saturating_sub(spend.at) < KEEP.as_secs() && keep(spend))
            .chain(add)
            .collect();
        let excess = spends.len().saturating_sub(MAX_SPENDS);
        spends.drain(..excess);
        let body: String = spends.iter().map(|spend| spend.encode() + "\n").collect();
        // A hint: a journal that cannot be written holds nothing back.
        if let Err(error) = quil_config::atomic_write(&self.path, body.as_bytes(), 0o600) {
            super::super::output::detail(format!(
                "Could not update the pending-spend journal {}: {error}",
                self.path.display()
            ));
        }
    }

    /// Add `spend`, replacing an entry of the same operation.
    pub(super) fn record(&self, spend: PendingSpend) {
        let operation = spend.operation;
        self.rewrite(spend.at, |old| old.operation != operation, Some(spend));
    }

    /// Drop the entries of `operation`, which will never commit.
    pub(super) fn release(&self, operation: &[u8; 32]) {
        self.rewrite(
            RecipientWallet::unix_now(),
            |old| &old.operation != operation,
            None,
        );
    }

    /// The newest entry of the settlement paying `receipt`.
    pub(super) fn by_receipt(&self, receipt: &[u8; 32]) -> Option<PendingSpend> {
        self.read()
            .into_iter()
            .rev()
            .find(|spend| spend.receipt.as_ref() == Some(receipt))
    }

    /// The newest entry of `operation` of `application`.
    pub(super) fn by_operation(
        &self,
        application: &[u8; 32],
        operation: &[u8; 32],
    ) -> Option<PendingSpend> {
        self.read()
            .into_iter()
            .rev()
            .find(|spend| &spend.application == application && &spend.operation == operation)
    }

    /// The markers of `application`'s spends younger than [`HOLD`] at `now`,
    /// each with its spend.
    pub(super) fn held(
        &self,
        application: &[u8; 32],
        now: u64,
    ) -> std::collections::HashMap<[u8; 32], PendingSpend> {
        let mut held = std::collections::HashMap::new();
        for spend in self.read() {
            if &spend.application == application && now.saturating_sub(spend.at) < HOLD.as_secs() {
                for input in &spend.inputs {
                    held.insert(input.marker, spend.clone());
                }
            }
        }
        held
    }
}

/// An input of a submitted spend that another operation consumed: the spend
/// can never commit, and every node refuses it on arrival.
#[derive(Debug)]
pub(super) struct InputSpent {
    /// What the spend is, as the error names it ("settlement 0x…").
    pub(super) what: String,
    pub(super) input: SpentInput,
    /// The operation that consumed it.
    pub(super) by: [u8; 32],
    /// Whether that operation is one this wallet journaled.
    pub(super) own: bool,
}

impl std::fmt::Display for InputSpent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let input = match self.input.coin {
            Some(coin) => format!("input coin 0x{}", hex::encode(coin)),
            None => format!(
                "input with consumption key 0x{}",
                hex::encode(self.input.marker)
            ),
        };
        let (by, cause) = if self.own {
            ("this wallet's earlier operation", "")
        } else {
            (
                "operation",
                ", or another copy of this wallet or a concurrent command spent it first",
            )
        };
        let next = match self.input.coin {
            Some(_) => "rerun to select other coins",
            None => "check what that operation did before running this again",
        };
        write!(
            f,
            "the {} can never commit: its {input} was already consumed by {by} 0x{}, so every \
             node refuses it and none of its inputs was spent. The node still listed the input \
             unspent when this was built: its GLOBAL view may trail GLOBAL{cause}; {next}",
            self.what,
            hex::encode(self.by)
        )
    }
}

impl std::error::Error for InputSpent {}

/// What a spend's inputs' consumption records say.
#[derive(Debug)]
pub(super) enum Inputs {
    /// None is consumed yet, or none could be read.
    Unspent,
    /// The spend itself consumed them: it committed.
    Committed,
    /// Another operation consumed one.
    Spent(InputSpent),
}

/// The operation that consumed `key` (a spend marker or a receipt) of
/// `application`, from its GLOBAL consumption record; `None` while none did.
pub(super) async fn read_consumer(
    client: &Client,
    application: &[u8; 32],
    key: &[u8; 32],
) -> anyhow::Result<Option<[u8; 32]>> {
    let mut address = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
    address.extend_from_slice(&global_commit::consumed_address(application, key)?);
    let response = client
        .clone()
        .max_decoding_message_size(66_560)
        .get_vertex_data(quil_types::proto::node::GetVertexDataRequest {
            address,
            full_data: true,
        })
        .await?
        .into_inner();
    let (present, blob) = RecipientWallet::decode_global_record(response)?;
    if !present {
        return Ok(None);
    }
    Ok(Some(global_commit::parse_consumed_record(&blob)?))
}

/// Read each input of `spend` (`what`, for the error) until one is consumed.
/// A read that fails or a record that does not parse says nothing: the wait
/// goes on as it did without this check.
pub(super) async fn check_inputs(client: &Client, spend: &PendingSpend, what: &str) -> Inputs {
    for input in &spend.inputs {
        match read_consumer(client, &spend.application, &input.marker).await {
            Ok(Some(by)) if by == spend.operation => return Inputs::Committed,
            Ok(Some(by)) => {
                return Inputs::Spent(InputSpent {
                    what: what.to_string(),
                    input: input.clone(),
                    by,
                    own: false,
                })
            }
            Ok(None) | Err(_) => {}
        }
    }
    Inputs::Unspent
}

/// Watches one wait's spend: its journal entry, read once, and whether its
/// inputs still need reading.
pub(super) struct InputWatch {
    spends: PendingSpends,
    spend: Option<PendingSpend>,
    what: String,
}

impl InputWatch {
    /// The settlement paying `receipt`, as this wallet recorded it.
    pub(super) fn settlement(tc: &TokenCtx, receipt: &[u8; 32]) -> Self {
        let spends = PendingSpends::at(&tc.config_dir);
        let spend = spends.by_receipt(receipt);
        Self {
            spends,
            spend,
            what: format!("settlement 0x{}", hex::encode(receipt)),
        }
    }

    /// Operation `operation` of `application` (`what`), as this wallet
    /// recorded it.
    pub(super) fn operation(
        tc: &TokenCtx,
        what: &str,
        application: &[u8; 32],
        operation: &[u8; 32],
    ) -> Self {
        let spends = PendingSpends::at(&tc.config_dir);
        let spend = spends.by_operation(application, operation);
        Self {
            spends,
            spend,
            what: format!("{what} 0x{}", hex::encode(operation)),
        }
    }

    /// The commit decided the spend: a rejection spent none of its coins,
    /// which selection takes again at once.
    pub(super) fn decided(&mut self, decision: &global_commit::Decision) {
        if let (Some(spend), global_commit::Decision::Rejected { .. }) = (&self.spend, decision) {
            self.spends.release(&spend.operation);
        }
        self.spend = None;
    }

    /// One poll, its reads ended at the wait's `deadline`: an error once
    /// another operation consumed an input, which also frees the spend's
    /// other coins for selection. Once the spend itself shows committed,
    /// later polls read nothing.
    pub(super) async fn poll(
        &mut self,
        client: &Client,
        deadline: std::time::Instant,
    ) -> Result<(), InputSpent> {
        let Some(spend) = &self.spend else {
            return Ok(());
        };
        let read = check_inputs(client, spend, &self.what);
        // A read that hangs says nothing, as one that fails.
        let inputs = tokio::time::timeout_at(deadline.into(), read)
            .await
            .unwrap_or(Inputs::Unspent);
        match inputs {
            Inputs::Unspent => Ok(()),
            Inputs::Committed => {
                self.spend = None;
                Ok(())
            }
            Inputs::Spent(mut spent) => {
                spent.own = self
                    .spends
                    .by_operation(&spend.application, &spent.by)
                    .is_some();
                self.spends.release(&spend.operation);
                self.spend = None;
                Err(spent)
            }
        }
    }
}

impl RecipientWallet {
    /// Journal the spend `bytes` makes, once submitted.
    pub(super) fn note_submitted(&self, bytes: &[u8]) {
        let Some(spends) = &self.spends else {
            return;
        };
        let coins = self.input_coins.lock().expect("input coin lock").clone();
        if let Some(spend) = PendingSpend::of(
            &self.network,
            &self.application,
            bytes,
            &coins,
            RecipientWallet::unix_now(),
        ) {
            spends.record(spend);
        }
    }

    /// Note the coins a spend being built takes, by spend marker, so its
    /// journal entry names them.
    pub(super) fn note_inputs(&self, coins: impl IntoIterator<Item = ([u8; 32], [u8; 32])>) {
        let mut known = self.input_coins.lock().expect("input coin lock");
        // Bounded: a run builds a few spends; a long batch drops old ones.
        if known.len() > 4 * MAX_SPENDS {
            known.clear();
        }
        known.extend(coins);
    }

    /// `coins` without those this wallet spent within [`HOLD`] that the
    /// node still lists unspent; one line names what was left out.
    pub(super) fn hold_pending(
        &self,
        coins: Vec<super::OwnedCoin>,
    ) -> anyhow::Result<Vec<super::OwnedCoin>> {
        let Some(spends) = &self.spends else {
            return Ok(coins);
        };
        let now = RecipientWallet::unix_now();
        let held = spends.held(&self.application, now);
        if held.is_empty() {
            return Ok(coins);
        }
        let mut kept = Vec::with_capacity(coins.len());
        let mut left = Vec::new();
        for coin in coins {
            let marker = quil_execution::token_intrinsic::spent::marker_address(
                &self.network,
                &self.application,
                &coin.image,
            )?;
            match held.get(&marker) {
                Some(spend) => left.push((coin, spend.at)),
                None => kept.push(coin),
            }
        }
        if let Some(until) = left.iter().map(|(_, at)| at + HOLD.as_secs()).max() {
            let total = left
                .iter()
                .fold(0u128, |sum, (coin, _)| sum.saturating_add(*coin.amount));
            let named: Vec<String> = left
                .iter()
                .take(4)
                .map(|(coin, _)| format!("0x{}", hex::encode(coin.address)))
                .collect();
            super::super::output::err_line(format!(
                "Left out {} coin(s) of {total} base units this wallet spent within the last {} \
                 min that the node still lists unspent ({}{}): its GLOBAL view may trail GLOBAL. \
                 They are selectable again once the node lists them spent or their spend is \
                 refused, else after {} UTC; a command naming a coin still takes it.",
                left.len(),
                HOLD.as_secs() / 60,
                named.join(", "),
                if left.len() > named.len() {
                    ", ..."
                } else {
                    ""
                },
                super::super::shield_pacing::utc(until)
            ));
        }
        Ok(kept)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spend(operation: u8, at: u64, markers: &[u8]) -> PendingSpend {
        PendingSpend {
            application: [1; 32],
            operation: [operation; 32],
            receipt: operation.is_multiple_of(2).then_some([operation + 100; 32]),
            at,
            inputs: markers
                .iter()
                .map(|marker| SpentInput {
                    marker: [*marker; 32],
                    coin: marker.is_multiple_of(2).then_some([marker + 50; 32]),
                })
                .collect(),
        }
    }

    #[test]
    fn the_journal_round_trips_holds_and_stays_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let spends = PendingSpends::at(directory.path());
        let now = RecipientWallet::unix_now();
        spends.record(spend(2, now, &[3, 4]));
        spends.record(spend(5, now - HOLD.as_secs(), &[6]));
        assert_eq!(
            spends.read(),
            vec![spend(2, now, &[3, 4]), spend(5, now - HOLD.as_secs(), &[6])]
        );
        assert_eq!(spends.by_receipt(&[102; 32]), Some(spend(2, now, &[3, 4])));
        assert_eq!(
            spends.by_operation(&[1; 32], &[5; 32]).map(|s| s.at),
            Some(now - HOLD.as_secs())
        );
        assert_eq!(spends.by_operation(&[9; 32], &[5; 32]), None);
        let held = spends.held(&[1; 32], now);
        let mut markers: Vec<_> = held.keys().copied().collect();
        markers.sort();
        assert_eq!(
            markers,
            vec![[3; 32], [4; 32]],
            "a spend past the hold holds nothing"
        );
        assert!(spends.held(&[9; 32], now).is_empty());
        spends.release(&[2; 32]);
        assert!(
            spends.held(&[1; 32], now).is_empty(),
            "journal_release: a released spend still holds its coins"
        );
        let numbered = |index: usize| {
            let mut operation = [0; 32];
            operation[24..].copy_from_slice(&(index as u64).to_be_bytes());
            operation
        };
        for index in 0..(MAX_SPENDS + 10) {
            spends.record(PendingSpend {
                operation: numbered(index),
                receipt: None,
                ..spend(1, now, &[(index % 7) as u8])
            });
        }
        let kept = spends.read();
        assert_eq!(
            kept.len(),
            MAX_SPENDS,
            "journal_bound: the journal outgrew its bound"
        );
        assert_eq!(
            kept[0].operation,
            numbered(10),
            "the oldest entries go first"
        );
        spends.record(spend(9, now - KEEP.as_secs(), &[1]));
        spends.record(spend(11, now, &[1]));
        assert!(
            spends.read().iter().all(|s| s.operation != [9; 32]),
            "an entry past KEEP is dropped"
        );
        std::fs::write(directory.path().join(FILE), "not a line\n").unwrap();
        assert!(spends.read().is_empty());
    }
}
