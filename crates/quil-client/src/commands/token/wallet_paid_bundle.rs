//! A custom-token operation's paid bundle. Its QUIL settlement binds that one
//! bundle (`settlement_claim::bundle_context`: the SHA3-256 of the bundle's
//! other requests and timestamp), so a custom mint saves the bundle before the
//! settlement is sent. A mint whose settlement is not certified within
//! `--pay-wait` is then finished by `token custom-mint --resume <file>`,
//! which submits that same bundle and pays nothing again.
use super::*;
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

/// First line of a saved paid bundle.
const HEADER: &str = "qclient custom-mint resume v1";

/// The `--pay-wait` a resume suggests, in seconds: twice the default.
const RESUME_WAIT_SECS: u64 = 1800;

/// Called with a settlement's receipt after it is built and before it is
/// sent; an error stops the payment.
pub(super) type BeforeSubmit<'a> = dyn Fn(&[u8; 32]) -> anyhow::Result<()> + Sync + 'a;

/// What rebuilds a paid bundle exactly, and the settlement that pays for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PaidBundle {
    pub(super) network: [u8; 32],
    pub(super) application: [u8; 32],
    /// The bundle's timestamp, part of the context the settlement binds.
    pub(super) timestamp: i64,
    /// The operation the bundle carries after its claim.
    pub(super) operation: Vec<u8>,
    /// The settlement's receipt, which its claim spends.
    pub(super) receipt: [u8; 32],
    /// The settlement amount in QUIL base units.
    pub(super) settlement: u128,
    /// The settlement record's payment address and value (a paid mint's price).
    pub(super) payment: Option<([u8; 32], u128)>,
    /// Whether the bundle executes in the global venue.
    pub(super) global_execution: bool,
}

impl PaidBundle {
    /// The bundle without its claim, as its context hashes it.
    pub(super) fn rest(&self) -> anyhow::Result<CanonicalMessageBundle> {
        Ok(CanonicalMessageBundle {
            requests: vec![
                None,
                Some(
                    CanonicalMessageRequest::wrap(self.operation.clone())
                        .map_err(|e| anyhow::anyhow!("wrap operation: {e}"))?,
                ),
            ],
            timestamp: self.timestamp,
        })
    }

    /// The context the settlement binds.
    pub(super) fn context(&self) -> anyhow::Result<[u8; 32]> {
        Ok(quil_execution::token_intrinsic::settlement_claim::bundle_context(&self.rest()?)?)
    }

    /// `custom-mint-<first 8 receipt bytes>.txt` in `dir`.
    pub(super) fn path(&self, dir: &std::path::Path) -> std::path::PathBuf {
        dir.join(format!(
            "custom-mint-{}.txt",
            hex::encode(&self.receipt[..8])
        ))
    }

    /// One `key value` line per field; `context` lets a load check the rest.
    pub(super) fn encode(&self) -> anyhow::Result<String> {
        let payment = match self.payment {
            Some((address, value)) => format!("{} {value}", hex::encode(address)),
            None => "none".into(),
        };
        Ok(format!(
            "{HEADER}\nnetwork {}\napplication {}\ntimestamp {}\nreceipt {}\nsettlement {}\n\
             payment {payment}\nglobal-execution {}\ncontext {}\noperation {}\n",
            hex::encode(self.network),
            hex::encode(self.application),
            self.timestamp,
            hex::encode(self.receipt),
            self.settlement,
            self.global_execution,
            hex::encode(self.context()?),
            hex::encode(&self.operation),
        ))
    }

    /// [`encode`](Self::encode)'s text, refused unless every field is there
    /// once and the bundle still hashes to the saved context.
    pub(super) fn decode(text: &str) -> anyhow::Result<Self> {
        let mut lines = text.lines();
        anyhow::ensure!(
            lines.next() == Some(HEADER),
            "not a saved custom-mint bundle (its first line is not {HEADER:?})"
        );
        let mut fields = std::collections::BTreeMap::new();
        for line in lines {
            let (key, value) = line
                .split_once(' ')
                .ok_or_else(|| anyhow::anyhow!("malformed line {line:?}"))?;
            anyhow::ensure!(fields.insert(key, value).is_none(), "{key} given twice");
        }
        let mut take = |key: &str| {
            fields
                .remove(key)
                .ok_or_else(|| anyhow::anyhow!("no {key} line"))
        };
        let id = |key: &str, value: &str| -> anyhow::Result<[u8; 32]> {
            hex::decode(value)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("{key} must be 32 bytes of hex"))
        };
        let network = id("network", take("network")?)?;
        let application = id("application", take("application")?)?;
        let timestamp = take("timestamp")?.parse()?;
        let receipt = id("receipt", take("receipt")?)?;
        let settlement = take("settlement")?.parse()?;
        let payment = match take("payment")? {
            "none" => None,
            value => {
                let (address, value) = value
                    .split_once(' ')
                    .ok_or_else(|| anyhow::anyhow!("payment is `<address> <value>` or none"))?;
                Some((id("payment address", address)?, value.parse()?))
            }
        };
        let global_execution = take("global-execution")?.parse()?;
        let context = id("context", take("context")?)?;
        let operation = hex::decode(take("operation")?)?;
        anyhow::ensure!(
            fields.is_empty(),
            "unknown lines: {}",
            fields.into_keys().collect::<Vec<_>>().join(", ")
        );
        let saved = Self {
            network,
            application,
            timestamp,
            operation,
            receipt,
            settlement,
            payment,
            global_execution,
        };
        anyhow::ensure!(
            saved.context()? == context,
            "the saved bundle does not hash to the context its settlement binds: the file was \
             changed"
        );
        Ok(saved)
    }

    /// Write it to [`path`](Self::path) in `dir`.
    pub(super) fn save(&self, dir: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
        let path = self.path(dir);
        quil_config::atomic_write(&path, self.encode()?.as_bytes(), 0o644)
            .map_err(|e| anyhow::anyhow!("save {}: {e}", path.display()))?;
        Ok(path)
    }

    pub(super) fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        std::fs::read_to_string(path)
            .map_err(anyhow::Error::from)
            .and_then(|text| Self::decode(&text))
            .map_err(|e| anyhow::anyhow!("{}: {e:#}", path.display()))
    }
}

/// The command that finishes the paid bundle saved at `saved`.
fn resume_command(program: &str, read_flags: &[String], saved: &std::path::Path) -> String {
    let mut words = vec![
        program.to_string(),
        "token".into(),
        "custom-mint".into(),
        "--resume".into(),
        saved.display().to_string(),
    ];
    words.extend(read_flags.iter().cloned());
    words.push("--pay-wait".into());
    words.push(RESUME_WAIT_SECS.to_string());
    words
        .iter()
        .map(|word| inclusion::shell_word(word))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A claim wait's `error` once the settlement paying for the bundle saved at
/// `saved` was sent: that payment stands, and only the saved bundle spends it.
fn unclaimed(error: anyhow::Error, tc: &TokenCtx, saved: &std::path::Path) -> anyhow::Error {
    anyhow::anyhow!(
        "{error:#}. The settlement was submitted and pays only for the bundle saved at {}: do \
         not run custom-mint again, which pays a new settlement. Finish this mint without \
         paying: {}",
        saved.display(),
        resume_command(&inclusion::program(), &tc.read_flags, saved)
    )
}

/// The settlement record's payment fields for `payment`'s payee and value.
pub(super) fn claimed_payment(
    payment: &Option<(RecipientAddress, u128)>,
) -> anyhow::Result<Option<([u8; 32], u128)>> {
    match payment {
        Some((payee, value)) => Ok(Some((
            quil_execution::token_intrinsic::settlement_record::payment_address(&payee.encode())?,
            *value,
        ))),
        None => Ok(None),
    }
}

/// Pay a QUIL settlement bound to `[claim, operation]` for the operation's
/// application, wait up to `wait` for its certification, and submit claim and
/// operation together. `payment` adds a public payment coin (a paid mint's
/// price). With `save`, the bundle is saved in the config directory before
/// the settlement is sent, for [`run_custom_mint_resume`].
pub(super) async fn submit_paid(
    tc: &TokenCtx,
    wallet: &RecipientWallet,
    bytes: Vec<u8>,
    payment: Option<(RecipientAddress, u128)>,
    wait: std::time::Duration,
    save: bool,
) -> anyhow::Result<Option<Submitted>> {
    let application = wallet.application;
    // Boxed: the payment and its claim make this future about 57 KB in a
    // debug build, and every wallet operation off QUIL awaits it, so inline
    // it outgrew the 2 MiB test-thread stack of callers that never reach it.
    Box::pin(submit_paid_with(
        tc,
        wallet,
        bytes,
        payment,
        wait,
        save,
        async |amount, binding, payment, before_submit| {
            run_pay(
                tc,
                application,
                amount,
                binding,
                None,
                payment,
                PAY_SCAN_BUDGET.0,
                PAY_SCAN_BUDGET.1,
                before_submit,
            )
            .await
        },
    ))
    .await
}

/// [`submit_paid`] with its payment made by `pay` (the wallet's [`run_pay`]
/// outside tests), given the amount, the binding, the payment coin and the
/// call to make before the settlement is sent.
pub(super) async fn submit_paid_with<Pay>(
    tc: &TokenCtx,
    wallet: &RecipientWallet,
    bytes: Vec<u8>,
    payment: Option<(RecipientAddress, u128)>,
    wait: std::time::Duration,
    save: bool,
    pay: Pay,
) -> anyhow::Result<Option<Submitted>>
where
    Pay: AsyncFnOnce(
        u128,
        SettlementBinding,
        Option<(RecipientAddress, u128)>,
        Option<&BeforeSubmit<'_>>,
    ) -> anyhow::Result<[u8; 32]>,
{
    let submitted = Submitted::of(&wallet.network, wallet.application, &bytes);
    let (domain, request) = wallet.prepare_submission(bytes.clone())?;
    let unpaid = PaidBundle {
        network: wallet.network,
        application: wallet.application,
        timestamp: crate::send::now_millis(),
        operation: bytes,
        receipt: [0; 32],
        settlement: 0,
        payment: claimed_payment(&payment)?,
        global_execution: false,
    };
    let quote = quote_bundle(tc, wallet.application, &unpaid.rest()?).await?;
    // A pre-funded settlement of this destination pays for the bundle without
    // a new transaction. One that also carries a payment coin is not reused:
    // the payment is part of the settlement, chosen when it was paid.
    if payment.is_none() {
        if let Some(claim) = claim_prefunded(tc, wallet.application, &quote, wait).await? {
            return send_claimed_bundle(
                tc,
                domain,
                request,
                claim,
                unpaid.timestamp,
                quote.global_execution,
                submitted,
            )
            .await;
        }
    }
    let unpaid = PaidBundle {
        settlement: quote.amount,
        global_execution: quote.global_execution,
        ..unpaid
    };
    let saved = std::sync::OnceLock::new();
    let dir = &tc.config_dir;
    let journal = |receipt: &[u8; 32]| -> anyhow::Result<()> {
        let paid = PaidBundle {
            receipt: *receipt,
            ..unpaid.clone()
        };
        let path = paid.save(dir)?;
        println!(
            "Saved the bundle this settlement pays for: {} (`custom-mint --resume` finishes it).",
            path.display()
        );
        let _ = saved.set(path);
        Ok(())
    };
    let receipt = pay(
        quote.amount,
        SettlementBinding::Bundle(quote.context),
        payment,
        save.then_some(&journal as &BeforeSubmit<'_>),
    )
    .await?;
    println!("Waiting for the settlement to be certified in global state...");
    let claim = settlement_claim(
        tc,
        wallet.application,
        receipt,
        quote.amount,
        &ClaimBinding::Bundle(quote.context),
        unpaid.payment,
        wait,
    )
    .await
    .map_err(|error| match saved.get() {
        Some(path) => unclaimed(error, tc, path),
        None => error,
    })?;
    send_claimed_bundle(
        tc,
        domain,
        request,
        claim,
        unpaid.timestamp,
        quote.global_execution,
        submitted,
    )
    .await
}

/// Submit `claim` and then `request`, the operation, as the bundle stamped
/// `timestamp` that the claim's settlement binds.
async fn send_claimed_bundle(
    tc: &TokenCtx,
    domain: Vec<u8>,
    request: quil_types::proto::global::MessageRequest,
    claim: Vec<u8>,
    timestamp: i64,
    global_execution: bool,
    mut submitted: Option<Submitted>,
) -> anyhow::Result<Option<Submitted>> {
    let bundle = quil_types::proto::global::MessageBundle {
        requests: vec![
            quil_types::proto::global::MessageRequest {
                request: Some(
                    quil_types::proto::global::message_request::Request::TokenOperation(
                        quil_types::proto::token::TokenOperation {
                            canonical_bytes: claim,
                        },
                    ),
                ),
                timestamp: 0,
            },
            request,
        ],
        timestamp,
    };
    if let Some(submitted) = &mut submitted {
        submitted.bundle = bundle_id(&bundle)?;
        if global_execution {
            submitted.route = inclusion::Route::Global;
        }
    }
    crate::send::send_to_venue(
        &mut crate::retry::connect(|| tc.connect_submit()).await?,
        &tc.submit_key_manager,
        domain,
        global_execution,
        bundle,
    )
    .await?;
    println!("Submitted with its QUIL settlement claim.");
    Ok(submitted)
}

/// Finish the custom mint whose bundle `token custom-mint` saved at `saved`
/// before paying: wait up to `wait` for its settlement to be certified, then
/// submit that bundle with its claim, and follow it. Pays nothing.
/// `application`, when given, must be the saved bundle's.
pub(in crate::commands::token) async fn run_custom_mint_resume(
    tc: &TokenCtx,
    application: Option<[u8; 32]>,
    saved: &std::path::Path,
    wait: std::time::Duration,
    follow: Follow,
) -> anyhow::Result<()> {
    let (wallet, submitted, paid) = resume(tc, application, saved, wait).await?;
    let what = if paid {
        "paid custom-token mint"
    } else {
        "custom-token mint"
    };
    inclusion::follow(tc, &wallet, what, submitted, follow).await
}

/// [`run_custom_mint_resume`] up to the submission; also whether the mint
/// paid a price.
pub(super) async fn resume(
    tc: &TokenCtx,
    application: Option<[u8; 32]>,
    saved: &std::path::Path,
    wait: std::time::Duration,
) -> anyhow::Result<(std::sync::Arc<RecipientWallet>, Option<Submitted>, bool)> {
    let paid = PaidBundle::load(saved)?;
    let network =
        quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    anyhow::ensure!(
        paid.network == network,
        "{} was saved on another network",
        saved.display()
    );
    if let Some(application) = application {
        anyhow::ensure!(
            application == paid.application,
            "{} mints application {}, not --application {}",
            saved.display(),
            hex::encode(paid.application),
            hex::encode(application)
        );
    }
    let wallet = std::sync::Arc::new(RecipientWallet::load(tc, &network, &paid.application)?);
    let (domain, request) = wallet.prepare_submission(paid.operation.clone())?;
    let context = paid.context()?;
    println!(
        "Resuming the bundle settlement {} pays for; nothing is paid again.",
        hex::encode(paid.receipt)
    );
    let claim = settlement_claim(
        tc,
        paid.application,
        paid.receipt,
        paid.settlement,
        &ClaimBinding::Bundle(context),
        paid.payment,
        wait,
    )
    .await
    .map_err(|error| unclaimed(error, tc, saved))?;
    let submitted = Submitted::of(&wallet.network, wallet.application, &paid.operation);
    let submitted = send_claimed_bundle(
        tc,
        domain,
        request,
        claim,
        paid.timestamp,
        paid.global_execution,
        submitted,
    )
    .await?;
    Ok((wallet, submitted, paid.payment.is_some()))
}
