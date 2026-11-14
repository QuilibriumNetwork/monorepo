//! Async action commands for the `prover manage` TUI. Port of
//! `manage_actions.go` + the RPC-driving `tea.Cmd`s in `manage_model.go`.
//!
//! Each function performs its RPC work and returns the corresponding
//! [`Msg`]; the event loop spawns them onto the message channel.

use std::sync::Arc;
use std::time::Duration;

use tonic::transport::Channel;

use quil_keys::FileKeyManager;
use quil_types::proto::global::{
    message_request::Request, MessageRequest, ProverLeave, ProverPause, ProverReject, ProverResume,
};
use quil_types::proto::node::{
    node_service_client::NodeServiceClient, GetNodeInfoRequest, GetShardInfoRequest,
    GetWorkerInfoRequest, NodeInfoResponse, RequestJoinRequest, SetManuallyManagedRequest,
};

use super::super::sign;
use super::model::{AwaitFilterEntry, FilterOutcome};
use super::msg::Msg;
use super::shield;
use super::util::{filters_label, trunc_hex};
use crate::commands::token::action_log::ActionLog;
use crate::context::GlobalArgs;

type Client = NodeServiceClient<Channel>;

/// Per-call deadline for every NodeService RPC (mirrors `rpcTimeout`).
pub(super) const RPC_TIMEOUT: Duration = Duration::from_secs(15);
/// Archive fallback can exceed the fast status deadline.
pub(super) const SHARD_RPC_TIMEOUT: Duration = Duration::from_secs(60);
/// Longer ceiling for RequestJoin (VDF on the node side).
const JOIN_RPC_TIMEOUT: Duration = Duration::from_secs(90);

/// `allocationStatusNames`.
fn status_name(status: u32) -> String {
    match status {
        0 => "Unknown".to_string(),
        1 => "Joining".to_string(),
        2 => "Active".to_string(),
        3 => "Paused".to_string(),
        4 => "Leaving".to_string(),
        5 => "Rejected".to_string(),
        6 => "Kicked".to_string(),
        n => format!("Unknown({n})"),
    }
}

/// Fetch an authenticated GLOBAL reward witness without waiting on coin scans.
pub async fn fetch_rewards(client: Client, km: Arc<FileKeyManager>) -> Msg {
    #[cfg(feature = "confidential-tokens")]
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let public = km.get_public_key_bytes_by_id("q-prover-key")?;
        crate::commands::token::balance::read_claimable_rewards(client, &public).await
    })
    .await
    .unwrap_or_else(|_| Err(anyhow::anyhow!("reward query timed out")))
    .map_err(|e| e.to_string());
    #[cfg(not(feature = "confidential-tokens"))]
    let result = {
        let _ = (client, km);
        Err("reward witness support unavailable".into())
    };
    Msg::RewardRefresh(result)
}

/// When a legacy read of the Coins tab gives up: once the node sends
/// nothing for `stall` (no page, nor the shard list after the last one),
/// or after `cap` in all. A listing's length follows the owner's coins (a
/// regular node forwards each page of 512 to an archive in about 0.7 s:
/// 3,000 coins take 5 s, 180,000 about 250 s), so only a stalled read
/// fails early.
#[derive(Clone, Copy, Debug)]
pub struct LegacyLimits {
    pub stall: Duration,
    pub cap: Duration,
}

/// A page the node is still retrying arrives within the channel's 120 s
/// call deadline, which ends a stuck call first; an hour lists over a
/// million coins at the pace above.
pub const LEGACY_LIMITS: LegacyLimits = LegacyLimits {
    stall: Duration::from_secs(120),
    cap: Duration::from_secs(3600),
};

/// Read the legacy coins of the identity with Ed448 key `public` (`None`:
/// the config has none, so it owns no legacy coins), sending
/// [`Msg::LegacyProgress`] to `progress` as pages arrive.
pub async fn fetch_legacy(
    client: Client,
    public: Option<[u8; 57]>,
    network: u8,
    config_dir: Option<std::path::PathBuf>,
    progress: tokio::sync::mpsc::UnboundedSender<Msg>,
) -> Msg {
    read_legacy(client, public, network, config_dir, progress, LEGACY_LIMITS).await
}

/// [`fetch_legacy`] within `limits`.
async fn read_legacy(
    client: Client,
    public: Option<[u8; 57]>,
    network: u8,
    config_dir: Option<std::path::PathBuf>,
    progress: tokio::sync::mpsc::UnboundedSender<Msg>,
    limits: LegacyLimits,
) -> Msg {
    let started = std::time::Instant::now();
    let answer = match public {
        None => Ok(None),
        Some(public) => {
            let (tick, ticks) = tokio::sync::watch::channel((0, 0));
            let mut report = move |pages: usize, coins: usize| {
                let _ = tick.send((pages, coins));
            };
            let read = crate::commands::token::legacy::snapshot(
                &client,
                &quil_execution::domains::QUIL_TOKEN,
                &public,
                network,
                config_dir.as_deref(),
                &mut report,
            );
            until_stalled(read, ticks, limits, |(pages, coins)| {
                let _ = progress.send(Msg::LegacyProgress { pages, coins });
            })
            .await
            .and_then(|read| read.map(Some).map_err(|e| format!("{e:#}")))
        }
    };
    Msg::LegacyRefresh {
        answer,
        took: started.elapsed(),
        mints: saved_mints(config_dir.as_deref(), network),
    }
}

/// Run `read` to its end unless `ticks`, its `(pages, coins)` so far, stays
/// unchanged for `limits.stall`, or `limits.cap` passes; `on_tick` gets
/// each new value. The error says which, and how far the read got.
async fn until_stalled<T>(
    read: impl std::future::Future<Output = T>,
    mut ticks: tokio::sync::watch::Receiver<(usize, usize)>,
    limits: LegacyLimits,
    mut on_tick: impl FnMut((usize, usize)),
) -> Result<T, String> {
    let started = tokio::time::Instant::now();
    let (mut last, mut open) = (started, true);
    let mut reported = None;
    tokio::pin!(read);
    loop {
        let wake = (last + limits.stall).min(started + limits.cap);
        tokio::select! {
            biased;
            out = &mut read => {
                // The read's last page can land with its result in one poll;
                // `biased` takes the result first, so report that page too.
                let now = *ticks.borrow();
                if now != (0, 0) && reported != Some(now) {
                    on_tick(now);
                }
                return Ok(out);
            }
            changed = ticks.changed(), if open => match changed {
                Ok(()) => {
                    last = tokio::time::Instant::now();
                    let now = *ticks.borrow_and_update();
                    reported = Some(now);
                    on_tick(now);
                }
                Err(_) => open = false,
            },
            () = tokio::time::sleep_until(wake) => {
                let (pages, coins) = *ticks.borrow();
                return Err(if wake >= started + limits.cap {
                    format!(
                        "not done within {} min, after {pages} pages ({coins} coins)",
                        limits.cap.as_secs() / 60
                    )
                } else {
                    format!(
                        "no answer for {}s after {pages} pages ({coins} coins)",
                        limits.stall.as_secs_f64()
                    )
                });
            }
        }
    }
}

/// The `mint-<frame>.bin` authorizations saved in `config_dir`.
fn saved_mints(config_dir: Option<&std::path::Path>, network: u8) -> Vec<super::mint::Saved> {
    #[cfg(feature = "confidential-tokens")]
    if let Some(dir) = config_dir {
        return crate::commands::token::saved_mints(dir, network)
            .into_iter()
            .map(|saved| super::mint::Saved {
                path: saved.path,
                cited_frame: saved.cited_frame,
                amounts: saved.amounts,
            })
            .collect();
    }
    let _ = (config_dir, network);
    Vec::new()
}

/// The reward mint's confirmation: this prover's reward read and checked
/// against its GLOBAL root and the fee quoted, as `token mint` does.
#[cfg(feature = "native-proof")]
pub async fn mint_prepare(token: Option<(GlobalArgs, u128)>) -> Msg {
    use crate::commands::token::{output, TokenCtx};
    let (notes, _ignored) = tokio::sync::mpsc::unbounded_channel();
    let result = output::capture(notes, async {
        let (global, max_fee) = token.ok_or_else(|| anyhow::anyhow!("no node config"))?;
        mint_preview(&TokenCtx::for_manager(global, max_fee)?).await
    })
    .await;
    Msg::MintPreview(result.map_err(|e| format!("{e:#}")))
}

#[cfg(feature = "native-proof")]
async fn mint_preview(
    tc: &crate::commands::token::TokenCtx,
) -> anyhow::Result<super::mint::Preview> {
    use crate::commands::token::{plan_mint, reward_mint_fee};
    // Before any quote or witness: a submission the node would refuse.
    check_identity(tc).await?;
    let fee = reward_mint_fee(tc, None).await?;
    let plan = plan_mint(tc, fee).await?;
    Ok(super::mint::Preview {
        stage: super::mint::Stage::Authorize,
        cited_frame: plan.cited_frame,
        reward: plan.reward,
        fee,
        max_fee: tc.max_fee,
        recipient: plan.own_address(),
    })
}

/// The claim's confirmation: the saved authorization's amounts and its
/// finalized GLOBAL witness, which the claim needs.
#[cfg(feature = "native-proof")]
pub async fn claim_prepare(
    token: Option<(GlobalArgs, u128)>,
    path: std::path::PathBuf,
    cited_frame: u64,
) -> Msg {
    use crate::commands::token::{output, TokenCtx};
    let (notes, _ignored) = tokio::sync::mpsc::unbounded_channel();
    let result = output::capture(notes, async {
        let (global, max_fee) = token.ok_or_else(|| anyhow::anyhow!("no node config"))?;
        claim_preview(&TokenCtx::for_manager(global, max_fee)?, path, cited_frame).await
    })
    .await;
    Msg::MintPreview(result.map_err(|e| format!("{e:#}")))
}

#[cfg(feature = "native-proof")]
async fn claim_preview(
    tc: &crate::commands::token::TokenCtx,
    path: std::path::PathBuf,
    cited_frame: u64,
) -> anyhow::Result<super::mint::Preview> {
    // Before any read: a submission the node would refuse.
    check_identity(tc).await?;
    let bytes = std::fs::read(&path)?;
    let (reward, fee) = saved_mints(Some(&tc.config_dir), tc.node_config.p2p.network)
        .into_iter()
        .find(|saved| saved.path == path)
        .and_then(|saved| saved.amounts)
        .ok_or_else(|| anyhow::anyhow!("{} is not a mint of this network", path.display()))?;
    let witness = crate::commands::token::mint_claim_witness(tc, &bytes)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the authorization citing f{cited_frame} is not finalized: GLOBAL holds no \
                 witness for it yet"
            )
        })?;
    Ok(super::mint::Preview {
        stage: super::mint::Stage::Claim { path, witness },
        cited_frame,
        reward,
        fee,
        max_fee: tc.max_fee,
        recipient: String::new(),
    })
}

/// Run the confirmed mint or claim through `token mint`'s own functions,
/// reporting on `progress` and recording it in the private action `log`.
/// A mint reads the reward and quotes the fee again ([`recheck`]): a
/// larger reward is minted, a changed fee comes back as a new
/// confirmation, a smaller reward stops it.
#[cfg(feature = "native-proof")]
pub async fn mint_run(
    token: Option<(GlobalArgs, u128)>,
    preview: super::mint::Preview,
    progress: tokio::sync::mpsc::UnboundedSender<Msg>,
    log: Option<ActionLog>,
) -> Msg {
    use crate::commands::token::action_log::ActionRecorder;
    use crate::commands::token::{output, TokenCtx};
    let (notes, mut lines) = tokio::sync::mpsc::unbounded_channel::<String>();
    let forward = progress.clone();
    tokio::spawn(async move {
        while let Some(line) = lines.recv().await {
            let _ = forward.send(Msg::Mint(super::mint::Progress::Note(line)));
        }
    });
    let result = output::capture(notes, async {
        let (global, max_fee) = token.ok_or_else(|| anyhow::anyhow!("no node config"))?;
        let kind = match preview.stage {
            super::mint::Stage::Authorize => "mint",
            super::mint::Stage::Claim { .. } => "mint_claim",
        };
        mint_execute(
            &TokenCtx::for_manager(global, max_fee)?,
            &preview,
            &progress,
            &mut ActionRecorder::new(log, kind, "manager"),
        )
        .await
    })
    .await;
    Msg::Mint(match result {
        Ok(Some(grown)) => super::mint::Progress::Requoted(grown),
        Ok(None) => super::mint::Progress::Done(Ok(())),
        Err(e) => super::mint::Progress::Done(Err(format!("{e:#}"))),
    })
}

/// The file name alone: the private log names the authorization, not the
/// config directory it lies in.
#[cfg(feature = "native-proof")]
fn file_name(path: &std::path::Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The private action log's start record of a mint or claim: what was
/// confirmed, to the base unit.
#[cfg(feature = "native-proof")]
fn mint_record(preview: &super::mint::Preview) -> serde_json::Value {
    let mut fields = serde_json::json!({
        "cited_frame": preview.cited_frame,
        "reward": preview.reward.to_string(),
        "fee": preview.fee.to_string(),
        "minted": preview.minted().to_string(),
        "max_fee": preview.max_fee.to_string(),
    });
    match &preview.stage {
        super::mint::Stage::Authorize => {
            fields["recipient"] = preview.recipient.clone().into();
        }
        super::mint::Stage::Claim { path, witness } => {
            fields["file"] = file_name(path).into();
            fields["witness_frame"] = (*witness).into();
        }
    }
    fields
}

/// Tell the manager the action log could not be written.
#[cfg(feature = "native-proof")]
fn mint_log_failed(progress: &tokio::sync::mpsc::UnboundedSender<Msg>, why: Option<String>) {
    if let Some(why) = why {
        let _ = progress.send(Msg::Mint(super::mint::Progress::LogFailed(why)));
    }
}

/// [`mint_run`]'s work with `tc`'s node and keys, recorded by `record`:
/// the confirmed inputs, the submission and the outcome. `Some` is a new
/// confirmation, as the fee quote changed since this one; nothing was
/// proved.
#[cfg(feature = "native-proof")]
async fn mint_execute(
    tc: &crate::commands::token::TokenCtx,
    preview: &super::mint::Preview,
    progress: &tokio::sync::mpsc::UnboundedSender<Msg>,
    record: &mut crate::commands::token::action_log::ActionRecorder,
) -> anyhow::Result<Option<super::mint::Preview>> {
    mint_log_failed(progress, record.write("start", mint_record(preview)));
    // Boxed, as are the stage's own large futures: polled inline they
    // overflow a 2 MiB thread stack in a debug build.
    let result = Box::pin(mint_stage(tc, preview, progress, record)).await;
    let written = match &result {
        Ok(Some(requoted)) => record.write(
            "outcome",
            serde_json::json!({
                "outcome": "requoted",
                "reason": "fee_changed",
                "cited_frame": requoted.cited_frame,
                "reward": requoted.reward.to_string(),
                "fee": requoted.fee.to_string(),
            }),
        ),
        _ => record.outcome(&result.as_ref().map(|_| ()).map_err(|e| format!("{e:#}"))),
    };
    mint_log_failed(progress, written);
    result
}

#[cfg(feature = "native-proof")]
async fn mint_stage(
    tc: &crate::commands::token::TokenCtx,
    preview: &super::mint::Preview,
    progress: &tokio::sync::mpsc::UnboundedSender<Msg>,
    record: &mut crate::commands::token::action_log::ActionRecorder,
) -> anyhow::Result<Option<super::mint::Preview>> {
    use crate::commands::token::{execute_mint, execute_mint_claim, MintEvent};
    let mut amounts = (preview.reward, preview.fee);
    let report = |event: MintEvent| {
        let (step, report) = mint_report(event, &mut amounts);
        if let Some((phase, fields)) = step {
            mint_log_failed(progress, record.write(phase, fields));
        }
        if let Some(report) = report {
            let _ = progress.send(Msg::Mint(report));
        }
    };
    match &preview.stage {
        super::mint::Stage::Claim { path, .. } => {
            Box::pin(execute_mint_claim(tc, path, report)).await?;
            Ok(None)
        }
        super::mint::Stage::Authorize => match Box::pin(mint_recheck(tc, preview)).await? {
            // To this wallet, as confirmed.
            Rechecked::Prove(plan) => {
                Box::pin(execute_mint(tc, plan, None, report)).await?;
                Ok(None)
            }
            Rechecked::Requote(requoted) => Ok(Some(requoted)),
        },
    }
}

/// A private action log step of a mint's `event` and the manager's report
/// of it. `amounts` holds the reward and fee the authorization announced
/// last (the confirmed ones until it does): more than the confirmed reward
/// when it grew before the run read it, which the submission reports.
#[cfg(feature = "native-proof")]
fn mint_report(
    event: crate::commands::token::MintEvent,
    amounts: &mut (u128, u128),
) -> (
    Option<(&'static str, serde_json::Value)>,
    Option<super::mint::Progress>,
) {
    use super::mint::Progress;
    use crate::commands::token::MintEvent;
    if let MintEvent::Amounts { reward, fee } = &event {
        *amounts = (*reward, *fee);
    }
    let (reward, fee) = *amounts;
    let step = match &event {
        MintEvent::Submitted { cited_frame, saved } => Some((
            "submitted",
            serde_json::json!({
                "cited_frame": cited_frame,
                "file": file_name(saved),
                "reward": reward.to_string(),
                "minted": reward.saturating_sub(fee).to_string(),
            }),
        )),
        MintEvent::Claimed => Some(("claimed", serde_json::json!({}))),
        MintEvent::Amounts { .. } | MintEvent::Proving => None,
    };
    let report = match event {
        MintEvent::Proving => Some(Progress::Proving),
        MintEvent::Submitted { cited_frame, saved } => Some(Progress::Submitted {
            cited_frame,
            reward,
            saved,
        }),
        MintEvent::Claimed => Some(Progress::Claimed),
        MintEvent::Amounts { .. } => event.cli_line().map(Progress::Note),
    };
    (step, report)
}

/// What a mint run does after reading the reward and quoting the fee
/// again.
#[cfg(feature = "native-proof")]
#[derive(Debug, PartialEq, Eq)]
enum Recheck {
    /// Prove the reward read now: the confirmed amount or more.
    Prove,
    /// Open a new confirmation: the fee quote changed.
    Requote,
}

/// What the run does with the reward read again (`reward` at
/// `cited_frame`) and the fee quoted again (`fee`) under `preview`'s
/// confirmation. A later GLOBAL frame is no change: one passes every 10 s.
/// A larger reward is none either: rewards grow every frame, so nearly
/// every run reads more than its confirmation showed; the run mints it
/// all to this wallet and its outcome names both amounts. A changed fee
/// needs a new confirmation, since the mint pays the fee confirmed; a
/// smaller reward stops the run.
#[cfg(feature = "native-proof")]
fn recheck(
    cited_frame: u64,
    reward: u128,
    fee: u128,
    preview: &super::mint::Preview,
) -> anyhow::Result<Recheck> {
    anyhow::ensure!(
        reward >= preview.reward,
        "the reward changed since it was confirmed (f{cited_frame}, {reward} base units now); \
         press ‹M› again"
    );
    Ok(if fee == preview.fee {
        Recheck::Prove
    } else {
        Recheck::Requote
    })
}

/// A mint run's reads before it proves anything.
#[cfg(feature = "native-proof")]
enum Rechecked {
    /// The reward read now, at the confirmed fee.
    Prove(crate::commands::token::MintPlan),
    /// A new confirmation, read and quoted as `M` does.
    Requote(super::mint::Preview),
}

/// Read the reward and quote the fee again for the confirmed `preview`,
/// as [`recheck`] decides.
#[cfg(feature = "native-proof")]
async fn mint_recheck(
    tc: &crate::commands::token::TokenCtx,
    preview: &super::mint::Preview,
) -> anyhow::Result<Rechecked> {
    use crate::commands::token::{plan_mint, reward_mint_fee};
    let plan = Box::pin(plan_mint(tc, preview.fee)).await?;
    let fee = Box::pin(reward_mint_fee(tc, None)).await?;
    let decision = recheck(plan.cited_frame, plan.reward, fee, preview)?;
    Ok(match decision {
        Recheck::Prove => Rechecked::Prove(plan),
        Recheck::Requote => {
            drop(plan);
            Rechecked::Requote(Box::pin(mint_preview(tc)).await?)
        }
    })
}

#[cfg(not(feature = "native-proof"))]
pub async fn mint_prepare(_token: Option<(GlobalArgs, u128)>) -> Msg {
    Msg::MintPreview(Err("this qclient build has no mint commands".into()))
}

#[cfg(not(feature = "native-proof"))]
pub async fn claim_prepare(
    _token: Option<(GlobalArgs, u128)>,
    _path: std::path::PathBuf,
    _cited_frame: u64,
) -> Msg {
    Msg::MintPreview(Err("this qclient build has no mint commands".into()))
}

#[cfg(not(feature = "native-proof"))]
pub async fn mint_run(
    _token: Option<(GlobalArgs, u128)>,
    _preview: super::mint::Preview,
    _progress: tokio::sync::mpsc::UnboundedSender<Msg>,
    _log: Option<ActionLog>,
) -> Msg {
    Msg::Mint(super::mint::Progress::Done(Err(
        "this qclient build has no mint commands".into(),
    )))
}

/// `token shield-all`'s batches for the shield confirmation: read, cut and
/// quoted as the CLI would, nothing proved or submitted. `token` is the
/// manager's global flags and `--max-fee`.
#[cfg(feature = "native-proof")]
pub async fn shield_prepare(token: Option<(GlobalArgs, u128)>) -> Msg {
    use crate::commands::token::{output, TokenCtx};
    // The CLI's progress lines would overwrite the screen.
    let (notes, _ignored) = tokio::sync::mpsc::unbounded_channel();
    let result = output::capture(notes, async {
        let (global, max_fee) = token.ok_or_else(|| anyhow::anyhow!("no node config"))?;
        shield_preview(&TokenCtx::for_manager(global, max_fee)?).await
    })
    .await;
    Msg::ShieldPreview(result.map_err(|e| format!("{e:#}")))
}

/// The fix for a submission signed by a config other than the running
/// node's: the manager has no `--submit-config`, and signs with the config
/// it loaded (`--network`, else the default config, else `./.config`).
#[cfg(feature = "native-proof")]
const MANAGER_CONFIG_REMEDY: &str = "start the manager with the running node's \
     config: --network <name> loads ~/.quilibrium/configs/<name>, and the node directory's \
     .config is used only when no default config exists";

/// Refuse, before any read, a submission the node would reject because
/// `tc` signs with another config than the node's own; the advice names the
/// manager's options.
#[cfg(feature = "native-proof")]
async fn check_identity(tc: &crate::commands::token::TokenCtx) -> anyhow::Result<()> {
    Box::pin(tc.check_submit_identity_advising(MANAGER_CONFIG_REMEDY)).await
}

/// [`shield_prepare`]'s reads and quotes with `tc`'s node and keys.
#[cfg(feature = "native-proof")]
async fn shield_preview(tc: &crate::commands::token::TokenCtx) -> anyhow::Result<shield::Preview> {
    use crate::commands::token::{plan_shield_all, shield_batch_fee};
    // Before any listing or proof: a submission the node would refuse.
    check_identity(tc).await?;
    let plan = plan_shield_all(tc, &quil_token(), shield::BATCH_COINS, None).await?;
    anyhow::ensure!(
        !plan.batches.is_empty(),
        "no unshielded legacy coins on a live shard to shield"
    );
    let (coins, units) = plan.totals()?;
    // One quote per batch size: the price follows the coin count.
    let mut quoted = std::collections::BTreeMap::new();
    let (mut fee, mut fee_max) = (0u128, 0u128);
    for batch in &plan.batches {
        let quote = match quoted.get(&batch.len()) {
            Some(quote) => *quote,
            None => {
                let quote = shield_batch_fee(tc, batch.len()).await?;
                quoted.insert(batch.len(), quote);
                quote
            }
        };
        fee = fee.saturating_add(quote);
        fee_max = fee_max.max(quote);
    }
    Ok(shield::Preview {
        batches: plan.batches.len(),
        coins,
        units,
        fee,
        fee_max,
        max_fee: tc.max_fee,
        recipient: plan.recipient(),
        listed: plan.listed,
        shielded: plan.shielded,
        uncovered: plan.uncovered,
        pending: plan.pending,
        duplicates: plan.duplicates,
    })
}

/// The manager paces its shield as `token shield-all` does by default.
#[cfg(feature = "native-proof")]
pub(crate) const PACING: crate::commands::token::shield_pacing::Pacing =
    crate::commands::token::shield_pacing::Pacing {
        min_interval: crate::commands::token::shield_pacing::DEFAULT_MIN_INTERVAL_SECS,
        inclusion_timeout: crate::commands::token::shield_pacing::DEFAULT_INCLUSION_TIMEOUT_SECS,
    };

/// Run the confirmed shield through the CLI's own functions, paced as
/// `token shield-all` paces it, reporting each step on `progress` and
/// recording the run in the private action `log`. The batches are read
/// again and must match what was confirmed; otherwise nothing is
/// submitted. Once `stop` is set the run submits nothing more and ends.
#[cfg(feature = "native-proof")]
pub async fn shield_run(
    token: Option<(GlobalArgs, u128)>,
    preview: shield::Preview,
    progress: tokio::sync::mpsc::UnboundedSender<Msg>,
    log: Option<ActionLog>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> Msg {
    use crate::commands::token::action_log::ShieldRecorder;
    use crate::commands::token::{output, TokenCtx};
    let (notes, mut lines) = tokio::sync::mpsc::unbounded_channel::<String>();
    let forward = progress.clone();
    tokio::spawn(async move {
        while let Some(line) = lines.recv().await {
            let _ = forward.send(Msg::Shield(shield::Progress::Note(line)));
        }
    });
    let result = output::capture(notes, async {
        let (global, max_fee) = token.ok_or_else(|| anyhow::anyhow!("no node config"))?;
        let tc = TokenCtx::for_manager(global, max_fee)?;
        shield_execute(
            &tc,
            &preview,
            &progress,
            &mut ShieldRecorder::new(log, "manager"),
            PACING,
            &stop,
        )
        .await
    })
    .await;
    Msg::Shield(shield::Progress::Done(result.map_err(|e| format!("{e:#}"))))
}

/// A paced run's report as the manager shows it; `None` for reports it
/// shows otherwise (the plan, repeated waits) or not at all.
#[cfg(feature = "native-proof")]
pub(crate) fn progress_of(
    report: crate::commands::token::ShieldReport<'_>,
) -> Option<shield::Progress> {
    use crate::commands::token::shield_pacing::ShieldEvent as Paced;
    use crate::commands::token::{ShieldEvent, ShieldReport};
    use shield::Progress;
    Some(match report {
        ShieldReport::Batch(ShieldEvent::Proving {
            index,
            count,
            coins,
        }) => Progress::Proving {
            index: *index,
            count: *count,
            coins: *coins,
        },
        ShieldReport::Batch(ShieldEvent::Proved { index, count }) => Progress::Proved {
            index: *index,
            count: *count,
        },
        ShieldReport::Batch(ShieldEvent::Skipped { index, count, .. }) => Progress::Skipped {
            index: *index,
            count: *count,
        },
        ShieldReport::Batch(ShieldEvent::Submitted {
            index,
            count,
            addresses,
            shielded,
            ..
        }) => Progress::Submitted {
            index: *index,
            count: *count,
            addresses: addresses.clone(),
            shielded: *shielded,
        },
        ShieldReport::Batch(ShieldEvent::Nothing { .. } | ShieldEvent::Uncovered(_)) => {
            return None
        }
        ShieldReport::Paced(Paced::WaitingInterval { index, total, secs }) => Progress::Spacing {
            index: index + 1,
            count: *total,
            secs: *secs,
        },
        ShieldReport::Paced(Paced::Included { index, total, .. }) => Progress::Included {
            index: index + 1,
            count: *total,
        },
        ShieldReport::Paced(Paced::Paused { reason, .. } | Paced::StillPaused { reason, .. }) => {
            Progress::Paused {
                reason: reason.clone(),
            }
        }
        ShieldReport::Paced(Paced::Resumed { paused_secs, .. }) => Progress::Resumed {
            paused_secs: *paused_secs,
        },
        ShieldReport::Paced(Paced::ShardGone {
            index,
            shard,
            submitted,
            ..
        }) => Progress::ShardGone {
            index: index + 1,
            shard: shard.clone(),
            submitted: submitted.is_some(),
        },
        ShieldReport::Paced(Paced::Progress { projected_end, .. }) => Progress::Projected {
            end: *projected_end,
        },
        ShieldReport::Paced(Paced::Stopped { submitted, .. }) => Progress::Stopped {
            submitted: *submitted,
        },
        // The batch events carry these; the TUI shows waits by their start.
        ShieldReport::Paced(
            Paced::Plan { .. }
            | Paced::Skipped { .. }
            | Paced::Submitted { .. }
            | Paced::WaitingInclusion { .. },
        ) => return None,
        ShieldReport::LogFailed(why) => Progress::LogFailed(why),
    })
}

/// [`shield_run`]'s work with `tc`'s node and keys, recorded by `record`:
/// the plan, each batch and the outcome.
#[cfg(feature = "native-proof")]
async fn shield_execute(
    tc: &crate::commands::token::TokenCtx,
    preview: &shield::Preview,
    progress: &tokio::sync::mpsc::UnboundedSender<Msg>,
    record: &mut crate::commands::token::action_log::ShieldRecorder,
    pacing: crate::commands::token::shield_pacing::Pacing,
    stop: &std::sync::atomic::AtomicBool,
) -> anyhow::Result<()> {
    use crate::commands::token::{execute_shield_all, ShieldReport};
    let mut sink = |report: ShieldReport<'_>| {
        if let Some(report) = progress_of(report) {
            let _ = progress.send(Msg::Shield(report));
        }
    };
    let plan = match confirmed_plan(tc, preview).await {
        Ok(plan) => plan,
        Err(error) => {
            if let Some(why) = record.outcome(&Err(format!("{error:#}"))) {
                sink(ShieldReport::LogFailed(why));
            }
            return Err(error);
        }
    };
    execute_shield_all(tc, plan, pacing, record, Some(stop), &mut sink)
        .await
        .map(|_| ())
}

/// The batches read again, refused unless they are what was confirmed.
#[cfg(feature = "native-proof")]
async fn confirmed_plan(
    tc: &crate::commands::token::TokenCtx,
    preview: &shield::Preview,
) -> anyhow::Result<crate::commands::token::ShieldAllPlan> {
    use crate::commands::token::plan_shield_all;
    let plan = plan_shield_all(tc, &quil_token(), shield::BATCH_COINS, None).await?;
    let (coins, units) = plan.totals()?;
    anyhow::ensure!(
        plan.batches.len() == preview.batches && coins == preview.coins && units == preview.units,
        "the plan changed since it was confirmed ({} batches of {coins} coins now); press ‹S› \
         again",
        plan.batches.len()
    );
    Ok(plan)
}

#[cfg(feature = "native-proof")]
fn quil_token() -> String {
    hex::encode(quil_execution::domains::QUIL_TOKEN)
}

/// This build has no shield commands.
#[cfg(not(feature = "native-proof"))]
pub async fn shield_prepare(_token: Option<(GlobalArgs, u128)>) -> Msg {
    Msg::ShieldPreview(Err("this qclient build has no shield commands".into()))
}

#[cfg(not(feature = "native-proof"))]
pub async fn shield_run(
    _token: Option<(GlobalArgs, u128)>,
    _preview: shield::Preview,
    _progress: tokio::sync::mpsc::UnboundedSender<Msg>,
    _log: Option<ActionLog>,
    _stop: Arc<std::sync::atomic::AtomicBool>,
) -> Msg {
    Msg::Shield(shield::Progress::Done(Err(
        "this qclient build has no shield commands".into(),
    )))
}

/// Wallet reads that check a coin's or an escrow's state by its address
/// go to this node only: a public or custom RPC the qclient config names
/// would learn which coins and escrows are this wallet's.
#[cfg(feature = "confidential-tokens")]
fn own_node_only(tc: &crate::commands::token::TokenCtx) -> anyhow::Result<()> {
    anyhow::ensure!(
        !tc.connect_opts.is_light_node(),
        "the qclient config reads through a public or custom RPC (publicRpc, customRpc), which \
         would learn this wallet's coins; the manager reads them from this node only"
    );
    Ok(())
}

/// The shielded side of this wallet: its unspent confidential coins and
/// the pending transfers it can act on, as `token balance` and `token
/// escrows` read them. Both are full scans matched on this machine; the
/// spent and consumed checks of what matched read this node's GLOBAL
/// state, never another node.
pub async fn fetch_shielded(token: Option<(GlobalArgs, u128)>) -> Msg {
    #[cfg(feature = "confidential-tokens")]
    let result = {
        use crate::commands::token::{output, TokenCtx};
        let (notes, _ignored) = tokio::sync::mpsc::unbounded_channel();
        output::capture(notes, async {
            let (global, max_fee) = token.ok_or_else(|| anyhow::anyhow!("no node config"))?;
            shielded_read(&TokenCtx::for_manager(global, max_fee)?).await
        })
        .await
        .map_err(|e| read_failure(&e))
    };
    #[cfg(not(feature = "confidential-tokens"))]
    let result = {
        let _ = token;
        let failed = "this qclient build has no confidential tokens".to_string();
        Err(super::transfer::ReadFailure::Failed(failed))
    };
    Msg::Shielded(result)
}

/// A failed read as the manager's notices tell it. A scan stopped by the
/// node's snapshot age stops the same way when read again; another names
/// where it stopped and why, and the notice adds what to do.
#[cfg(feature = "confidential-tokens")]
fn read_failure(error: &anyhow::Error) -> super::transfer::ReadFailure {
    use super::transfer::ReadFailure;
    match error.downcast_ref::<crate::commands::token::ScanStopped>() {
        Some(stopped) => match stopped.outlived() {
            Some(minutes) => ReadFailure::Outlived { minutes },
            None => ReadFailure::Failed(stopped.cause()),
        },
        None => ReadFailure::Failed(format!("{error:#}")),
    }
}

#[cfg(feature = "confidential-tokens")]
async fn shielded_read(
    tc: &crate::commands::token::TokenCtx,
) -> anyhow::Result<super::transfer::Read> {
    use crate::commands::token::{SCAN_MAX_COINS, SCAN_PAGES_UNCAPPED};
    shielded_read_within(tc, SCAN_PAGES_UNCAPPED, SCAN_MAX_COINS).await
}

/// [`shielded_read`] within a page cap and a limit on the coins and on the
/// pending transfers it keeps. The coins are read first and kept when the
/// pending transfers' read fails, which the read then carries.
#[cfg(feature = "confidential-tokens")]
async fn shielded_read_within(
    tc: &crate::commands::token::TokenCtx,
    max_pages: usize,
    max_kept: usize,
) -> anyhow::Result<super::transfer::Read> {
    use crate::commands::token::{confidential_balance, list_escrows};
    own_node_only(tc)?;
    let (coins, skipped) = confidential_balance(tc, max_pages, max_kept).await?;
    let application = hex::encode(quil_execution::domains::QUIL_TOKEN);
    let (escrows, escrows_skipped, escrows_failed) =
        match list_escrows(tc, &application, max_pages, max_kept).await {
            Ok((escrows, skipped)) => (escrows, skipped, None),
            Err(error) => (Vec::new(), Default::default(), Some(read_failure(&error))),
        };
    Ok(super::transfer::Read {
        coins,
        skipped: super::transfer::Skipped {
            mismatched: skipped.mismatched,
            duplicates: skipped.duplicates,
            limited: skipped.limited,
            escrows: escrows_skipped.limited,
            escrows_mismatched: escrows_skipped.mismatched,
        },
        escrows_failed,
        escrows: escrows
            .into_iter()
            .map(|escrow| super::transfer::Escrow {
                address: escrow.address,
                amount: escrow.amount,
                outgoing: escrow.refund,
                refund_after: escrow.refund_after,
            })
            .collect(),
    })
}

/// A transfer action's confirmation: its inputs checked and its fee quoted
/// as `qclient token` would; a merge also scans the coins it would take.
#[cfg(feature = "native-proof")]
pub async fn transfer_prepare(
    token: Option<(GlobalArgs, u128)>,
    kind: super::transfer::Kind,
) -> Msg {
    use crate::commands::token::{output, TokenCtx};
    let (notes, _ignored) = tokio::sync::mpsc::unbounded_channel();
    let result = output::capture(notes, async {
        let (global, max_fee) = token.ok_or_else(|| anyhow::anyhow!("no node config"))?;
        transfer_preview(&TokenCtx::for_manager(global, max_fee)?, kind).await
    })
    .await;
    Msg::TransferPreview(result.map_err(|e| format!("{e:#}")))
}

#[cfg(feature = "native-proof")]
async fn transfer_preview(
    tc: &crate::commands::token::TokenCtx,
    kind: super::transfer::Kind,
) -> anyhow::Result<super::transfer::Preview> {
    use super::transfer::Kind;
    use crate::commands::token::{
        check_recipient, claim_fee, max_inputs, merge_fee, merge_preview, pending_fee, transfer_fee,
    };
    // Before any request: reads that would name this wallet's coins to
    // another node; then before any check or quote, a submission the node
    // would refuse.
    own_node_only(tc)?;
    check_identity(tc).await?;
    let app = quil_token();
    let mut merge = None;
    let fee = match &kind {
        Kind::Transfer { recipient, .. } => {
            check_recipient(tc, recipient, false)?;
            transfer_fee(
                tc,
                &quil_execution::domains::QUIL_TOKEN,
                None,
                max_inputs(tc),
            )
            .await?
        }
        Kind::Pending { recipient, .. } => {
            check_recipient(tc, recipient, true)?;
            pending_fee(tc, &app, None).await?
        }
        Kind::Accept { .. } | Kind::Refund { .. } => claim_fee(tc, &app, None).await?,
        Kind::Merge => {
            let fee = merge_fee(tc, &app, None).await?;
            let (coins, total) = merge_preview(tc).await?;
            anyhow::ensure!(
                coins >= 2,
                "{coins} coin(s) to merge; a merge needs two or more"
            );
            anyhow::ensure!(total > fee, "the coins to merge do not cover the fee");
            merge = Some((coins, total));
            fee
        }
    };
    Ok(super::transfer::Preview {
        kind,
        fee,
        max_fee: tc.max_fee,
        merge,
    })
}

/// Run the confirmed action through `qclient token`'s own function,
/// reporting its lines on `progress` and recording it in the private action
/// `log`.
#[cfg(feature = "native-proof")]
pub async fn transfer_run(
    token: Option<(GlobalArgs, u128)>,
    preview: super::transfer::Preview,
    progress: tokio::sync::mpsc::UnboundedSender<Msg>,
    log: Option<ActionLog>,
) -> Msg {
    use crate::commands::token::action_log::ActionRecorder;
    use crate::commands::token::{output, TokenCtx};
    let (notes, mut lines) = tokio::sync::mpsc::unbounded_channel::<String>();
    let forward = progress.clone();
    tokio::spawn(async move {
        while let Some(line) = lines.recv().await {
            let _ = forward.send(Msg::Transfer(super::transfer::Progress::Note(line)));
        }
    });
    let result = output::capture(notes, async {
        let (global, max_fee) = token.ok_or_else(|| anyhow::anyhow!("no node config"))?;
        let tc = TokenCtx::for_manager(global, max_fee)?;
        let mut record = ActionRecorder::new(log, preview.kind.log_name(), "manager");
        transfer_execute(&tc, &preview, &progress, &mut record).await
    })
    .await;
    Msg::Transfer(super::transfer::Progress::Done(
        result.map_err(|e| format!("{e:#}")),
    ))
}

/// The private action log's start record of a transfer action: what was
/// confirmed, to the base unit.
#[cfg(feature = "native-proof")]
fn transfer_record(preview: &super::transfer::Preview) -> serde_json::Value {
    use super::transfer::Kind;
    let mut fields = serde_json::json!({
        "fee": preview.fee.to_string(),
        "max_fee": preview.max_fee.to_string(),
    });
    match &preview.kind {
        Kind::Transfer { recipient, amount } => {
            fields["recipient"] = recipient.clone().into();
            fields["amount"] = amount.to_string().into();
        }
        Kind::Pending {
            recipient,
            amount,
            refund_after,
        } => {
            fields["recipient"] = recipient.clone().into();
            fields["amount"] = amount.to_string().into();
            fields["refund_after"] = (*refund_after).into();
        }
        Kind::Accept { escrow, amount } | Kind::Refund { escrow, amount } => {
            fields["escrow"] = hex::encode(escrow).into();
            fields["amount"] = amount.to_string().into();
        }
        Kind::Merge => {
            if let Some((coins, total)) = preview.merge {
                fields["coins"] = coins.into();
                fields["amount"] = total.to_string().into();
            }
        }
    }
    fields
}

/// [`transfer_run`]'s work with `tc`'s node and keys, recorded by `record`:
/// the confirmed inputs and the outcome.
#[cfg(feature = "native-proof")]
async fn transfer_execute(
    tc: &crate::commands::token::TokenCtx,
    preview: &super::transfer::Preview,
    progress: &tokio::sync::mpsc::UnboundedSender<Msg>,
    record: &mut crate::commands::token::action_log::ActionRecorder,
) -> anyhow::Result<()> {
    let failed = |why: Option<String>| {
        if let Some(why) = why {
            let _ = progress.send(Msg::Transfer(super::transfer::Progress::LogFailed(why)));
        }
    };
    failed(record.write("start", transfer_record(preview)));
    let result = transfer_action(tc, preview).await;
    let outcome = result.as_ref().map(|_| ()).map_err(|e| format!("{e:#}"));
    failed(record.outcome(&outcome));
    result
}

#[cfg(feature = "native-proof")]
async fn transfer_action(
    tc: &crate::commands::token::TokenCtx,
    preview: &super::transfer::Preview,
) -> anyhow::Result<()> {
    use super::transfer::Kind;
    use crate::commands::token::{
        run_claim, run_merge, run_pending_create, run_transfer, Follow, SCAN_MAX_COINS,
        SCAN_PAGES_UNCAPPED,
    };
    // The manager prints each submission's identifiers into its notice and
    // leaves the wait to the operator (`token inclusion`, named in the notice).
    const NO_WAIT: std::time::Duration = std::time::Duration::ZERO;
    let no_follow = || Follow {
        wait: NO_WAIT,
        max_pages: SCAN_PAGES_UNCAPPED,
    };
    own_node_only(tc)?;
    let app = quil_token();
    match &preview.kind {
        // As `token transfer` without --fee: quoted again, rebuilt if the
        // price moves, always under --max-fee.
        Kind::Transfer { recipient, amount } => {
            run_transfer(
                tc,
                &app,
                recipient,
                *amount,
                None,
                SCAN_PAGES_UNCAPPED,
                SCAN_MAX_COINS,
                NO_WAIT,
            )
            .await
        }
        Kind::Pending {
            recipient,
            amount,
            refund_after,
        } => {
            run_pending_create(
                tc,
                &app,
                recipient,
                *amount,
                preview.fee,
                *refund_after,
                SCAN_PAGES_UNCAPPED,
                SCAN_MAX_COINS,
                NO_WAIT,
            )
            .await
        }
        Kind::Accept { escrow, .. } => {
            run_claim(
                tc,
                &app,
                &hex::encode(escrow),
                preview.fee,
                false,
                no_follow(),
            )
            .await
        }
        Kind::Refund { escrow, .. } => {
            run_claim(
                tc,
                &app,
                &hex::encode(escrow),
                preview.fee,
                true,
                no_follow(),
            )
            .await
        }
        Kind::Merge => {
            run_merge(
                tc,
                &app,
                &["all".to_string()],
                preview.fee,
                SCAN_PAGES_UNCAPPED,
                SCAN_MAX_COINS,
                NO_WAIT,
            )
            .await
        }
    }
}

#[cfg(not(feature = "native-proof"))]
pub async fn transfer_prepare(
    _token: Option<(GlobalArgs, u128)>,
    _kind: super::transfer::Kind,
) -> Msg {
    Msg::TransferPreview(Err("this qclient build has no transfer commands".into()))
}

#[cfg(not(feature = "native-proof"))]
pub async fn transfer_run(
    _token: Option<(GlobalArgs, u128)>,
    _preview: super::transfer::Preview,
    _progress: tokio::sync::mpsc::UnboundedSender<Msg>,
    _log: Option<ActionLog>,
) -> Msg {
    Msg::Transfer(super::transfer::Progress::Done(Err(
        "this qclient build has no transfer commands".into(),
    )))
}

// ── Data fetch ───────────────────────────────────────────────────────────

/// `fetchRPCData` — GetNodeInfo (required), GetShardInfo + GetWorkerInfo
/// (optional, nil-on-error).
async fn fetch_rpc_data(
    client: &mut Client,
) -> Result<
    (
        NodeInfoResponse,
        Option<quil_types::proto::node::GetShardInfoResponse>,
        Option<quil_types::proto::node::WorkerInfoResponse>,
    ),
    String,
> {
    let node_info = match tokio::time::timeout(
        RPC_TIMEOUT,
        client.get_node_info(tonic::Request::new(GetNodeInfoRequest::default())),
    )
    .await
    {
        Ok(Ok(r)) => r.into_inner(),
        Ok(Err(e)) => return Err(format!("GetNodeInfo: {e}")),
        Err(_) => return Err("GetNodeInfo: timed out".to_string()),
    };

    let shard_info = match tokio::time::timeout(
        RPC_TIMEOUT,
        client.get_shard_info(tonic::Request::new(GetShardInfoRequest {
            include_all: true,
        })),
    )
    .await
    {
        Ok(Ok(r)) => Some(r.into_inner()),
        _ => None,
    };

    let worker_info = match tokio::time::timeout(
        RPC_TIMEOUT,
        client.get_worker_info(tonic::Request::new(GetWorkerInfoRequest::default())),
    )
    .await
    {
        Ok(Ok(r)) => Some(r.into_inner()),
        _ => None,
    };

    Ok((node_info, shard_info, worker_info))
}

/// Fetch fast node/worker status independently of archive-backed shard sizes.
pub async fn fetch_data(mut client: Client) -> Msg {
    let node_info = match tokio::time::timeout(
        RPC_TIMEOUT,
        client.get_node_info(tonic::Request::new(GetNodeInfoRequest::default())),
    )
    .await
    {
        Ok(Ok(r)) => r.into_inner(),
        result => {
            return Msg::DataRefresh {
                node_info: None,
                shard_info: None,
                worker_info: None,
                err: Some(match result {
                    Ok(Err(e)) => format!("GetNodeInfo: {e}"),
                    _ => "GetNodeInfo: timed out".into(),
                }),
            }
        }
    };
    let worker_info = match tokio::time::timeout(
        RPC_TIMEOUT,
        client.get_worker_info(tonic::Request::new(GetWorkerInfoRequest::default())),
    )
    .await
    {
        Ok(Ok(r)) => Some(r.into_inner()),
        _ => None,
    };
    Msg::DataRefresh {
        node_info: Some(node_info),
        shard_info: None,
        worker_info,
        err: None,
    }
}

// ── Health report ────────────────────────────────────────────────────────

/// The node's health conditions, or why there are none. A node without the
/// diagnostics service, or whose report has no conditions, predates them:
/// the node manager judges none in its place.
pub async fn fetch_health(
    source: Result<crate::commands::node::diagnostics::HealthSource, String>,
) -> Msg {
    use super::model::HealthAnswer;
    let answer = match source {
        Err(reason) => HealthAnswer::Failed(reason),
        Ok(source) => match source.read().await {
            Ok(Some(health)) => HealthAnswer::Reported(health),
            Ok(None) => HealthAnswer::NotReported,
            Err(reason) => HealthAnswer::Failed(reason),
        },
    };
    Msg::HealthRefresh(answer)
}

/// Keep the shard query bounded, report failure explicitly, and allow node
/// status to refresh meanwhile.
pub async fn fetch_shards(mut client: Client) -> Msg {
    let result = tokio::time::timeout(
        SHARD_RPC_TIMEOUT,
        client.get_shard_info(tonic::Request::new(GetShardInfoRequest {
            include_all: true,
        })),
    )
    .await;
    Msg::ShardRefresh(match result {
        Ok(Ok(r)) => Ok(r.into_inner()),
        Ok(Err(e)) => Err(format!("Shard data unavailable: {e}")),
        Err(_) => Err(format!(
            "Shard data timed out after {}s; retrying",
            SHARD_RPC_TIMEOUT.as_secs()
        )),
    })
}

/// `getFrameNumber` — current frame from GetShardInfo (the sign frame).
async fn get_frame_number(client: &mut Client) -> Result<u64, String> {
    match tokio::time::timeout(
        RPC_TIMEOUT,
        client.get_shard_info(tonic::Request::new(GetShardInfoRequest::default())),
    )
    .await
    {
        Ok(Ok(r)) => Ok(r.into_inner().frame_number),
        Ok(Err(e)) => Err(format!("get frame number: {e}")),
        Err(_) => Err("get frame number: timed out".to_string()),
    }
}

// ── Join ─────────────────────────────────────────────────────────────────

/// `doJoin` — RequestJoin RPC (VDF runs node-side; longer timeout).
pub async fn do_join(mut client: Client, filters: Vec<Vec<u8>>) -> Msg {
    let label = format!("{} filter(s)", filters.len());
    let err = match tokio::time::timeout(
        JOIN_RPC_TIMEOUT,
        client.request_join(tonic::Request::new(RequestJoinRequest {
            filters: filters.clone(),
            delegate: Vec::new(),
            worker_ids: Vec::new(),
        })),
    )
    .await
    {
        Ok(Ok(_)) => None,
        Ok(Err(e)) => Some(e.to_string()),
        Err(_) => Some("RequestJoin timed out".to_string()),
    };
    Msg::ActionResult {
        action: "Join".to_string(),
        filter: label,
        filters_raw: filters,
        err,
    }
}

// ── Signed lifecycle ops (Leave / Confirm / Reject / Pause / Resume) ─────

/// Build the signed `MessageRequest` for a lifecycle action.
#[allow(deprecated)] // ProverReject.filter is a deprecated wire field.
fn build_request(
    km: &FileKeyManager,
    action: &str,
    filters: &[Vec<u8>],
    frame: u64,
) -> anyhow::Result<MessageRequest> {
    let request = match action {
        "Leave" => {
            let sig = sign::leave_sig(km, filters, frame)?;
            Request::Leave(ProverLeave {
                filters: filters.to_vec(),
                frame_number: frame,
                public_key_signature_bls48581: Some(sig),
            })
        }
        "Confirm" => Request::Confirm(sign::confirm_op(km, filters, frame)?),
        "Reject" => {
            let sig = sign::reject_sig(km, filters, frame)?;
            Request::Reject(ProverReject {
                filter: Vec::new(),
                frame_number: frame,
                public_key_signature_bls48581: Some(sig),
                filters: filters.to_vec(),
            })
        }
        "Pause" => {
            let filter = filters.first().cloned().unwrap_or_default();
            let sig = sign::pause_sig(km, &filter, frame)?;
            Request::Pause(ProverPause {
                filter,
                frame_number: frame,
                public_key_signature_bls48581: Some(sig),
            })
        }
        "Resume" => {
            let filter = filters.first().cloned().unwrap_or_default();
            let sig = sign::resume_sig(km, &filter, frame)?;
            Request::Resume(ProverResume {
                filter,
                frame_number: frame,
                public_key_signature_bls48581: Some(sig),
            })
        }
        other => anyhow::bail!("unknown lifecycle action {other}"),
    };
    Ok(MessageRequest {
        timestamp: 0,
        request: Some(request),
    })
}

/// `doLeave`/`doConfirm`/`doReject`/`doPause`/`doResume` + `sendAction`
/// collapsed: fetch the sign frame, build+sign the message, and broadcast
/// it over the global domain.
pub async fn do_lifecycle(
    mut client: Client,
    km: Arc<FileKeyManager>,
    waits: super::super::EpochWaits,
    action: String,
    filters: Vec<Vec<u8>>,
    original_status: u32,
    progress: tokio::sync::mpsc::UnboundedSender<Msg>,
) -> Msg {
    let label = if action == "Pause" || action == "Resume" {
        trunc_hex(&hex::encode(filters.first().cloned().unwrap_or_default()))
    } else {
        filters_label(&filters)
    };

    let _ = label; // label mirrors Go's status string; unused in the Rust flow.

    // Every node refuses one of these landing in a later epoch than it was
    // signed in, so it signs once this node no longer holds prover ops for
    // the next epoch. A confirm or reject is valid only in this epoch and
    // goes at once.
    if matches!(action.as_str(), "Leave" | "Pause" | "Resume") {
        if let Err(e) = super::super::frame_clear_of_epoch_end(
            &mut client,
            &waits,
            super::super::EPOCH_END_WAIT_CAP,
            super::super::EPOCH_END_POLL,
            |frames_left| {
                let _ = progress.send(Msg::SigningWait {
                    action: action.clone(),
                    frames_left,
                });
            },
        )
        .await
        {
            return broadcast_err(&action, &filters, original_status, e.to_string());
        }
    }

    let frame = match get_frame_number(&mut client).await {
        Ok(f) => f,
        Err(e) => {
            return broadcast_err(&action, &filters, original_status, e);
        }
    };

    let request = match build_request(&km, &action, &filters, frame) {
        Ok(r) => r,
        Err(e) => {
            return broadcast_err(&action, &filters, original_status, e.to_string());
        }
    };

    let global_domain = vec![0xFFu8; 32];
    let send = tokio::time::timeout(
        RPC_TIMEOUT,
        crate::send::send_message_request(&mut client, &km, global_domain, request),
    )
    .await;
    let err = match send {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e.to_string()),
        Err(_) => Some("broadcast timed out".to_string()),
    };

    Msg::ActionBroadcast {
        action,
        filters_raw: filters,
        send_frame: frame,
        original_status,
        err,
    }
}

fn broadcast_err(action: &str, filters: &[Vec<u8>], original_status: u32, err: String) -> Msg {
    Msg::ActionBroadcast {
        action: action.to_string(),
        filters_raw: filters.to_vec(),
        send_frame: 0,
        original_status,
        err: Some(err),
    }
}

// ── Worker manual-management ─────────────────────────────────────────────

/// `doToggleManual`.
pub async fn do_toggle_manual(mut client: Client, core_id: u32, manual: bool) -> Msg {
    let err = match tokio::time::timeout(
        RPC_TIMEOUT,
        client.set_manually_managed(tonic::Request::new(SetManuallyManagedRequest {
            core_id,
            manually_managed: manual,
        })),
    )
    .await
    {
        Ok(Ok(_)) => None,
        Ok(Err(e)) => Some(e.to_string()),
        Err(_) => Some("timed out".to_string()),
    };
    Msg::ToggleManual {
        core_id,
        new_state: manual,
        err,
    }
}

/// `doMarkWorkersManual` — mark several workers manual (parallel batch).
pub async fn do_mark_workers_manual(client: Client, worker_ids: Vec<u32>) -> Msg {
    let mut handles = Vec::new();
    for id in worker_ids.clone() {
        let mut c = client.clone();
        handles.push(tokio::spawn(async move {
            let r = tokio::time::timeout(
                RPC_TIMEOUT,
                c.set_manually_managed(tonic::Request::new(SetManuallyManagedRequest {
                    core_id: id,
                    manually_managed: true,
                })),
            )
            .await;
            let ok = matches!(r, Ok(Ok(_)));
            (id, ok, format!("{r:?}"))
        }));
    }
    let mut failed = Vec::new();
    let mut first_err = None;
    for h in handles {
        if let Ok((id, ok, dbg)) = h.await {
            if !ok {
                failed.push(id);
                if first_err.is_none() {
                    first_err = Some(dbg);
                }
            }
        }
    }
    Msg::MarkManual {
        worker_ids,
        failed_ids: failed,
        err: first_err,
    }
}

// ── Await confirm ────────────────────────────────────────────────────────

/// `checkAllocationStatus` — poll the node once and resolve each awaited
/// filter's outcome.
pub async fn check_allocation_status(
    mut client: Client,
    action: String,
    entries: Vec<AwaitFilterEntry>,
) -> Msg {
    let (node_info, shard_info, _worker_info) = match fetch_rpc_data(&mut client).await {
        Ok(t) => t,
        Err(e) => {
            return Msg::AwaitResult {
                action,
                frame: 0,
                err: Some(e),
                per_filter: Vec::new(),
            };
        }
    };

    let current_frame = shard_info.as_ref().map(|s| s.frame_number).unwrap_or(0);

    let mut by_filter: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for a in &node_info.shard_allocations {
        by_filter.insert(hex::encode(&a.filter), a.status);
    }

    let outcomes: Vec<FilterOutcome> = entries
        .iter()
        .map(|e| {
            let key = hex::encode(&e.filter);
            match by_filter.get(&key) {
                None => FilterOutcome {
                    filter: e.filter.clone(),
                    outcome: "Removed".to_string(),
                    settled: true,
                },
                Some(&st) if st != e.original_status => FilterOutcome {
                    filter: e.filter.clone(),
                    outcome: status_name(st),
                    settled: true,
                },
                Some(_) => FilterOutcome {
                    filter: e.filter.clone(),
                    outcome: String::new(),
                    settled: false,
                },
            }
        })
        .collect();

    Msg::AwaitResult {
        action,
        frame: current_frame,
        err: None,
        per_filter: outcomes,
    }
}

/// The shield action end to end against a node double: reads, batches and
/// quotes for the confirmation, then the run, whose quotes exceed every
/// batch so nothing is proved or submitted.
#[cfg(all(test, feature = "native-proof"))]
mod shield_action_tests {
    use super::*;
    use quil_types::store::{CoinWitnessProvider, LegacyCoinData, LegacyCoinPageData};
    use std::collections::HashMap;

    struct Coins(HashMap<[u8; 32], Vec<LegacyCoinData>>);
    impl CoinWitnessProvider for Coins {
        fn legacy_coins(
            &self,
            _domain: &[u8; 32],
            owner: &[u8; 32],
            after: Option<&[u8; 32]>,
        ) -> quil_types::error::Result<Option<LegacyCoinPageData>> {
            let coins: Vec<LegacyCoinData> = self
                .0
                .get(owner)
                .into_iter()
                .flatten()
                .filter(|coin| after.is_none_or(|after| coin.address > *after))
                .cloned()
                .collect();
            Ok(Some(LegacyCoinPageData {
                cursor: coins.last().map(|coin| coin.address),
                coins,
                has_more: false,
            }))
        }
    }

    /// One live shard: the QUIL root, which covers every address.
    struct Root;
    impl quil_types::consensus::ShardInfoProvider for Root {
        fn get_shard_info(
            &self,
            _include_all: bool,
        ) -> quil_types::error::Result<(
            Vec<quil_types::consensus::ShardDetail>,
            u64,
            num_bigint::BigInt,
            u64,
            num_bigint::BigInt,
        )> {
            Ok((
                vec![quil_types::consensus::ShardDetail {
                    allocation_reason: None,
                    ring_known: true,
                    filter: quil_execution::domains::QUIL_TOKEN.to_vec(),
                    shard_size: 0.into(),
                    active_provers: 8,
                    ring: 0,
                    estimated_reward: 0.into(),
                    is_allocated: false,
                    data_shards: 1,
                    materialized_frame: 1,
                    latest_frame: 1,
                    prover_counts: None,
                }],
                0,
                0.into(),
                1,
                0.into(),
            ))
        }
    }

    /// The manager's leave, as it builds it, passes the verifier every node
    /// runs: it signs through the command's `leave_sig`.
    #[test]
    fn the_managers_leave_passes_the_network_verifier() {
        use quil_execution::global_intrinsic::{
            conversions, prover_filter_ops::ProverLeave as CanonicalLeave, verify,
        };
        let directory = tempfile::tempdir().unwrap();
        let km = FileKeyManager::new(
            directory.path().join("keys.yml"),
            "",
            "q-prover-key".into(),
            Box::new(quil_crypto::FalconKeyConstructor),
        )
        .unwrap();
        km.create_falcon_key("q-prover-key").unwrap();
        let pubkey = km
            .get_signer_by_id("q-prover-key")
            .unwrap()
            .public_key()
            .to_vec();
        let mut tree = quil_tries::VectorCommitmentTree::new();
        quil_execution::global_schema::write_type(&mut tree, "prover:Prover").unwrap();
        quil_execution::global_schema::write_field(
            &mut tree,
            "prover:Prover",
            "PublicKey",
            &pubkey,
        )
        .unwrap();
        let filters = vec![vec![0x08; 32], vec![0x09; 40]];
        let request = super::build_request(&km, "Leave", &filters, 777).unwrap();
        let Some(quil_types::proto::global::message_request::Request::Leave(pb)) = request.request
        else {
            panic!("a leave request");
        };
        let wire = conversions::prover_leave_from_proto(&pb)
            .to_canonical_bytes()
            .unwrap();
        let op = CanonicalLeave::from_canonical_bytes(&wire).unwrap();
        assert!(
            verify::verify_prover_leave(&op, &tree, &quil_crypto::DefaultKeyManager::new())
                .unwrap()
        );
    }

    #[tokio::test]
    async fn s_previews_and_runs_through_the_cli_functions() {
        let directory = tempfile::tempdir().unwrap();
        let km = Arc::new(
            FileKeyManager::new(
                directory.path().join("keys.yml"),
                &hex::encode([9; 32]),
                "q-prover-key".into(),
                Box::new(quil_crypto::FalconKeyConstructor),
            )
            .unwrap(),
        );
        km.create_agreement_key("q-onion-key", 9).unwrap();
        let seed = [55; 57];
        let public = quil_crypto::Ed448Signer::derive_public(&seed).unwrap();
        let mut node_config = quil_config::Config::default();
        node_config.p2p.peer_priv_key = hex::encode([&seed[..], &public[..]].concat());
        let owners =
            crate::commands::token::legacy::key_owners(&public.as_slice().try_into().unwrap())
                .unwrap();
        // Three coins under the key owner, one shielded already; another
        // under the peer-id owner.
        let coin = |byte: u8, shielded| LegacyCoinData {
            address: [byte; 32],
            amount: 5,
            origin: [byte ^ 0xff; 32],
            shielded,
        };
        let coins = Coins(HashMap::from([
            (
                owners[0].1,
                vec![coin(0x10, false), coin(0x20, true), coin(0x30, false)],
            ),
            (owners[1].1, vec![coin(0x40, false)]),
        ]));
        let network = quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(
            node_config.p2p.network,
        )
        .network;
        // The node reports a peer ID; a context with none to compare skips
        // the identity check, one signing as another peer is refused below.
        let server = quil_rpc::node_service::NodeRpcServer::new()
            .with_peer_id("the-node-peer".into())
            .with_coin_witness_provider(Arc::new(coins))
            .with_shard_info_provider(Arc::new(Root))
            .with_token_fee_provider(Arc::new(move |_, _| {
                // A small world: each byte of growth costs far more than
                // the five-unit coins, so every batch is skipped unproved.
                Ok(quil_rpc::node_service::TokenFeeSnapshot {
                    network,
                    observed_frame: 42,
                    global_execution: true,
                    difficulty: 50_000,
                    world_state_bytes: 1 << 24,
                    fee_multiplier_vote: 1,
                })
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let multiaddr = format!(
            "/ip4/127.0.0.1/tcp/{}",
            listener.local_addr().unwrap().port()
        );
        let incoming = futures::stream::unfold(listener, |listener| async {
            let result = listener.accept().await.map(|(socket, _)| socket);
            Some((result, listener))
        });
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    quil_types::proto::node::node_service_server::NodeServiceServer::new(server),
                )
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        let opts = crate::rpc::ConnectOpts {
            listen_grpc_multiaddr: multiaddr,
            ..Default::default()
        };
        let tc = crate::commands::token::TokenCtx {
            node_config,
            config_dir: directory.path().to_path_buf(),
            key_manager: km.clone(),
            connect_opts: opts.clone(),
            submit_opts: opts,
            submit_key_manager: km,
            submit_config_dir: directory.path().to_path_buf(),
            submit_identity: Default::default(),
            peer_id_bytes: Vec::new(),
            max_fee: u128::MAX,
            read_flags: Vec::new(),
        };
        let (notes, mut lines) = tokio::sync::mpsc::unbounded_channel();
        let preview = crate::commands::token::output::capture(notes, shield_preview(&tc))
            .await
            .unwrap();
        assert_eq!(
            (
                preview.batches,
                preview.coins,
                preview.units,
                preview.uncovered
            ),
            (1, 3, 15, 0)
        );
        // Every listed coin is in a batch or named as left out.
        assert_eq!((preview.listed, preview.shielded), (4, 1));
        assert_eq!(
            preview.coins
                + preview.shielded
                + preview.uncovered
                + preview.pending
                + preview.duplicates,
            preview.listed
        );
        assert!(preview.fee > preview.units && preview.fee == preview.fee_max);
        assert!(preview.recipient.starts_with("0x") && preview.recipient.len() > 66);
        // The fee estimate went to the sink, not the terminal.
        assert!(lines.try_recv().unwrap().starts_with("Estimated fee: "));

        // The run: the model sees the batch skipped and the run end.
        let mut m = super::super::model::Model::new();
        m.coins.shield.dialog = Some(shield::Dialog::Confirm(preview.clone()));
        let cmds = shield::dialog_key(
            &mut m,
            crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('y')),
        );
        assert!(matches!(
            cmds.as_slice(),
            [super::super::update::Cmd::ShieldRun(_)]
        ));
        let (progress, mut reports) = tokio::sync::mpsc::unbounded_channel();
        let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
        let log = ActionLog::new(directory.path());
        let recorder = || {
            crate::commands::token::action_log::ShieldRecorder::new(Some(log.clone()), "manager")
        };
        let halt = std::sync::atomic::AtomicBool::new(false);
        let result = crate::commands::token::output::capture(
            notes,
            shield_execute(&tc, &preview, &progress, &mut recorder(), PACING, &halt),
        )
        .await;
        drop(progress);
        super::super::update::apply_msg(
            &mut m,
            Msg::Shield(shield::Progress::Done(result.map_err(|e| format!("{e:#}")))),
        );
        let mut seen = Vec::new();
        while let Some(Msg::Shield(report)) = reports.recv().await {
            seen.push(report.clone());
            super::super::update::apply_msg(&mut m, Msg::Shield(report));
        }
        assert_eq!(seen, [shield::Progress::Skipped { index: 1, count: 1 }]);
        assert!(!shield::running(&m));
        let run = m.coins.shield.run.as_ref().unwrap();
        assert_eq!((run.skipped, run.submitted.len()), (1, 0));
        assert_eq!(run.done, Some(Ok(())));
        // Nothing went into shield-all's journal.
        assert!(!directory
            .path()
            .join(crate::commands::token::legacy::SHIELD_JOURNAL)
            .exists());
        // The private action log has the plan, the skipped batch and the
        // outcome, with the details the operator log leaves out.
        let records = || -> Vec<serde_json::Value> {
            std::fs::read_to_string(log.path())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        };
        let written = records();
        let phases: Vec<&str> = written
            .iter()
            .map(|r| r["phase"].as_str().unwrap())
            .collect();
        assert_eq!(phases, ["start", "skipped", "outcome"]);
        assert!(written
            .iter()
            .all(|r| r["kind"] == "shield" && r["source"] == "manager"));
        assert_eq!(written[0]["recipient"], preview.recipient.as_str());
        assert_eq!(
            (written[0]["coins"].as_u64(), written[0]["units"].as_str()),
            (Some(3), Some("15"))
        );
        assert_eq!(written[1]["units"], "15");
        assert_eq!(written[2]["outcome"], "ok");

        // A changed plan between confirmation and run submits nothing.
        let mut stale = preview.clone();
        stale.coins = 4;
        let (progress, _reports) = tokio::sync::mpsc::unbounded_channel();
        let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
        let error = crate::commands::token::output::capture(
            notes,
            shield_execute(&tc, &stale, &progress, &mut recorder(), PACING, &halt),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("the plan changed"), "{error}");
        let last = records().pop().unwrap();
        assert_eq!(last["phase"], "outcome");
        assert_eq!(last["outcome"], "failed");
        assert!(last["error"].as_str().unwrap().contains("the plan changed"));

        // `--recipient`, as `token shield-all` passes it: the plan and the
        // paced run's private log name that address, not this wallet's.
        let address = tc.another_quil_address();
        assert_ne!(address, preview.recipient);
        let plan = crate::commands::token::plan_shield_all(
            &tc,
            &quil_token(),
            shield::BATCH_COINS,
            Some(&address),
        )
        .await
        .unwrap();
        assert_eq!(plan.recipient(), address);
        let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
        let submitted = crate::commands::token::output::capture(
            notes,
            crate::commands::token::execute_shield_all(
                &tc,
                plan,
                PACING,
                &mut recorder(),
                None,
                &mut |_| {},
            ),
        )
        .await
        .unwrap();
        assert_eq!(submitted, 0);
        let written = records();
        let start = written
            .iter()
            .rfind(|r| r["phase"] == "start")
            .expect("the run logged its start");
        assert_eq!(start["recipient"], address.as_str());

        // Signed as another peer, the confirmation is refused before any
        // listing, as `token shield-all` refuses it.
        let other = crate::commands::token::TokenCtx {
            submit_identity: crate::commands::token::ConfigIdentity {
                falcon: Some("another-peer".into()),
                ed448: None,
            },
            ..tc
        };
        let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
        let error = crate::commands::token::output::capture(notes, shield_preview(&other))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("own peer key"), "{error}");
        // The advice names the manager's options, not the CLI's.
        assert!(
            error.contains("start the manager with the running node's config: --network <name>"),
            "{error}"
        );
        assert!(!error.contains("--submit-config"), "{error}");
        stop.send(()).unwrap();
        serving.await.unwrap();
    }
}

/// The mint action end to end against a node double serving a real GLOBAL
/// reward witness: the confirmation's reads and quote, and the run's check
/// that the reward did not change. Nothing is proved or submitted.
#[cfg(all(test, feature = "native-proof"))]
mod mint_action_tests {
    use super::*;
    use quil_types::store::{CoinWitnessProvider, RewardWitnessData};

    struct Rewards(RewardWitnessData);
    impl CoinWitnessProvider for Rewards {
        fn prover_reward_witness(
            &self,
            _domain: &[u8],
            _owner: &[u8],
        ) -> quil_types::error::Result<RewardWitnessData> {
            Ok(self.0.clone())
        }
    }

    async fn node(
        reward: u128,
        km: &FileKeyManager,
    ) -> (crate::rpc::ConnectOpts, tokio::sync::oneshot::Sender<()>) {
        let public = km.get_public_key_bytes_by_id("q-prover-key").unwrap();
        let owner = quil_crypto::poseidon::hash_bytes_to_32(&public).unwrap();
        let witness = crate::commands::token::balance::tests::reward_witness(owner, reward);
        let network =
            quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(0).network;
        // The node reports a peer ID, so a context signing as another peer
        // is refused.
        let server = quil_rpc::node_service::NodeRpcServer::new()
            .with_peer_id("the-node-peer".into())
            .with_coin_witness_provider(Arc::new(Rewards(witness)))
            .with_token_fee_provider(Arc::new(move |_, _| {
                Ok(quil_rpc::node_service::TokenFeeSnapshot {
                    network,
                    observed_frame: 42,
                    global_execution: true,
                    difficulty: 50_000,
                    world_state_bytes: 1 << 40,
                    fee_multiplier_vote: 1,
                })
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let multiaddr = format!(
            "/ip4/127.0.0.1/tcp/{}",
            listener.local_addr().unwrap().port()
        );
        let incoming = futures::stream::unfold(listener, |listener| async {
            let result = listener.accept().await.map(|(socket, _)| socket);
            Some((result, listener))
        });
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    quil_types::proto::node::node_service_server::NodeServiceServer::new(server),
                )
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        (
            crate::rpc::ConnectOpts {
                listen_grpc_multiaddr: multiaddr,
                ..Default::default()
            },
            stop,
        )
    }

    #[tokio::test]
    async fn m_previews_the_reward_and_the_run_refuses_a_changed_one() {
        let directory = tempfile::tempdir().unwrap();
        let km = Arc::new(
            FileKeyManager::new(
                directory.path().join("keys.yml"),
                &hex::encode([9; 32]),
                "q-prover-key".into(),
                Box::new(quil_crypto::FalconKeyConstructor),
            )
            .unwrap(),
        );
        km.create_agreement_key("q-onion-key", 9).unwrap();
        km.create_falcon_key("q-prover-key").unwrap();
        let reward = 80_000_000_000u128;
        let (opts, stop) = node(reward, &km).await;
        let tc = crate::commands::token::TokenCtx {
            node_config: quil_config::Config::default(),
            config_dir: directory.path().to_path_buf(),
            key_manager: km.clone(),
            connect_opts: opts.clone(),
            submit_opts: opts,
            submit_key_manager: km,
            submit_config_dir: directory.path().to_path_buf(),
            submit_identity: Default::default(),
            peer_id_bytes: Vec::new(),
            max_fee: crate::commands::token::DEFAULT_MAX_AUTOMATIC_FEE,
            read_flags: Vec::new(),
        };
        let (notes, mut lines) = tokio::sync::mpsc::unbounded_channel();
        let preview = crate::commands::token::output::capture(notes, mint_preview(&tc))
            .await
            .unwrap();
        assert_eq!(preview.stage, super::super::mint::Stage::Authorize);
        assert_eq!((preview.cited_frame, preview.reward), (42, reward));
        assert!(preview.fee > 0 && preview.fee < reward, "{}", preview.fee);
        assert!(preview.recipient.starts_with("0x"));
        assert!(lines.try_recv().unwrap().starts_with("Estimated fee: "));
        // A reward of another amount by the run's read is refused before
        // any proof, and the private action log records the confirmed
        // inputs and the refusal.
        let log = ActionLog::new(directory.path());
        let records = || -> Vec<serde_json::Value> {
            std::fs::read_to_string(log.path())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        };
        // A reward that grew since the confirmation, at the fee quoted
        // then, is the one the run proves: no new confirmation.
        let grown = super::super::mint::Preview {
            reward: reward - 5,
            cited_frame: 41,
            ..preview.clone()
        };
        let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
        let rechecked = crate::commands::token::output::capture(notes, mint_recheck(&tc, &grown))
            .await
            .unwrap();
        match rechecked {
            Rechecked::Prove(plan) => assert_eq!(
                (plan.cited_frame, plan.reward, plan.fee),
                (42, reward, preview.fee)
            ),
            Rechecked::Requote(again) => panic!("a grown reward re-confirmed: {again:?}"),
        }
        // A fee quoted otherwise than confirmed comes back as a new
        // confirmation of the amount and fee read now; nothing is proved.
        let quoted_otherwise = super::super::mint::Preview {
            fee: preview.fee + 1,
            ..grown.clone()
        };
        // Checked first, so a run that would prove fails here instead.
        let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
        let rechecked =
            crate::commands::token::output::capture(notes, mint_recheck(&tc, &quoted_otherwise))
                .await
                .unwrap();
        match rechecked {
            Rechecked::Requote(again) => assert_eq!(again, preview),
            Rechecked::Prove(_) => panic!("a changed fee proved"),
        }
        let (progress, _reports) = tokio::sync::mpsc::unbounded_channel();
        let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
        let mut record = crate::commands::token::action_log::ActionRecorder::new(
            Some(log.clone()),
            "mint",
            "manager",
        );
        let again = crate::commands::token::output::capture(
            notes,
            mint_execute(&tc, &quoted_otherwise, &progress, &mut record),
        )
        .await
        .unwrap()
        .expect("a new confirmation");
        assert_eq!(again, preview);
        let written = records();
        assert_eq!(written.len(), 2, "{written:?}");
        assert_eq!(
            (&written[0]["phase"], &written[0]["fee"]),
            (
                &serde_json::json!("start"),
                &serde_json::json!((preview.fee + 1).to_string())
            )
        );
        assert_eq!(written[1]["phase"], "outcome");
        assert_eq!(written[1]["outcome"], "requoted");
        assert_eq!(written[1]["reason"], "fee_changed");
        assert_eq!(written[1]["fee"], preview.fee.to_string());
        assert_eq!(written[1]["reward"], reward.to_string());
        std::fs::remove_file(log.path()).unwrap();
        let stale = super::super::mint::Preview {
            reward: reward + 1,
            ..preview.clone()
        };
        // Checked first, so a run that would prove fails here instead.
        let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
        let rechecked =
            crate::commands::token::output::capture(notes, mint_recheck(&tc, &stale)).await;
        assert!(rechecked.is_err(), "a smaller reward ran");
        let (progress, _reports) = tokio::sync::mpsc::unbounded_channel();
        let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
        let mut record = crate::commands::token::action_log::ActionRecorder::new(
            Some(log.clone()),
            "mint",
            "manager",
        );
        let error = crate::commands::token::output::capture(
            notes,
            mint_execute(&tc, &stale, &progress, &mut record),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("the reward changed"), "{error}");
        let records = records();
        let phases: Vec<&str> = records
            .iter()
            .map(|r| r["phase"].as_str().unwrap())
            .collect();
        assert_eq!(phases, ["start", "outcome"]);
        assert!(records
            .iter()
            .all(|r| r["kind"] == "mint" && r["source"] == "manager"));
        assert_eq!(records[0]["recipient"], preview.recipient.as_str());
        assert_eq!(records[0]["reward"], (reward + 1).to_string());
        assert_eq!(records[0]["cited_frame"], 42);
        assert_eq!(records[1]["outcome"], "failed");
        assert!(records[1]["error"]
            .as_str()
            .unwrap()
            .contains("the reward changed"));
        // Signed as another peer, both stages are refused before any read,
        // as `token mint` refuses them.
        let other = crate::commands::token::TokenCtx {
            submit_identity: crate::commands::token::ConfigIdentity {
                falcon: Some("another-peer".into()),
                ed448: None,
            },
            ..tc
        };
        for result in [
            {
                let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
                crate::commands::token::output::capture(notes, mint_preview(&other)).await
            },
            {
                let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
                crate::commands::token::output::capture(
                    notes,
                    claim_preview(&other, directory.path().join("mint-42.bin"), 42),
                )
                .await
            },
        ] {
            let error = result.unwrap_err().to_string();
            assert!(error.contains("own peer key"), "{error}");
            assert!(!error.contains("--submit-config"), "{error}");
        }
        stop.send(()).unwrap();
    }
}

#[cfg(test)]
mod legacy_read_tests {
    use super::*;
    use quil_types::store::{CoinWitnessProvider, LegacyCoinData, LegacyCoinPageData};
    use tokio::sync::watch;
    use tokio::time::Instant;

    const LIMITS: LegacyLimits = LEGACY_LIMITS;

    /// The last page and the read's result can land in one poll: the read
    /// is ready and the watch holds a page no tick reported. The page is
    /// still reported, so the progress shown ends at the read's total.
    #[tokio::test(start_paused = true)]
    async fn a_last_page_landing_with_the_result_is_reported() {
        let (tick, ticks) = watch::channel((0, 0));
        tick.send_replace((31, 15_872));
        let mut seen = Vec::new();
        let out = until_stalled(async { 7 }, ticks, LIMITS, |p| seen.push(p)).await;
        assert_eq!(out, Ok(7));
        assert_eq!(seen, vec![(31, 15_872)]);
    }

    /// A read sending `pages` pages of 512 coins, one every `every`, then
    /// `after`: a snapshot's calls after its last page.
    async fn paging<T>(
        tick: watch::Sender<(usize, usize)>,
        pages: usize,
        every: Duration,
        after: impl std::future::Future<Output = T>,
    ) -> T {
        for page in 1..=pages {
            tokio::time::sleep(every).await;
            tick.send_replace((page, page * 512));
        }
        after.await
    }

    /// A listing of 347 pages of 0.72 s each, 250 s, as a regular node
    /// lists 177,000 coins. A fixed 120 s limit on the whole read, as the
    /// Coins tab had, cuts it every time; a read that keeps paging is
    /// never cut, and each page reaches the tab.
    #[tokio::test(start_paused = true)]
    async fn a_long_listing_that_keeps_paging_is_read_to_its_end() {
        let every = Duration::from_millis(720);
        let (tick, _) = watch::channel((0, 0));
        let fixed = tokio::time::timeout(
            Duration::from_secs(120),
            paging(tick, 347, every, async { 347 }),
        );
        assert!(fixed.await.is_err(), "a fixed 120 s limit cuts it");
        let started = Instant::now();
        let (tick, ticks) = watch::channel((0, 0));
        let mut seen = Vec::new();
        let read = until_stalled(
            paging(tick, 347, every, async {
                tokio::time::sleep(every).await;
                "listed"
            }),
            ticks,
            LIMITS,
            |tick| seen.push(tick),
        );
        assert_eq!(read.await, Ok("listed"));
        assert!(started.elapsed() >= Duration::from_secs(249));
        assert_eq!(seen.len(), 347);
        assert_eq!(seen.last(), Some(&(347, 347 * 512)));
    }

    /// A read whose node stops answering fails once nothing came for the
    /// stall window, naming how far it got; one that keeps answering
    /// without end fails at the cap.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_or_endless_read_fails_and_says_how_far_it_got() {
        let started = Instant::now();
        let (tick, ticks) = watch::channel((0, 0));
        let read = until_stalled(
            paging(
                tick,
                10,
                Duration::from_millis(720),
                std::future::pending::<()>(),
            ),
            ticks,
            LIMITS,
            |_| {},
        );
        assert_eq!(
            read.await,
            Err("no answer for 120s after 10 pages (5120 coins)".into())
        );
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(127_200) && took < Duration::from_secs(128),
            "{took:?}"
        );
        let started = Instant::now();
        let (tick, ticks) = watch::channel((0, 0));
        let read = until_stalled(
            paging(tick, usize::MAX, Duration::from_secs(1), async {}),
            ticks,
            LIMITS,
            |_| {},
        );
        let error = read.await.unwrap_err();
        assert!(
            error.starts_with("not done within 60 min, after "),
            "{error}"
        );
        let took = started.elapsed();
        assert!(
            took >= Duration::from_secs(3600) && took < Duration::from_secs(3601),
            "{took:?}"
        );
    }

    /// One owner's legacy coins in full pages, each after `latency`: a
    /// regular node forwarding each page to an archive.
    struct SlowIndex {
        owner: [u8; 32],
        coins: Vec<LegacyCoinData>,
        latency: Duration,
    }

    impl CoinWitnessProvider for SlowIndex {
        fn legacy_coins(
            &self,
            _domain: &[u8; 32],
            owner: &[u8; 32],
            after: Option<&[u8; 32]>,
        ) -> quil_types::error::Result<Option<LegacyCoinPageData>> {
            std::thread::sleep(self.latency);
            let rest: Vec<LegacyCoinData> = if *owner == self.owner {
                self.coins
                    .iter()
                    .filter(|coin| after.is_none_or(|after| coin.address > *after))
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            };
            let max = quil_types::store::MAX_LEGACY_COINS_PER_PAGE;
            let coins: Vec<LegacyCoinData> = rest.iter().take(max).cloned().collect();
            Ok(Some(LegacyCoinPageData {
                cursor: coins.last().map(|coin| coin.address),
                has_more: rest.len() > max,
                coins,
            }))
        }
    }

    /// Over loopback gRPC, at a hundredth of the time scale: 15,360 coins
    /// in 31 pages of 100 ms take about 3 s, twice a 1.5 s stall window,
    /// as a 250 s listing is twice the tab's former 120 s limit. The tab gets each page's progress, then the coins.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_coins_tab_reads_thousands_of_legacy_coins_paging_slowly() {
        let public = [7u8; 57];
        let owners = crate::commands::token::legacy::key_owners(&public).unwrap();
        let coins: Vec<LegacyCoinData> = (1..=15_360u32)
            .map(|i| {
                let mut address = [0u8; 32];
                address[28..].copy_from_slice(&i.to_be_bytes());
                LegacyCoinData {
                    address,
                    amount: 1,
                    origin: [9; 32],
                    shielded: false,
                }
            })
            .collect();
        let provider = Arc::new(SlowIndex {
            owner: owners[0].1,
            coins,
            latency: Duration::from_millis(100),
        });
        let server =
            quil_rpc::node_service::NodeRpcServer::new().with_coin_witness_provider(provider);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let multiaddr = format!(
            "/ip4/127.0.0.1/tcp/{}",
            listener.local_addr().unwrap().port()
        );
        let incoming = futures::stream::unfold(listener, |listener| async {
            let result = listener.accept().await.map(|(socket, _)| socket);
            Some((result, listener))
        });
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    quil_types::proto::node::node_service_server::NodeServiceServer::new(server),
                )
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        });
        let client = crate::rpc::connect_node_service(&crate::rpc::ConnectOpts {
            listen_grpc_multiaddr: multiaddr,
            ..Default::default()
        })
        .await
        .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let limits = LegacyLimits {
            stall: Duration::from_millis(1500),
            cap: Duration::from_secs(60),
        };
        let started = std::time::Instant::now();
        let Msg::LegacyRefresh { answer, .. } =
            read_legacy(client, Some(public), 0, None, tx, limits).await
        else {
            panic!("a legacy read answers with LegacyRefresh");
        };
        let snapshot = answer.unwrap().unwrap();
        assert!(
            started.elapsed() > limits.stall,
            "the read outlasts the window"
        );
        assert_eq!((snapshot.tally.unshielded, snapshot.pages), (15_360, 31));
        let mut progress = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            if let Msg::LegacyProgress { pages, coins } = msg {
                progress.push((pages, coins));
            }
        }
        assert!(progress.len() >= 2, "{progress:?}");
        assert!(progress.windows(2).all(|w| w[0] <= w[1]), "{progress:?}");
        assert_eq!(progress.last(), Some(&(31, 15_360)));
    }
}

#[cfg(test)]
mod epoch_end_tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use std::time::Duration;

    /// The manager holds a leave, pause or resume near the epoch's end, and a
    /// confirm or reject, valid only in this epoch, goes on at once (here to the
    /// frame read, which this node has no provider for).
    #[tokio::test]
    async fn the_manager_signs_clear_of_the_end_of_an_epoch() {
        let directory = tempfile::tempdir().unwrap();
        let km = Arc::new(
            FileKeyManager::new(
                directory.path().join("keys.yml"),
                "",
                "q-prover-key".into(),
                Box::new(quil_crypto::FalconKeyConstructor),
            )
            .unwrap(),
        );
        let length = quil_types::consensus::epoch_length_frames();
        let mut server = quil_rpc::NodeRpcServer::default();
        server.last_global_head_frame = Arc::new(AtomicU64::new(length - 1));
        let head = server.last_global_head_frame.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let multiaddr = format!(
            "/ip4/127.0.0.1/tcp/{}",
            listener.local_addr().unwrap().port()
        );
        let incoming = futures::stream::unfold(listener, |listener| async {
            let result = listener.accept().await.map(|(socket, _)| socket);
            Some((result, listener))
        });
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    quil_types::proto::node::node_service_server::NodeServiceServer::new(server),
                )
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        });
        let client = crate::rpc::connect_node_service(&crate::rpc::ConnectOpts {
            listen_grpc_multiaddr: multiaddr,
            ..Default::default()
        })
        .await
        .unwrap();
        let (progress, mut notices) = tokio::sync::mpsc::unbounded_channel();
        let waits = super::super::super::tests::node_waits(head.clone());
        let run = |action: &str| {
            tokio::time::timeout(
                Duration::from_secs(1),
                do_lifecycle(
                    client.clone(),
                    km.clone(),
                    waits.clone(),
                    action.to_string(),
                    vec![vec![0xAA; 32]],
                    2,
                    progress.clone(),
                ),
            )
        };
        for held in ["Leave", "Pause", "Resume"] {
            assert!(run(held).await.is_err(), "{held} waits for the next epoch");
            match notices.try_recv() {
                Ok(Msg::SigningWait {
                    action,
                    frames_left,
                }) => assert_eq!((action.as_str(), frames_left), (held, 1)),
                _ => panic!("{held} says nothing while it waits"),
            }
            assert!(notices.try_recv().is_err(), "{held} says it once");
        }
        for at_once in ["Confirm", "Reject"] {
            assert!(run(at_once).await.is_ok(), "{at_once} does not wait");
            assert!(notices.try_recv().is_err(), "{at_once} has no wait to tell");
        }
    }
}

#[cfg(test)]
mod lifecycle_request_tests {
    use super::*;
    use quil_execution::global_intrinsic::{conversions, prover_filter_ops, prover_ops, verify};

    fn prover_tree(pubkey: &[u8]) -> quil_tries::VectorCommitmentTree {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        quil_execution::global_schema::write_type(&mut tree, "prover:Prover").unwrap();
        quil_execution::global_schema::write_field(&mut tree, "prover:Prover", "PublicKey", pubkey)
            .unwrap();
        tree
    }

    fn allocation_tree(status: u8) -> quil_tries::VectorCommitmentTree {
        let class = "allocation:ProverAllocation";
        let mut tree = quil_tries::VectorCommitmentTree::new();
        quil_execution::global_schema::write_type(&mut tree, class).unwrap();
        quil_execution::global_schema::write_field(&mut tree, class, "Status", &[status]).unwrap();
        tree
    }

    /// Confirm, reject, pause and resume as the manager builds them, through
    /// their wire encoding and the verifier every node runs.
    #[test]
    fn the_managers_requests_pass_the_network_verifier() {
        let directory = tempfile::tempdir().unwrap();
        let km = FileKeyManager::new(
            directory.path().join("keys.yml"),
            "",
            "q-prover-key".into(),
            Box::new(quil_crypto::FalconKeyConstructor),
        )
        .unwrap();
        km.create_falcon_key("q-prover-key").unwrap();
        let pubkey = km
            .get_signer_by_id("q-prover-key")
            .unwrap()
            .public_key()
            .to_vec();
        let tree = prover_tree(&pubkey);
        let verifier = quil_crypto::DefaultKeyManager::new();
        let filters = vec![vec![0x08; 32], vec![0x09; 35]];
        let build = |action, filters: &[Vec<u8>]| {
            build_request(&km, action, filters, 777)
                .unwrap()
                .request
                .unwrap()
        };

        let Request::Confirm(pb) = build("Confirm", &filters) else {
            panic!("a confirm");
        };
        let wire = conversions::prover_confirm_from_proto(&pb)
            .to_canonical_bytes()
            .unwrap();
        let op = prover_ops::ProverConfirm::from_canonical_bytes(&wire).unwrap();
        assert_eq!(op.filters, filters);
        assert!(verify::verify_prover_confirm(&op, &tree, &verifier).unwrap());

        let Request::Reject(pb) = build("Reject", &filters) else {
            panic!("a reject");
        };
        let wire = conversions::prover_reject_from_proto(&pb)
            .to_canonical_bytes()
            .unwrap();
        let op = prover_ops::ProverReject::from_canonical_bytes(&wire).unwrap();
        assert_eq!(op.filters, filters);
        assert!(verify::verify_prover_reject(&op, &tree, &verifier).unwrap());

        let single = &filters[1..];
        let Request::Pause(pb) = build("Pause", single) else {
            panic!("a pause");
        };
        let wire = conversions::prover_pause_from_proto(&pb)
            .to_canonical_bytes()
            .unwrap();
        let op = prover_filter_ops::ProverPause::from_canonical_bytes(&wire).unwrap();
        let active = allocation_tree(1);
        assert!(verify::verify_prover_pause(&op, &tree, Some(&active), &verifier).unwrap());

        let Request::Resume(pb) = build("Resume", single) else {
            panic!("a resume");
        };
        let wire = conversions::prover_resume_from_proto(&pb)
            .to_canonical_bytes()
            .unwrap();
        let op = prover_filter_ops::ProverResume::from_canonical_bytes(&wire).unwrap();
        let paused = allocation_tree(2);
        assert!(verify::verify_prover_resume(&op, &tree, Some(&paused), &verifier).unwrap());
    }
}

#[cfg(all(test, feature = "native-proof"))]
mod recheck_tests {
    use super::*;

    /// The submission reports the reward the authorization announced, not
    /// the confirmed one, to the manager and the private action log.
    #[test]
    fn a_submission_reports_the_reward_the_authorization_minted() {
        use super::super::mint::Progress;
        use crate::commands::token::MintEvent;
        let mut amounts = (1000, 10);
        let (step, report) = mint_report(
            MintEvent::Amounts {
                reward: 1300,
                fee: 10,
            },
            &mut amounts,
        );
        assert!(step.is_none() && matches!(report, Some(Progress::Note(_))));
        assert!(mint_report(MintEvent::Proving, &mut amounts).0.is_none());
        let (step, report) = mint_report(
            MintEvent::Submitted {
                cited_frame: 43,
                saved: "/cfg/mint-43.bin".into(),
            },
            &mut amounts,
        );
        let (phase, fields) = step.unwrap();
        assert_eq!(phase, "submitted");
        assert_eq!(
            fields,
            serde_json::json!({
                "cited_frame": 43,
                "file": "mint-43.bin",
                "reward": "1300",
                "minted": "1290",
            })
        );
        assert_eq!(
            report,
            Some(Progress::Submitted {
                cited_frame: 43,
                reward: 1300,
                saved: "/cfg/mint-43.bin".into(),
            })
        );
    }

    /// Read again at a later GLOBAL frame, the confirmed reward or a larger
    /// one at the confirmed fee is proved: rewards grow every frame, and a
    /// person answers the confirmation frames later (the devnet's delayed
    /// `y` re-confirmed four times in a row, +26048 Q a frame). A changed
    /// fee asks for a new confirmation; a smaller reward stops the run,
    /// whatever the fee.
    #[test]
    fn a_grown_reward_at_the_confirmed_fee_is_proved_without_a_new_confirmation() {
        let preview = super::super::mint::Preview {
            stage: super::super::mint::Stage::Authorize,
            cited_frame: 42,
            reward: 1000,
            fee: 10,
            max_fee: 1,
            recipient: String::new(),
        };
        for frame in [42, 43, 50] {
            for reward in [1000, 1001, 260_480] {
                assert_eq!(
                    recheck(frame, reward, 10, &preview).unwrap(),
                    Recheck::Prove,
                    "f{frame} {reward}"
                );
                for fee in [9, 11] {
                    assert_eq!(
                        recheck(frame, reward, fee, &preview).unwrap(),
                        Recheck::Requote,
                        "f{frame} {reward} fee {fee}"
                    );
                }
            }
            for fee in [9, 10, 11] {
                let error = recheck(frame, 999, fee, &preview).unwrap_err().to_string();
                assert!(error.contains("the reward changed"), "{error}");
            }
        }
    }
}

/// The manager's shield runs through `token shield-all`'s paced runner:
/// a fake clock and fake node drive [`shield_pacing::run`] as
/// [`execute_shield_all`](crate::commands::token::execute_shield_all) does,
/// every report goes through [`progress_of`] into the model, and keys go
/// through the manager's own key handling.
#[cfg(all(test, feature = "native-proof"))]
mod paced_shield_tests {
    use super::super::model::Model;
    use super::super::update::{self, Cmd};
    use super::*;
    use crate::commands::token::shield_pacing::{
        self, node_with_stall, GlobalRead, ShieldEvent as Paced, ShieldIo,
    };
    use crate::commands::token::{ShieldEvent, ShieldReport};
    use crossterm::event::{KeyCode, KeyEvent};
    use std::sync::atomic::{AtomicBool, Ordering};

    const START: u64 = 1_000_000;

    fn healthy() -> impl Fn(u64) -> GlobalRead {
        node_with_stall(u64::MAX - 1, u64::MAX)
    }

    /// A run on the manager's model: proving takes 150 s, a batch reads
    /// included `inclusion` s after its submission.
    struct Fake {
        now: u64,
        node: Box<dyn Fn(u64) -> GlobalRead>,
        inclusion: u64,
        /// A batch whose shard has no active prover from this time on.
        gone: Option<(usize, u64)>,
        submits: Vec<(usize, u64)>,
        model: Model,
        /// The manager's stop flag, set by `Cmd::ShieldStop` as the event
        /// loop sets it.
        halt: AtomicBool,
        /// Each report the model got, with its notices right after.
        seen: Vec<(shield::Progress, Vec<String>)>,
        /// Keys pressed right after the first report this matches.
        press: Option<(fn(&shield::Progress) -> bool, Vec<KeyEvent>)>,
    }

    impl Fake {
        fn new(batches: usize, node: impl Fn(u64) -> GlobalRead + 'static, inclusion: u64) -> Self {
            let mut model = Model::new();
            super::super::coins::open(&mut model);
            model.coins.shield.dialog = Some(shield::Dialog::Confirm(shield::Preview {
                batches,
                ..shield::shield_tests::preview()
            }));
            let cmds = update::handle_key(&mut model, KeyEvent::from(KeyCode::Char('y')));
            assert!(matches!(cmds.as_slice(), [Cmd::ShieldRun(_)]));
            Self {
                now: START,
                node: Box::new(node),
                inclusion,
                gone: None,
                submits: Vec::new(),
                model,
                halt: AtomicBool::new(false),
                seen: Vec::new(),
                press: None,
            }
        }

        fn report(&mut self, report: ShieldReport<'_>) {
            let Some(progress) = progress_of(report) else {
                return;
            };
            shield::apply_progress(&mut self.model, progress.clone());
            let notices = self.texts();
            self.seen.push((progress.clone(), notices));
            if self
                .press
                .as_ref()
                .is_some_and(|(wanted, _)| wanted(&progress))
            {
                let (_, keys) = self.press.take().unwrap();
                for key in keys {
                    for cmd in update::handle_key(&mut self.model, key) {
                        if matches!(cmd, Cmd::ShieldStop) {
                            self.halt.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }
        }

        fn texts(&self) -> Vec<String> {
            shield::notices(&self.model, &|units: u128| units.to_string())
                .into_iter()
                .map(|n| n.text)
                .collect()
        }

        /// Run `batches` with the manager's pacing and end it as the
        /// manager does.
        async fn run(&mut self, batches: usize) -> anyhow::Result<usize> {
            let result = shield_pacing::run(&mut *self, batches, PACING).await;
            shield::apply_progress(
                &mut self.model,
                shield::Progress::Done(result.as_ref().map(|_| ()).map_err(|e| e.to_string())),
            );
            result
        }

        /// The notices right after the first report `wanted` matches.
        fn after(&self, wanted: fn(&shield::Progress) -> bool) -> &[String] {
            &self
                .seen
                .iter()
                .find(|(progress, _)| wanted(progress))
                .unwrap_or_else(|| panic!("no such report in {:#?}", self.seen))
                .1
        }

        fn gaps(&self) -> Vec<u64> {
            self.submits.windows(2).map(|w| w[1].1 - w[0].1).collect()
        }
    }

    impl ShieldIo for Fake {
        type Proof = usize;
        fn now(&self) -> u64 {
            self.now
        }
        fn unix(&self) -> u64 {
            1_700_000_000 + self.now
        }
        async fn sleep(&mut self, secs: u64) {
            self.now += secs;
        }
        async fn global(&mut self) -> anyhow::Result<GlobalRead> {
            Ok((self.node)(self.now))
        }
        fn coins(&self, _index: usize) -> usize {
            96
        }
        fn shard(&self, index: usize) -> String {
            format!("...feedbeef{index:02x}")
        }
        fn stop_requested(&self) -> bool {
            self.halt.load(Ordering::Relaxed)
        }
        async fn prove(&mut self, index: usize) -> anyhow::Result<Option<usize>> {
            let count = self
                .model
                .coins
                .shield
                .run
                .as_ref()
                .unwrap()
                .preview
                .batches;
            self.report(ShieldReport::Batch(&ShieldEvent::Proving {
                index: index + 1,
                count,
                coins: 96,
            }));
            self.now += 150;
            self.report(ShieldReport::Batch(&ShieldEvent::Proved {
                index: index + 1,
                count,
            }));
            Ok(Some(index))
        }
        async fn submit(&mut self, index: usize, _proof: usize) -> anyhow::Result<()> {
            self.submits.push((index, self.now));
            let count = self
                .model
                .coins
                .shield
                .run
                .as_ref()
                .unwrap()
                .preview
                .batches;
            self.report(ShieldReport::Batch(&ShieldEvent::Submitted {
                index: index + 1,
                count,
                addresses: vec![[index as u8 + 1; 32]; 96],
                shielded: 900,
                fee: 100,
            }));
            Ok(())
        }
        async fn included(&mut self, index: usize) -> anyhow::Result<bool> {
            let sent = self.submits.iter().find(|(i, _)| *i == index).unwrap().1;
            // A batch whose shard loses its provers never commits.
            Ok(self.now >= sent + self.inclusion && self.gone.is_none_or(|(g, _)| g != index))
        }
        async fn shard_live(&mut self, index: usize) -> anyhow::Result<bool> {
            Ok(!self
                .gone
                .is_some_and(|(gone, from)| gone == index && self.now >= from))
        }
        fn event(&mut self, event: &Paced) {
            self.report(ShieldReport::Paced(event));
        }
    }

    fn esc() -> KeyEvent {
        KeyEvent::from(KeyCode::Esc)
    }

    fn y() -> KeyEvent {
        KeyEvent::from(KeyCode::Char('y'))
    }

    /// The paced runner's waits reach the manager's notices: the spacing
    /// before a submission, the wait for each inclusion, the runner's own
    /// inclusion reads and the projected end; nothing waits on a legacy read.
    #[tokio::test]
    async fn manager_shield_paced_events_reach_the_tui() {
        let mut io = Fake::new(3, healthy(), 30);
        assert_eq!(io.run(3).await.unwrap(), 3);
        let submitted = io.after(|p| matches!(p, shield::Progress::Submitted { index: 1, .. }));
        assert!(
            submitted.iter().any(
                |t| t.starts_with("Shield batch 1/3: 96 coins submitted at ")
                    && t.ends_with(
                        "; inclusion not yet confirmed; the next batch is proved after it."
                    )
            ),
            "{submitted:#?}"
        );
        let spacing = io.after(|p| matches!(p, shield::Progress::Spacing { index: 2, .. }));
        assert!(
            spacing
                .iter()
                .any(|t| t.starts_with("Shield batch 2/3: proved; submits at ")
                    && t.ends_with(", 5 min after the last submission.")),
            "{spacing:#?}"
        );
        let included = io.after(|p| matches!(p, shield::Progress::Projected { .. }));
        assert!(
            included.iter().any(|t| t.starts_with(
                "Shield: 1 batch of 3 included: 96 coins, 900 Q shielded; projected end ~"
            )),
            "{included:#?}"
        );
        let run = io.model.coins.shield.run.as_ref().unwrap();
        assert!(
            run.submitted.iter().all(|b| b.included),
            "{:?}",
            run.submitted
        );
        assert_eq!(run.done, Some(Ok(())));
        assert_eq!(
            io.texts(),
            ["Shield: 3 batches of 3 included: 288 coins, 2700 Q shielded."]
        );
    }

    /// A batch whose shard loses its provers while it waits is left with a
    /// notice naming the shard; the run goes on with the next batch and
    /// ends with an error naming the batch left.
    #[tokio::test]
    async fn manager_shield_leaves_a_batch_whose_shard_lost_its_provers() {
        let mut io = Fake::new(2, healthy(), 30);
        // Batch 1 is submitted at START + 150; its shard empties 10 min on.
        io.gone = Some((0, START + 750));
        let error = io.run(2).await.unwrap_err().to_string();
        assert!(error.starts_with("1 batch of 2 left (batch 1)"), "{error}");
        let gone = io.after(|p| matches!(p, shield::Progress::ShardGone { index: 1, .. }));
        assert!(
            gone.iter().any(|t| t
                == "Shield: 1 batch left, shard ...feedbeef00 without active provers; a rerun \
                    plans their coins onto a live shard."),
            "{gone:#?}"
        );
        assert!(
            !gone
                .iter()
                .any(|t| t.starts_with("Shield batch 1/2: 96 coins submitted")),
            "the left batch is no longer awaited: {gone:#?}"
        );
        assert_eq!(io.submits.len(), 2, "batch 2 goes on: {:?}", io.submits);
        let run = io.model.coins.shield.run.as_ref().unwrap();
        assert_eq!(run.left, [(1, "...feedbeef00".to_owned(), true)]);
        assert!(run.submitted[1].included, "{:?}", run.submitted);
        let texts = io.texts();
        let stopped = "Shield: the run stopped after 2 batches of 2 submitted: 1 batch of 2 left";
        assert!(texts.iter().any(|t| t.starts_with(stopped)), "{texts:#?}");
        assert!(
            !texts.iter().any(|t| t.contains("without active provers;")),
            "the error says it once: {texts:#?}"
        );
    }

    /// The manager never submits batches back to back: it runs with
    /// `token shield-all`'s default pacing, whose spacing its notices name.
    #[tokio::test]
    async fn manager_shield_never_submits_back_to_back() {
        assert_eq!(
            (PACING.min_interval, PACING.inclusion_timeout),
            (
                shield_pacing::DEFAULT_MIN_INTERVAL_SECS,
                shield_pacing::DEFAULT_INCLUSION_TIMEOUT_SECS
            )
        );
        assert_eq!(
            shield::SPACING_MIN * 60,
            shield_pacing::DEFAULT_MIN_INTERVAL_SECS
        );
        assert_eq!(shield::RESUME_AFTER_MIN * 60, shield_pacing::RECOVERY_SECS);
        // Proving and inclusion take 180 s together, under the spacing.
        let mut io = Fake::new(4, healthy(), 30);
        io.run(4).await.unwrap();
        assert_eq!(io.submits.len(), 4);
        assert!(io.gaps().iter().all(|gap| *gap >= 300), "{:?}", io.gaps());
    }

    /// While the node reports GLOBAL's head unchanged the proved batch is
    /// held, the notice says so as a warning with the node's text, and it
    /// submits only after 10 min of healthy GLOBAL.
    #[tokio::test]
    async fn manager_shield_pauses_while_global_is_degraded() {
        let (from, to) = (START + 20, START + 2_000);
        let mut io = Fake::new(1, node_with_stall(from, to), 30);
        io.run(1).await.unwrap();
        let sent = io.submits[0].1;
        assert!(sent >= to + shield_pacing::RECOVERY_SECS, "{sent}");
        let paused = io.after(|p| matches!(p, shield::Progress::Paused { .. }));
        assert!(
            paused.iter().any(|t| t
                .starts_with("Shield batch 1/1: proved and held; paused since ")
                && t.contains(": Global head unchanged >120s; it submits after")
                && t.ends_with("; it submits after 10 min of healthy GLOBAL.")),
            "{paused:#?}"
        );
        let notice = |m: &Model, key| {
            shield::notices(m, &|units: u128| units.to_string())
                .into_iter()
                .find(|n| n.key == key)
        };
        // Held: no submission between the pause and the resume.
        let paused_at = io
            .seen
            .iter()
            .position(|(p, _)| matches!(p, shield::Progress::Paused { .. }))
            .unwrap();
        let resumed_at = io
            .seen
            .iter()
            .position(|(p, _)| matches!(p, shield::Progress::Resumed { .. }))
            .unwrap();
        assert!(io.seen[paused_at..resumed_at]
            .iter()
            .all(|(p, _)| !matches!(p, shield::Progress::Submitted { .. })));
        assert!(
            io.seen[resumed_at]
                .1
                .iter()
                .any(|t| t.starts_with("Shield resumed at ")
                    && t.ends_with("min paused; GLOBAL healthy for 10 min.")),
            "{:#?}",
            io.seen[resumed_at]
        );
        assert!(notice(&io.model, "shield-paused").is_none());
        // The severity while paused.
        let mut m = Fake::new(1, healthy(), 30).model;
        shield::apply_progress(
            &mut m,
            shield::Progress::Paused {
                reason: "GLOBAL head 1200 has not advanced for 75 s".into(),
            },
        );
        let warning = notice(&m, "shield-paused").unwrap();
        assert_eq!(
            warning.severity,
            super::super::model::NoticeSeverity::Warning
        );
        assert!(
            warning.text.starts_with("Shield paused since ")
                && warning.text.ends_with(
                    ": GLOBAL head 1200 has not advanced for 75 s; the next submission waits \
                     for 10 min of healthy GLOBAL."
                ),
            "{}",
            warning.text
        );
    }

    /// ‹esc› ‹y› while batch 2 is proved and held for the spacing ends the
    /// run without submitting it; batch 1 stays submitted. ‹esc› with any
    /// other key keeps the run going.
    #[tokio::test]
    async fn manager_shield_stop_ends_the_run_before_the_next_submit() {
        let mut io = Fake::new(3, healthy(), 30);
        io.press = Some((
            |p| matches!(p, shield::Progress::Proving { index: 1, .. }),
            vec![esc(), KeyEvent::from(KeyCode::Char('n'))],
        ));
        let mut keep = Fake::new(1, healthy(), 30);
        keep.press = io.press.take();
        assert_eq!(keep.run(1).await.unwrap(), 1);
        assert!(!keep.model.coins.shield.run.as_ref().unwrap().stopping);

        io.press = Some((
            |p| matches!(p, shield::Progress::Spacing { index: 2, .. }),
            vec![esc(), y()],
        ));
        assert_eq!(io.run(3).await.unwrap(), 1);
        assert_eq!(io.submits.len(), 1, "{:?}", io.submits);
        assert!(!shield::running(&io.model));
        let run = io.model.coins.shield.run.as_ref().unwrap();
        assert!(run.stopped && run.done == Some(Ok(())));
        let stopped = "Shield: stopped on request after 1 batch of 3 submitted; the rest were not.";
        assert!(io.texts().iter().any(|t| t == stopped), "{:#?}", io.texts());
    }
}

/// The transfer actions' confirmations against a node double that quotes
/// fees: a malformed recipient is refused before any quote, an accept is
/// quoted as `token accept` quotes it. Nothing is proved or submitted.
#[cfg(all(test, feature = "native-proof"))]
mod transfer_action_tests {
    use super::*;

    #[tokio::test]
    async fn previews_check_the_recipient_and_quote_the_fee() {
        let directory = tempfile::tempdir().unwrap();
        let km = Arc::new(
            FileKeyManager::new(
                directory.path().join("keys.yml"),
                &hex::encode([9; 32]),
                "q-prover-key".into(),
                Box::new(quil_crypto::FalconKeyConstructor),
            )
            .unwrap(),
        );
        km.create_agreement_key("q-onion-key", 9).unwrap();
        let network =
            quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(0).network;
        // The node reports a peer ID, so a context signing as another peer
        // is refused.
        let server = quil_rpc::node_service::NodeRpcServer::new()
            .with_peer_id("the-node-peer".into())
            .with_token_fee_provider(Arc::new(move |_, _| {
                Ok(quil_rpc::node_service::TokenFeeSnapshot {
                    network,
                    observed_frame: 42,
                    global_execution: true,
                    difficulty: 50_000,
                    world_state_bytes: 1 << 40,
                    fee_multiplier_vote: 1,
                })
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let multiaddr = format!(
            "/ip4/127.0.0.1/tcp/{}",
            listener.local_addr().unwrap().port()
        );
        let incoming = futures::stream::unfold(listener, |listener| async {
            let result = listener.accept().await.map(|(socket, _)| socket);
            Some((result, listener))
        });
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    quil_types::proto::node::node_service_server::NodeServiceServer::new(server),
                )
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        let opts = crate::rpc::ConnectOpts {
            listen_grpc_multiaddr: multiaddr,
            ..Default::default()
        };
        let tc = crate::commands::token::TokenCtx {
            node_config: quil_config::Config::default(),
            config_dir: directory.path().to_path_buf(),
            key_manager: km.clone(),
            connect_opts: opts.clone(),
            submit_opts: opts,
            submit_key_manager: km,
            submit_config_dir: directory.path().to_path_buf(),
            submit_identity: Default::default(),
            peer_id_bytes: Vec::new(),
            read_flags: Vec::new(),
            max_fee: crate::commands::token::DEFAULT_MAX_AUTOMATIC_FEE,
        };
        let capture = |kind| {
            let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
            crate::commands::token::output::capture(notes, transfer_preview(&tc, kind))
        };
        use super::super::transfer::Kind;
        for kind in [
            Kind::Transfer {
                recipient: "0x1234".into(),
                amount: 5,
            },
            Kind::Pending {
                recipient: "0x1234".into(),
                amount: 5,
                refund_after: None,
            },
        ] {
            assert!(
                capture(kind).await.is_err(),
                "a malformed recipient is refused"
            );
        }
        let preview = capture(Kind::Accept {
            escrow: [7; 32],
            amount: 50,
        })
        .await
        .unwrap();
        let quoted = crate::commands::token::claim_fee(&tc, &quil_token(), None)
            .await
            .unwrap();
        assert_eq!(preview.fee, quoted);
        assert!(preview.fee > 0 && preview.merge.is_none());
        // Signed as another peer, every action is refused before any check
        // or quote, as `qclient token` refuses it.
        let other = crate::commands::token::TokenCtx {
            submit_identity: crate::commands::token::ConfigIdentity {
                falcon: Some("another-peer".into()),
                ed448: None,
            },
            ..tc
        };
        for kind in [
            Kind::Accept {
                escrow: [7; 32],
                amount: 50,
            },
            Kind::Merge,
        ] {
            let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
            let error =
                crate::commands::token::output::capture(notes, transfer_preview(&other, kind))
                    .await
                    .unwrap_err()
                    .to_string();
            assert!(error.contains("own peer key"), "{error}");
            assert!(!error.contains("--submit-config"), "{error}");
        }
        stop.send(()).unwrap();
    }

    /// With the qclient config reading through a public or custom RPC, the
    /// shielded read, every transfer confirmation and every run are refused
    /// before any request, and the refused run is recorded in the private
    /// action log with its confirmed inputs.
    #[tokio::test]
    async fn wallet_reads_go_to_this_node_only() {
        use super::super::transfer::{Kind, Preview};
        let directory = tempfile::tempdir().unwrap();
        let km = Arc::new(
            FileKeyManager::new(
                directory.path().join("keys.yml"),
                &hex::encode([9; 32]),
                "q-prover-key".into(),
                Box::new(quil_crypto::FalconKeyConstructor),
            )
            .unwrap(),
        );
        // Nothing listens there: a request would fail with a transport
        // error, not the refusal.
        let public = crate::rpc::ConnectOpts {
            public_rpc: true,
            listen_grpc_multiaddr: "/ip4/127.0.0.1/tcp/9".into(),
            ..Default::default()
        };
        let custom = crate::rpc::ConnectOpts {
            custom_rpc: "127.0.0.1:9".into(),
            ..Default::default()
        };
        for opts in [public, custom] {
            assert!(opts.is_light_node());
            let tc = crate::commands::token::TokenCtx {
                node_config: quil_config::Config::default(),
                config_dir: directory.path().to_path_buf(),
                key_manager: km.clone(),
                connect_opts: opts.clone(),
                submit_opts: opts,
                submit_key_manager: km.clone(),
                submit_config_dir: directory.path().to_path_buf(),
                submit_identity: Default::default(),
                peer_id_bytes: Vec::new(),
                read_flags: Vec::new(),
                max_fee: crate::commands::token::DEFAULT_MAX_AUTOMATIC_FEE,
            };
            let refused = |error: String| {
                assert!(
                    error.contains("public or custom RPC") && error.contains("this node only"),
                    "{error}"
                );
            };
            let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
            refused(
                crate::commands::token::output::capture(notes, shielded_read(&tc))
                    .await
                    .unwrap_err()
                    .to_string(),
            );
            let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
            refused(
                crate::commands::token::output::capture(notes, transfer_preview(&tc, Kind::Merge))
                    .await
                    .unwrap_err()
                    .to_string(),
            );
            let log = ActionLog::new(directory.path());
            let _ = std::fs::remove_file(log.path());
            let preview = Preview {
                kind: Kind::Accept {
                    escrow: [7; 32],
                    amount: 50,
                },
                fee: 9,
                max_fee: 10,
                merge: None,
            };
            let (progress, _reports) = tokio::sync::mpsc::unbounded_channel();
            let mut record = crate::commands::token::action_log::ActionRecorder::new(
                Some(log.clone()),
                "accept",
                "manager",
            );
            let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
            refused(
                crate::commands::token::output::capture(
                    notes,
                    transfer_execute(&tc, &preview, &progress, &mut record),
                )
                .await
                .unwrap_err()
                .to_string(),
            );
            let records: Vec<serde_json::Value> = std::fs::read_to_string(log.path())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            let phases: Vec<&str> = records
                .iter()
                .map(|r| r["phase"].as_str().unwrap())
                .collect();
            assert_eq!(phases, ["start", "outcome"]);
            assert!(records
                .iter()
                .all(|r| r["kind"] == "accept" && r["source"] == "manager"));
            assert_eq!(records[0]["escrow"], hex::encode([7; 32]));
            assert_eq!(records[0]["amount"], "50");
            assert_eq!(records[1]["outcome"], "failed");
        }
    }
    /// A token context for a wallet whose node listens on `listener`, its
    /// keys in `directory`.
    fn left_out_ctx(
        directory: &std::path::Path,
        listener: &tokio::net::TcpListener,
    ) -> crate::commands::token::TokenCtx {
        let km = Arc::new(
            FileKeyManager::new(
                directory.join("keys.yml"),
                &hex::encode([9; 32]),
                "q-prover-key".into(),
                Box::new(quil_crypto::FalconKeyConstructor),
            )
            .unwrap(),
        );
        km.create_agreement_key("q-onion-key", 9).unwrap();
        km.create_falcon_key("q-prover-key").unwrap();
        let opts = crate::rpc::ConnectOpts {
            listen_grpc_multiaddr: format!(
                "/ip4/127.0.0.1/tcp/{}",
                listener.local_addr().unwrap().port()
            ),
            ..Default::default()
        };
        crate::commands::token::TokenCtx {
            node_config: quil_config::Config::default(),
            config_dir: directory.to_path_buf(),
            key_manager: km.clone(),
            connect_opts: opts.clone(),
            submit_opts: opts,
            submit_key_manager: km,
            submit_config_dir: directory.to_path_buf(),
            submit_identity: Default::default(),
            peer_id_bytes: Vec::new(),
            read_flags: Vec::new(),
            max_fee: crate::commands::token::DEFAULT_MAX_AUTOMATIC_FEE,
        }
    }

    /// The manager's read of the shielded side goes on past what its scans
    /// leave out and carries their counts: a coin whose memo does not
    /// match, a second coin of a spend image, a pending transfer whose memo
    /// does not match, and pending transfers past its limit, of which it
    /// lists the largest.
    #[tokio::test]
    async fn the_shielded_read_carries_what_its_scans_left_out() {
        let directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tc = left_out_ctx(directory.path(), &listener);
        let (stop, serving) = crate::commands::token::serve_left_out(&tc, listener);
        let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
        let read = crate::commands::token::output::capture(notes, shielded_read_within(&tc, 4, 2))
            .await
            .expect("skipped coins: the read goes on past what its scans leave out");
        assert_eq!(read.coins, Some((2, 26)));
        assert_eq!(
            read.skipped,
            super::super::transfer::Skipped {
                mismatched: 1,
                duplicates: 1,
                limited: 1,
                escrows: 1,
                escrows_mismatched: 1,
            },
            "skipped coins: the read carries what its scans left out"
        );
        assert_eq!(read.escrows_failed, None);
        let mut amounts: Vec<u128> = read.escrows.iter().map(|escrow| escrow.amount).collect();
        amounts.sort();
        assert_eq!(amounts, [9, 11]);
        assert!(read.escrows.iter().all(|escrow| !escrow.outgoing));
        stop.send(()).unwrap();
        serving.await.unwrap();
    }

    /// The manager's read, with its own bounds, reads past the 2,048 pages
    /// that once ended it: other users' coins and escrows fill a scan's
    /// pages, and anyone can add them for fees.
    #[tokio::test]
    async fn the_managers_read_reaches_past_the_old_page_budget() {
        let directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tc = left_out_ctx(directory.path(), &listener);
        // Pages of eight reads, past 2,048 pages.
        let (stop, serving) =
            crate::commands::token::serve_left_out_with(&tc, listener, (2_048 + 8) * 8, false);
        let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
        let read = crate::commands::token::output::capture(notes, shielded_read(&tc))
            .await
            .expect("skipped coins: the manager's read goes past the old page budget");
        assert_eq!(read.coins, Some((3, 29)));
        assert_eq!(
            read.skipped,
            super::super::transfer::Skipped {
                mismatched: 1,
                duplicates: 1,
                limited: 0,
                escrows: 0,
                escrows_mismatched: 1,
            }
        );
        let mut amounts: Vec<u128> = read.escrows.iter().map(|escrow| escrow.amount).collect();
        amounts.sort();
        assert_eq!(amounts, [7, 9, 11]);
        stop.send(()).unwrap();
        serving.await.unwrap();
    }

    /// The node releases a scan's snapshot an hour after the scan starts.
    /// The manager's read that the hour stopped, of the coins or of the
    /// pending transfers, fails as such, so that its notice offers no read
    /// again; the coins are kept when only the pending transfers' scan
    /// stopped.
    #[tokio::test]
    async fn a_read_its_snapshot_hour_stopped_fails_as_such() {
        use super::super::transfer::ReadFailure;
        use crate::commands::token::{output::capture, scans_begin_ago, serve_left_out_expiring};
        let age = quil_hypergraph::snapshot::SCAN_MAX_AGE;
        let minutes = age.as_secs() / 60;
        for escrows in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let tc = left_out_ctx(directory.path(), &listener);
            let (stop, serving) = serve_left_out_expiring(&tc, listener, escrows);
            scans_begin_ago(age);
            let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
            let read = capture(notes, shielded_read(&tc)).await;
            scans_begin_ago(std::time::Duration::ZERO);
            let failure = match read {
                Ok(read) => {
                    assert_eq!(read.coins, Some((3, 29)));
                    read.escrows_failed
                }
                Err(error) => Some(read_failure(&error)),
            };
            assert_eq!(
                failure,
                Some(ReadFailure::Outlived { minutes }),
                "the read offers to read again (the escrow scan stopped: {escrows})"
            );
            stop.send(()).unwrap();
            serving.await.unwrap();
        }
    }

    /// The manager reads the coins, then the pending transfers. When the
    /// pending transfers' read fails, the read keeps the coins and carries
    /// the failure, which its notice shows.
    #[tokio::test]
    async fn the_managers_read_keeps_its_coins_when_the_escrow_read_fails() {
        let directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tc = left_out_ctx(directory.path(), &listener);
        let (stop, serving) = crate::commands::token::serve_left_out_with(&tc, listener, 0, true);
        let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
        let read = crate::commands::token::output::capture(notes, shielded_read_within(&tc, 4, 2))
            .await
            .expect("skipped coins: a failed escrow read keeps the coins");
        assert_eq!(read.coins, Some((2, 26)));
        assert!(read.escrows.is_empty());
        let failed = match read.escrows_failed {
            Some(super::super::transfer::ReadFailure::Failed(failed)) => failed,
            other => panic!("the escrow read failed as {other:?}"),
        };
        assert!(failed.contains("invalid escrow blob"), "{failed}");
        stop.send(()).unwrap();
        serving.await.unwrap();
    }
}
