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
const RPC_TIMEOUT: Duration = Duration::from_secs(15);
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

/// Longest a legacy read of the Coins tab may take.
const LEGACY_TIMEOUT: Duration = Duration::from_secs(120);

/// Read the legacy coins of the identity with Ed448 key `public` (`None`:
/// the config has none, so it owns no legacy coins).
pub async fn fetch_legacy(
    client: Client,
    public: Option<[u8; 57]>,
    network: u8,
    config_dir: Option<std::path::PathBuf>,
) -> Msg {
    let started = std::time::Instant::now();
    let answer = match public {
        None => Ok(None),
        Some(public) => tokio::time::timeout(
            LEGACY_TIMEOUT,
            crate::commands::token::legacy::snapshot(
                &client,
                &quil_execution::domains::QUIL_TOKEN,
                &public,
                network,
                config_dir.as_deref(),
            ),
        )
        .await
        .unwrap_or_else(|_| {
            Err(anyhow::anyhow!(
                "no answer within {}s",
                LEGACY_TIMEOUT.as_secs()
            ))
        })
        .map(Some)
        .map_err(|e| format!("{e:#}")),
    };
    Msg::LegacyRefresh {
        answer,
        took: started.elapsed(),
        mints: saved_mints(config_dir.as_deref(), network),
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
    let plan = plan_shield_all(tc, &quil_token(), shield::BATCH_COINS).await?;
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

/// Run the confirmed shield through the CLI's own functions, reporting each
/// batch on `progress` and recording the run in the private action `log`.
/// The batches are read again and must match what was confirmed; otherwise
/// nothing is submitted.
#[cfg(feature = "native-proof")]
pub async fn shield_run(
    token: Option<(GlobalArgs, u128)>,
    preview: shield::Preview,
    progress: tokio::sync::mpsc::UnboundedSender<Msg>,
    log: Option<ActionLog>,
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
        )
        .await
    })
    .await;
    Msg::Shield(shield::Progress::Done(result.map_err(|e| format!("{e:#}"))))
}

/// Tell the manager the action log could not be written.
#[cfg(feature = "native-proof")]
fn log_failed(progress: &tokio::sync::mpsc::UnboundedSender<Msg>, why: Option<String>) {
    if let Some(why) = why {
        let _ = progress.send(Msg::Shield(shield::Progress::LogFailed(why)));
    }
}

/// [`shield_run`]'s work with `tc`'s node and keys, recorded by `record`:
/// the plan, each batch and the outcome.
#[cfg(feature = "native-proof")]
async fn shield_execute(
    tc: &crate::commands::token::TokenCtx,
    preview: &shield::Preview,
    progress: &tokio::sync::mpsc::UnboundedSender<Msg>,
    record: &mut crate::commands::token::action_log::ShieldRecorder,
) -> anyhow::Result<()> {
    let result = shield_batches(tc, preview, progress, record).await;
    let outcome = result.as_ref().map(|_| ()).map_err(|e| format!("{e:#}"));
    log_failed(progress, record.outcome(&outcome));
    result
}

#[cfg(feature = "native-proof")]
async fn shield_batches(
    tc: &crate::commands::token::TokenCtx,
    preview: &shield::Preview,
    progress: &tokio::sync::mpsc::UnboundedSender<Msg>,
    record: &mut crate::commands::token::action_log::ShieldRecorder,
) -> anyhow::Result<()> {
    use crate::commands::token::{execute_shield_all, plan_shield_all, ShieldEvent};
    let plan = plan_shield_all(tc, &quil_token(), shield::BATCH_COINS).await?;
    let (coins, units) = plan.totals()?;
    anyhow::ensure!(
        plan.batches.len() == preview.batches && coins == preview.coins && units == preview.units,
        "the plan changed since it was confirmed ({} batches of {coins} coins now); press ‹S› \
         again",
        plan.batches.len()
    );
    log_failed(progress, record.start(&plan, tc.max_fee));
    execute_shield_all(tc, plan, |event| {
        log_failed(progress, record.event(&event));
        let report = match event {
            ShieldEvent::Proving {
                index,
                count,
                coins,
            } => shield::Progress::Proving {
                index,
                count,
                coins,
            },
            ShieldEvent::Skipped { index, count, .. } => shield::Progress::Skipped { index, count },
            ShieldEvent::Submitted {
                index,
                count,
                addresses,
                shielded,
                ..
            } => shield::Progress::Submitted {
                index,
                count,
                addresses,
                shielded,
            },
            ShieldEvent::Nothing { .. } | ShieldEvent::Uncovered(_) => return,
        };
        let _ = progress.send(Msg::Shield(report));
    })
    .await
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
        .map_err(|e| format!("{e:#}"))
    };
    #[cfg(not(feature = "confidential-tokens"))]
    let result = {
        let _ = token;
        Err("this qclient build has no confidential tokens".into())
    };
    Msg::Shielded(result)
}

#[cfg(feature = "confidential-tokens")]
async fn shielded_read(
    tc: &crate::commands::token::TokenCtx,
) -> anyhow::Result<super::transfer::Read> {
    use crate::commands::token::{
        confidential_balance, list_escrows, SCAN_MAX_COINS, SCAN_MAX_PAGES,
    };
    own_node_only(tc)?;
    let coins = confidential_balance(tc, SCAN_MAX_PAGES, SCAN_MAX_COINS).await?;
    let application = hex::encode(quil_execution::domains::QUIL_TOKEN);
    let escrows = list_escrows(tc, &application, SCAN_MAX_PAGES, SCAN_MAX_COINS).await?;
    Ok(super::transfer::Read {
        coins,
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
        run_claim, run_merge, run_pending_create, run_transfer, SCAN_MAX_COINS, SCAN_MAX_PAGES,
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
                SCAN_MAX_PAGES,
                SCAN_MAX_COINS,
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
                SCAN_MAX_PAGES,
                SCAN_MAX_COINS,
            )
            .await
        }
        Kind::Accept { escrow, .. } => {
            run_claim(tc, &app, &hex::encode(escrow), preview.fee, false).await
        }
        Kind::Refund { escrow, .. } => {
            run_claim(tc, &app, &hex::encode(escrow), preview.fee, true).await
        }
        Kind::Merge => {
            run_merge(
                tc,
                &app,
                &["all".to_string()],
                preview.fee,
                SCAN_MAX_PAGES,
                SCAN_MAX_COINS,
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

/// Archive fallback can exceed the fast status deadline. Keep it bounded,
/// report failure explicitly, and allow node status to refresh meanwhile.
pub async fn fetch_shards(mut client: Client) -> Msg {
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        client.get_shard_info(tonic::Request::new(GetShardInfoRequest {
            include_all: true,
        })),
    )
    .await;
    Msg::ShardRefresh(match result {
        Ok(Ok(r)) => Ok(r.into_inner()),
        Ok(Err(e)) => Err(format!("Shard data unavailable: {e}")),
        Err(_) => Err("Shard data timed out after 60s; retrying".into()),
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
    action: String,
    filters: Vec<Vec<u8>>,
    original_status: u32,
) -> Msg {
    let label = if action == "Pause" || action == "Resume" {
        trunc_hex(&hex::encode(filters.first().cloned().unwrap_or_default()))
    } else {
        filters_label(&filters)
    };

    let _ = label; // label mirrors Go's status string; unused in the Rust flow.

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
        let result = crate::commands::token::output::capture(
            notes,
            shield_execute(&tc, &preview, &progress, &mut recorder()),
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
            shield_execute(&tc, &stale, &progress, &mut recorder()),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("the plan changed"), "{error}");
        let last = records().pop().unwrap();
        assert_eq!(last["phase"], "outcome");
        assert_eq!(last["outcome"], "failed");
        assert!(last["error"].as_str().unwrap().contains("the plan changed"));

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
}
