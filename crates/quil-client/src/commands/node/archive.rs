//! `qclient node archive …` — the archive peers the node reads from.
//!
//! `shards` asks every archive in the node's pool for the QUIL grid's shards
//! (the grid a mainnet node's shard-info refresh asks one archive about per
//! refresh) and compares the lists. The shard grid is not part of the GLOBAL
//! commitment, so archives can disagree on it without anything else noticing.

use std::collections::BTreeSet;

use clap::{Args, Subcommand};

use quil_rpc::archive_shard_list::ShardList;
use quil_rpc::ArchiveShardInfo;

use crate::context::{Context, GlobalArgs};
use crate::rpc;

#[derive(Debug, Subcommand)]
pub enum ArchiveCommand {
    /// Compare the shard list each archive reports.
    ///
    /// Asks the running node for its archive endpoints (the pool its shard
    /// refresh picks from), asks each archive for the QUIL grid's shards with
    /// the node's transport key, and prints one row per archive, then the
    /// filters each archive lists differently from the majority view. The
    /// digests match the node's "archives disagree" warning when the node
    /// refreshes only the QUIL grid, as mainnet nodes do today. Read-only;
    /// exits non-zero when no archive answers. A disagreement is an
    /// archive-side condition: report the endpoints and filters to the
    /// archive operators.
    Shards(ShardsArgs),
}

#[derive(Debug, Args)]
pub struct ShardsArgs {
    /// Query this archive (host:port) instead of the node's pool; repeatable.
    #[arg(long = "archive")]
    pub archives: Vec<String>,
    /// The node's stream address (host:port) to ask for its archive pool.
    /// Defaults to the node's stream listen address.
    #[arg(long = "rpc", default_value = "", conflicts_with = "archives")]
    pub rpc: String,
}

pub async fn run(global: GlobalArgs, cmd: &ArchiveCommand) -> anyhow::Result<()> {
    match cmd {
        ArchiveCommand::Shards(args) => shards(global, args).await,
    }
}

async fn shards(global: GlobalArgs, args: &ShardsArgs) -> anyhow::Result<()> {
    let ctx = Context::load(global)?;
    let (node_config, dir) = ctx.load_node_config("default")?;
    let key = ctx
        .key_manager(&node_config, &dir)?
        .get_signer_by_id("q-prover-key")
        .map_err(|e| anyhow::anyhow!("get q-prover-key for transport auth: {e}"))?
        .private_key()
        .to_vec();

    let endpoints = if !args.archives.is_empty() {
        args.archives.clone()
    } else {
        let addr = if args.rpc.is_empty() {
            rpc::local_stream_addr(&node_config)?
        } else {
            args.rpc.clone()
        };
        let mut client = quil_rpc::ArchiveClient::connect_own_master(&addr, &key)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "connect to the node at {addr}: {e}; is it running? Or pass --archive host:port"
                )
            })?;
        client
            .get_archive_endpoints()
            .await
            .map_err(|e| anyhow::anyhow!("ask the node at {addr} for its archive endpoints: {e}"))?
    };
    if endpoints.is_empty() {
        anyhow::bail!("the node knows no archive endpoint yet; pass --archive host:port");
    }

    // Concurrently, in this task: one failed query cannot discard the others.
    let shard_keys = [quil_grid_shard_key()];
    let answers = futures::future::join_all(
        endpoints
            .iter()
            .map(|endpoint| quil_rpc::fetch_shard_info_from_endpoint(endpoint, &key, &shard_keys)),
    )
    .await;
    let reports: Vec<ArchiveReport> = endpoints
        .iter()
        .zip(answers)
        .map(|(endpoint, answer)| ArchiveReport {
            endpoint: endpoint.clone(),
            result: report_result(answer.map_err(|e| e.to_string())),
        })
        .collect();
    let (text, answered) = format_comparison(&reports);
    print!("{text}");
    if answered == 0 {
        anyhow::bail!("no archive answered");
    }
    Ok(())
}

/// The QUIL token's grid shard key, `L1 ‖ L2` (35 bytes): the grid a
/// regular node's shard refresh enumerates on mainnet.
fn quil_grid_shard_key() -> Vec<u8> {
    let quil = quil_execution::domains::QUIL_TOKEN;
    let mut key = quil_hypergraph::addressing::get_bloom_filter_indices(&quil, 256, 3).to_vec();
    key.extend_from_slice(&quil);
    key
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or_default().to_string()
}

/// One archive's answer as a list to compare: like the node, a partial
/// answer (some shard key failed) is not compared.
fn report_result(answer: Result<ArchiveShardInfo, String>) -> Result<ShardList, String> {
    let info = answer.map_err(|e| first_line(&e))?;
    if info.sizes.is_empty() && info.failed_shard_keys == 0 {
        return Err("reported no shards".into());
    }
    ShardList::from_complete(&info).ok_or_else(|| {
        format!(
            "partial answer: {} shard keys failed",
            info.failed_shard_keys
        )
    })
}

/// One archive's answer: its shard list, or why there is none.
#[derive(Debug, Clone)]
pub(crate) struct ArchiveReport {
    pub endpoint: String,
    pub result: Result<ShardList, String>,
}

/// The distinct lists of the answering archives, each with the indices of
/// the reports holding it, largest group first (ties in report order).
fn groups(reports: &[ArchiveReport]) -> Vec<(&ShardList, Vec<usize>)> {
    let mut groups: Vec<(&ShardList, Vec<usize>)> = Vec::new();
    for (index, report) in reports.iter().enumerate() {
        let Ok(list) = &report.result else { continue };
        match groups.iter_mut().find(|(l, _)| l.filters == list.filters) {
            Some((_, members)) => members.push(index),
            None => groups.push((list, vec![index])),
        }
    }
    groups.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    groups
}

/// The comparison table and the differing filters, as plain text, and how
/// many archives answered.
pub(crate) fn format_comparison(reports: &[ArchiveReport]) -> (String, usize) {
    use std::fmt::Write as _;
    let groups = groups(reports);
    let answered: usize = groups.iter().map(|(_, members)| members.len()).sum();
    // The majority view: the single largest group of equal lists.
    let majority = match groups.as_slice() {
        [first, second, ..] if first.1.len() == second.1.len() => None,
        [first, ..] => Some(first.0),
        [] => None,
    };

    let mut out = String::new();
    let _ = writeln!(
        out,
        "Archive shard lists: {} archives, {answered} answered.",
        reports.len()
    );
    let width = reports
        .iter()
        .map(|r| r.endpoint.len())
        .max()
        .unwrap_or(0)
        .max("ENDPOINT".len());
    let _ = writeln!(
        out,
        "{:<width$}  {:>6}  {:>6}  {:<8}  STATUS",
        "ENDPOINT", "SHARDS", "FROZEN", "DIGEST"
    );
    for report in reports {
        let (shards, frozen, digest, status) = match &report.result {
            Ok(list) => {
                let status = match majority {
                    Some(m) if m.filters == list.filters => "agrees",
                    Some(_) => "differs",
                    None => "no majority",
                };
                (
                    list.filters.len().to_string(),
                    list.frozen.len().to_string(),
                    list.digest(),
                    status.to_string(),
                )
            }
            Err(error) => (
                "-".into(),
                "-".into(),
                "-".into(),
                format!("error: {error}"),
            ),
        };
        let _ = writeln!(
            out,
            "{:<width$}  {shards:>6}  {frozen:>6}  {digest:<8}  {status}",
            report.endpoint
        );
    }

    match (majority, groups.len()) {
        (_, 0) => {
            let _ = writeln!(out, "No archive answered.");
        }
        (Some(m), 1) => {
            let _ = writeln!(
                out,
                "All {answered} answering archives agree: {} shards, digest {}.",
                m.filters.len(),
                m.digest()
            );
        }
        (Some(m), _) => {
            let _ = writeln!(
                out,
                "Majority view: {} shards, digest {}, from {} of {answered} answering archives.",
                m.filters.len(),
                m.digest(),
                groups[0].1.len()
            );
            let _ = writeln!(
                out,
                "Filters that differ from the majority view, by archive:"
            );
            for report in reports {
                let Ok(list) = &report.result else { continue };
                if list.filters == m.filters {
                    continue;
                }
                write_differences(
                    &mut out,
                    &report.endpoint,
                    list,
                    &list.only_in(m),
                    &m.only_in(list),
                );
            }
        }
        (None, n) => {
            let _ = writeln!(
                out,
                "No majority view: no single largest group among the {n} lists of the {answered} answering archives."
            );
            let _ = writeln!(
                out,
                "Filters not every answering archive lists, by archive:"
            );
            let lists: Vec<&ShardList> = groups.iter().map(|(list, _)| *list).collect();
            let all: BTreeSet<Vec<u8>> = lists
                .iter()
                .flat_map(|l| l.filters.iter().cloned())
                .collect();
            let common: BTreeSet<Vec<u8>> = all
                .iter()
                .filter(|f| lists.iter().all(|l| l.filters.contains(*f)))
                .cloned()
                .collect();
            for report in reports {
                let Ok(list) = &report.result else { continue };
                let extra: Vec<Vec<u8>> = list.filters.difference(&common).cloned().collect();
                let missing: Vec<Vec<u8>> = all.difference(&list.filters).cloned().collect();
                write_differences(&mut out, &report.endpoint, list, &extra, &missing);
            }
        }
    }
    (out, answered)
}

/// `extra`: filters this archive lists that the reference does not;
/// `missing`: filters the reference lists that this archive does not.
fn write_differences(
    out: &mut String,
    endpoint: &str,
    list: &ShardList,
    extra: &[Vec<u8>],
    missing: &[Vec<u8>],
) {
    use std::fmt::Write as _;
    let _ = writeln!(
        out,
        "{endpoint} ({} shards, digest {}):",
        list.filters.len(),
        list.digest()
    );
    for filter in extra {
        let _ = writeln!(out, "  extra    {}", hex::encode(filter));
    }
    for filter in missing {
        let _ = writeln!(out, "  missing  {}", hex::encode(filter));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(filters: &[u8], frozen: &[u8]) -> ShardList {
        ShardList {
            filters: filters.iter().map(|&f| vec![0xab, f]).collect(),
            frozen: frozen.iter().map(|&f| vec![0xab, f]).collect(),
        }
    }

    fn ok(endpoint: &str, list: ShardList) -> ArchiveReport {
        ArchiveReport {
            endpoint: endpoint.into(),
            result: Ok(list),
        }
    }

    /// The parent `01` split into `02` and `03`; one archive still lists `01`.
    #[test]
    fn a_minority_archive_is_named_with_the_filters_it_lists_differently() {
        let split = list(&[2, 3, 9], &[9]);
        let stale = list(&[1, 9], &[]);
        let reports = vec![
            ok("a.example:8340", split.clone()),
            ok("stale.example:8340", stale.clone()),
            ArchiveReport {
                endpoint: "down.example:8340".into(),
                result: Err("connect: timed out".into()),
            },
            ok("b.example:8340", split.clone()),
        ];
        let (s, t) = (split.digest(), stale.digest());
        let expected = format!(
            "Archive shard lists: 4 archives, 3 answered.\n\
             ENDPOINT            SHARDS  FROZEN  DIGEST    STATUS\n\
             a.example:8340           3       1  {s}  agrees\n\
             stale.example:8340       2       0  {t}  differs\n\
             down.example:8340        -       -  -         error: connect: timed out\n\
             b.example:8340           3       1  {s}  agrees\n\
             Majority view: 3 shards, digest {s}, from 2 of 3 answering archives.\n\
             Filters that differ from the majority view, by archive:\n\
             stale.example:8340 (2 shards, digest {t}):\n\
             \x20 extra    ab01\n\
             \x20 missing  ab02\n\
             \x20 missing  ab03\n"
        );
        assert_eq!(format_comparison(&reports), (expected, 3));
    }

    #[test]
    fn agreeing_archives_print_no_differences() {
        let split = list(&[2, 3], &[]);
        let (out, answered) =
            format_comparison(&[ok("a:1", split.clone()), ok("b:1", split.clone())]);
        assert_eq!(answered, 2);
        assert!(
            out.ends_with(&format!(
                "All 2 answering archives agree: 2 shards, digest {}.\n",
                split.digest()
            )),
            "{out}"
        );
        assert!(!out.contains("differs") && !out.contains("extra"), "{out}");
    }

    #[test]
    fn an_even_split_has_no_majority_and_names_the_filters_not_all_list() {
        let (out, _) = format_comparison(&[
            ok("a:1", list(&[2, 3, 9], &[])),
            ok("b:1", list(&[1, 9], &[])),
        ]);
        assert!(out.contains("No majority view: no single largest group among the 2 lists of the 2 answering archives.\n"), "{out}");
        assert_eq!(out.matches("no majority\n").count(), 2, "{out}");
        assert!(out.contains("a:1 (3 shards, digest "), "{out}");
        assert!(
            out.contains("  extra    ab02\n  extra    ab03\n  missing  ab01\n"),
            "{out}"
        );
        assert!(
            out.contains("  extra    ab01\n  missing  ab02\n  missing  ab03\n"),
            "{out}"
        );
        assert!(
            !out.contains("ab09"),
            "a filter every archive lists is no difference: {out}"
        );
    }

    #[test]
    fn two_equal_largest_groups_and_a_third_list_have_no_majority() {
        let (x, y, z) = (list(&[2, 3], &[]), list(&[1], &[]), list(&[4], &[]));
        let (out, answered) = format_comparison(&[
            ok("a:1", x.clone()),
            ok("b:1", y.clone()),
            ok("c:1", x),
            ok("d:1", y),
            ok("e:1", z),
        ]);
        assert_eq!(answered, 5);
        assert!(out.contains("No majority view: no single largest group among the 3 lists of the 5 answering archives.\n"), "{out}");
        assert_eq!(out.matches("no majority\n").count(), 5, "{out}");
    }

    #[test]
    fn frozen_differences_alone_do_not_split_the_view() {
        let (out, _) = format_comparison(&[
            ok("a:1", list(&[2, 3], &[2])),
            ok("b:1", list(&[2, 3], &[])),
        ]);
        assert!(out.contains("All 2 answering archives agree"), "{out}");
    }

    #[test]
    fn no_answer_is_reported_and_counts_as_none_answered() {
        let (out, answered) = format_comparison(&[ArchiveReport {
            endpoint: "a:1".into(),
            result: Err("refused".into()),
        }]);
        assert_eq!(answered, 0, "the command then exits non-zero");
        assert!(
            out.contains("error: refused\n") && out.ends_with("No archive answered.\n"),
            "{out}"
        );
    }

    #[test]
    fn a_partial_or_empty_answer_is_not_compared() {
        let mut info = ArchiveShardInfo::default();
        assert_eq!(
            report_result(Ok(info.clone())),
            Err("reported no shards".into())
        );
        info.sizes.insert(vec![0xab, 2], 1);
        assert_eq!(
            report_result(Ok(info.clone())).map(|l| l.filters.len()),
            Ok(1)
        );
        info.failed_shard_keys = 1;
        assert_eq!(
            report_result(Ok(info)),
            Err("partial answer: 1 shard keys failed".into())
        );
        assert_eq!(
            report_result(Err("connect: refused\ndetail".into())),
            Err("connect: refused".into())
        );
    }

    #[test]
    fn rpc_conflicts_with_archive() {
        #[derive(clap::Parser, Debug)]
        struct Cli {
            #[command(flatten)]
            args: ShardsArgs,
        }
        use clap::Parser as _;
        assert!(Cli::try_parse_from(["shards", "--archive", "a:1", "--rpc", "b:1"]).is_err());
        assert_eq!(
            Cli::try_parse_from(["shards", "--archive", "a:1", "--archive", "b:1"])
                .unwrap()
                .args
                .archives
                .len(),
            2
        );
        assert_eq!(
            Cli::try_parse_from(["shards", "--rpc", "b:1"])
                .unwrap()
                .args
                .rpc,
            "b:1"
        );
    }

    #[test]
    fn the_grid_key_is_l1_then_the_quil_domain() {
        let key = quil_grid_shard_key();
        assert_eq!(key.len(), 35);
        assert_eq!(&key[3..], &quil_execution::domains::QUIL_TOKEN[..]);
    }
}
