//! The gossip traffic section of `qclient node prover status`: the node's
//! gossip messages by class, from the master's report and those of the
//! standalone workers, which run their own swarm.

use quil_types::proto::node::{GossipClassTraffic, GossipTraffic, WorkerInfo};

/// Report classes in display order; a class this client does not know
/// counts as other.
const CLASSES: [(&str, &str); 6] = [
    ("shard_consensus", "Shard consensus"),
    ("shard_frames", "Shard frames"),
    ("votes", "Votes"),
    ("global", "GLOBAL"),
    ("peer_info", "Peer info"),
    ("other", "Other"),
];
const OTHER: usize = 5;

const FOOTNOTES: [&str; 4] = [
    "Mbit/s over each process's uptime. In: every copy received; Unique: first copies;",
    "Out: every copy sent, own and forwarded; Own: this node's publishes, once each.",
    "Encoded message bytes without gossip control messages and transport overhead;",
    "workers that share the master's swarm are in its counts.",
];

#[derive(Clone, Copy, Default)]
struct Row {
    received: f64,
    unique: f64,
    sent: f64,
    published: f64,
    received_bytes: u64,
    sent_bytes: u64,
}

impl Row {
    fn add(&mut self, class: &GossipClassTraffic, secs: f64) {
        let rate = |bytes: u64| {
            if secs > 0.0 {
                bytes as f64 * 8.0 / 1e6 / secs
            } else {
                0.0
            }
        };
        self.received += rate(class.received_bytes);
        self.unique += rate(class.unique_bytes);
        self.sent += rate(class.sent_bytes);
        self.published += rate(class.published_bytes);
        self.received_bytes = self.received_bytes.saturating_add(class.received_bytes);
        self.sent_bytes = self.sent_bytes.saturating_add(class.sent_bytes);
    }

    fn add_row(&mut self, other: &Row) {
        self.received += other.received;
        self.unique += other.unique;
        self.sent += other.sent;
        self.published += other.published;
        self.received_bytes = self.received_bytes.saturating_add(other.received_bytes);
        self.sent_bytes = self.sent_bytes.saturating_add(other.sent_bytes);
    }
}

/// Mbit/s with two decimals; a trickle below that shows as `<0.01`, not as
/// nothing.
fn rate(mbps: f64) -> String {
    if mbps > 0.0 && mbps < 0.005 {
        "<0.01".to_string()
    } else {
        format!("{mbps:.2}")
    }
}

/// Bytes in decimal units, like the Mbit/s rates.
fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["kB", "MB", "GB", "TB", "PB"];
    if n < 1000 {
        return format!("{n} B");
    }
    let mut value = n as f64 / 1000.0;
    let mut unit = 0;
    while value >= 999.95 && unit + 1 < UNITS.len() {
        value /= 1000.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

fn uptime(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, hours, minutes) = (secs / 86_400, secs / 3_600 % 24, secs / 60 % 60);
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m")
    } else {
        format!("{secs}s")
    }
}

/// The section's lines: the master's traffic (`master`, absent from older
/// nodes) and every worker's that reports its own.
pub(crate) fn render(master: Option<&GossipTraffic>, workers: &[WorkerInfo]) -> String {
    let own: Vec<&GossipTraffic> = workers
        .iter()
        .filter_map(|w| w.execution.as_ref().and_then(|e| e.gossip_traffic.as_ref()))
        .collect();
    let Some(master) = master else {
        return "Gossip Traffic:     not reported by this node".to_string();
    };
    let mut rows = [Row::default(); CLASSES.len()];
    for process in std::iter::once(master).chain(own.iter().copied()) {
        let secs = process.uptime_ms as f64 / 1000.0;
        for class in &process.classes {
            let row = CLASSES
                .iter()
                .position(|(name, _)| *name == class.class)
                .unwrap_or(OTHER);
            rows[row].add(class, secs);
        }
    }
    let mut total = Row::default();
    rows.iter().for_each(|row| total.add_row(row));

    let mut lines = vec![
        format!(
            "Gossip Traffic (master up {}; {} of {} workers report their own swarm):",
            uptime(master.uptime_ms),
            own.len(),
            workers.len()
        ),
        format!(
            "  {:<16} {:>8} {:>8} {:>8} {:>8} {:>10} {:>10}",
            "Class", "In", "Unique", "Out", "Own", "In total", "Out total"
        ),
    ];
    let line = |label: &str, row: &Row| {
        format!(
            "  {:<16} {:>8} {:>8} {:>8} {:>8} {:>10} {:>10}",
            label,
            rate(row.received),
            rate(row.unique),
            rate(row.sent),
            rate(row.published),
            bytes(row.received_bytes),
            bytes(row.sent_bytes)
        )
    };
    for ((_, label), row) in CLASSES.iter().zip(&rows) {
        lines.push(line(label, row));
    }
    lines.push(line("Total", &total));
    lines.extend(FOOTNOTES.iter().map(|line| format!("  {line}")));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;
    use quil_types::proto::node::node_service_server::NodeService as _;
    use quil_types::proto::node::{GetNodeInfoRequest, NodeInfoResponse, WorkerExecution};

    fn class(
        name: &str,
        received: u64,
        unique: u64,
        sent: u64,
        published: u64,
    ) -> GossipClassTraffic {
        GossipClassTraffic {
            class: name.into(),
            received_messages: received / 1000,
            received_bytes: received,
            unique_messages: unique / 1000,
            unique_bytes: unique,
            sent_messages: sent / 1000,
            sent_bytes: sent,
            published_messages: published / 1000,
            published_bytes: published,
        }
    }

    fn worker(core_id: u32, traffic: Option<GossipTraffic>) -> WorkerInfo {
        WorkerInfo {
            core_id,
            execution: Some(WorkerExecution {
                state: "running".into(),
                gossip_traffic: traffic,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// The counters the node keeps reach the client through `GetNodeInfo`
    /// on the wire, class by class.
    #[tokio::test]
    async fn node_info_carries_the_process_gossip_traffic() {
        use quil_p2p::{GossipClass, TrafficKind};
        let counters = std::sync::Arc::new(quil_p2p::GossipTraffic::default());
        counters.record(TrafficKind::Received, GossipClass::Votes, 700);
        counters.record(TrafficKind::Received, GossipClass::Votes, 700);
        counters.record(TrafficKind::FirstReceived, GossipClass::Votes, 700);
        counters.record(TrafficKind::Sent, GossipClass::ShardFrames, 90_000);
        counters.record(TrafficKind::Published, GossipClass::ShardFrames, 90_000);
        let server = quil_rpc::NodeRpcServer::default().with_gossip_traffic(counters.clone());
        let response = server
            .get_node_info(tonic::Request::new(GetNodeInfoRequest {}))
            .await
            .unwrap()
            .into_inner();
        let decoded = NodeInfoResponse::decode(response.encode_to_vec().as_slice()).unwrap();
        let traffic = decoded.gossip_traffic.expect("reported");
        let names: Vec<&str> = traffic.classes.iter().map(|c| c.class.as_str()).collect();
        assert_eq!(names, CLASSES.map(|(name, _)| name));
        let by = |name: &str| {
            traffic
                .classes
                .iter()
                .find(|c| c.class == name)
                .unwrap()
                .clone()
        };
        assert_eq!(
            by("votes"),
            class("votes", 1_400, 700, 0, 0).with_messages(2, 1, 0, 0)
        );
        assert_eq!(
            by("shard_frames"),
            class("shard_frames", 0, 0, 90_000, 90_000).with_messages(0, 0, 1, 1)
        );
        for name in ["shard_consensus", "global", "peer_info", "other"] {
            assert_eq!(by(name), class(name, 0, 0, 0, 0));
        }
        assert!(traffic.uptime_ms <= counters.snapshot().uptime.as_millis() as u64);

        // A node without counters, like an older one, leaves the field out.
        let older = quil_rpc::NodeRpcServer::default();
        let response = older
            .get_node_info(tonic::Request::new(GetNodeInfoRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.gossip_traffic, None);
        assert_eq!(
            render(None, &[]),
            "Gossip Traffic:     not reported by this node"
        );
    }

    trait WithMessages {
        fn with_messages(self, received: u64, unique: u64, sent: u64, published: u64) -> Self;
    }

    impl WithMessages for GossipClassTraffic {
        fn with_messages(mut self, received: u64, unique: u64, sent: u64, published: u64) -> Self {
            self.received_messages = received;
            self.unique_messages = unique;
            self.sent_messages = sent;
            self.published_messages = published;
            self
        }
    }

    #[test]
    fn the_table_sums_the_master_and_reporting_workers_per_class() {
        // The master, up 2 h, and one of three workers, up 1 h.
        let master = GossipTraffic {
            uptime_ms: 7_200_000,
            classes: vec![
                class(
                    "shard_consensus",
                    900_000_000,
                    300_000_000,
                    1_800_000_000,
                    9_000_000,
                ),
                class("votes", 0, 0, 0, 0),
                class("global", 3_600_000_000, 450_000_000, 5_400_000_000, 0),
                class("peer_info", 450_000_000, 45_000_000, 900_000_000, 900_000),
                class("other", 900, 900, 0, 0),
                // A class this client does not know counts as other.
                class("someday", 9_000, 0, 0, 0),
            ],
        };
        let own = GossipTraffic {
            uptime_ms: 3_600_000,
            classes: vec![
                class(
                    "shard_consensus",
                    2_700_000_000,
                    900_000_000,
                    9_000_000_000,
                    45_000_000,
                ),
                class(
                    "shard_frames",
                    450_000_000,
                    90_000_000,
                    900_000_000,
                    4_500_000,
                ),
                class("votes", 225_000_000, 45_000_000, 540_000_000, 2_700_000),
            ],
        };
        let workers = [
            worker(1, Some(own)),
            worker(2, None),
            WorkerInfo {
                core_id: 3,
                ..Default::default()
            },
        ];
        let text = render(Some(&master), &workers);
        println!("{text}");
        let expected = "\
Gossip Traffic (master up 2h 0m; 1 of 3 workers report their own swarm):
  Class                  In   Unique      Out      Own   In total  Out total
  Shard consensus      7.00     2.33    22.00     0.11     3.6 GB    10.8 GB
  Shard frames         1.00     0.20     2.00     0.01   450.0 MB   900.0 MB
  Votes                0.50     0.10     1.20     0.01   225.0 MB   540.0 MB
  GLOBAL               4.00     0.50     6.00     0.00     3.6 GB     5.4 GB
  Peer info            0.50     0.05     1.00    <0.01   450.0 MB   900.0 MB
  Other               <0.01    <0.01     0.00     0.00     9.9 kB        0 B
  Total               13.00     3.18    32.20     0.13     8.3 GB    18.5 GB
  Mbit/s over each process's uptime. In: every copy received; Unique: first copies;
  Out: every copy sent, own and forwarded; Own: this node's publishes, once each.
  Encoded message bytes without gossip control messages and transport overhead;
  workers that share the master's swarm are in its counts.";
        assert_eq!(text, expected);
    }
}
