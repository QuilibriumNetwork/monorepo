//! `qclient node doctor`: whether peers can dial this node, and what to do
//! when they cannot.
//!
//! It asks the local node, over its RPC, for its p2p listeners, AutoNAT's
//! view of it (status, confirmed external addresses, the current run of
//! probes without a dial-back) and the addresses its PeerInfo announces,
//! and reads the stream listen address from its config. It gives one
//! verdict per address family and transport, and advice by the kind of
//! address this host has. It only reads: it never enables UPnP and never
//! changes a firewall.

use std::io::Write as _;
use std::net::IpAddr;

use clap::Args;
use serde::Serialize;

use quil_types::proto::node::{GetNodeInfoRequest, NodeReachability};

use quil_rpc::reachability::{
    self, run_text, Assessment, Check, CheckState, Endpoint, Family, FamilyChecks, HostClass,
    ProbeRun, Verdict,
};

use crate::context::{Context, GlobalArgs};
use crate::rpc;

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

pub async fn run(global: GlobalArgs, args: &DoctorArgs) -> anyhow::Result<()> {
    let diagnosis = match observe(global).await {
        Ok(observation) => diagnose(&observation),
        Err(e) => Diagnosis::unavailable(format!("{e:#}")),
    };
    let out = if args.json {
        serde_json::to_string_pretty(&diagnosis)? + "\n"
    } else {
        render(&diagnosis)
    };
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(out.as_bytes())?;
    stdout.flush()?;
    match diagnosis.exit_code {
        0 => Ok(()),
        code => std::process::exit(code),
    }
}

/// What the doctor reads: the node's report and its config.
#[derive(Clone, Debug, Default)]
pub(crate) struct Observation {
    pub report: NodeReachability,
    /// `p2p.announceListenMultiaddr`, when set.
    pub announce_override: Option<String>,
    /// `p2p.streamListenMultiaddr`.
    pub stream_listen: String,
}

async fn observe(global: GlobalArgs) -> anyhow::Result<Observation> {
    let ctx = Context::load(global)?;
    let (config, _) = ctx.load_node_config("default").map_err(|e| {
        e.context("the doctor reads this node's config: run qclient where it finds it")
    })?;
    let opts = ctx.connect_opts(&config, false);
    anyhow::ensure!(
        !opts.is_light_node(),
        "qclient's config sets publicRpc or customRpc, so it would ask that RPC rather than \
         this node"
    );
    let mut client = rpc::connect_node_service(&opts)
        .await
        .map_err(|e| anyhow::anyhow!("ask this node for its reachability: {e}; is it running?"))?;
    let info = client
        .get_node_info(GetNodeInfoRequest {})
        .await
        .map_err(|e| anyhow::anyhow!("ask this node for its reachability: {}", e.message()))?
        .into_inner();
    let report = info.node_reachability.ok_or_else(|| {
        anyhow::anyhow!(
            "this node does not report its reachability: its release predates this command; \
             update the node"
        )
    })?;
    Ok(Observation {
        report,
        announce_override: Some(config.p2p.announce_listen_multiaddr)
            .filter(|addr| !addr.is_empty()),
        stream_listen: config.p2p.stream_listen_multiaddr,
    })
}

/// A port to open or forward.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Port {
    pub port: u16,
    /// `tcp` or `udp`.
    pub protocol: &'static str,
}

impl std::fmt::Display for Port {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.port, self.protocol)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct FirewallCommand {
    pub tool: &'static str,
    pub command: String,
}

/// What to do about a family that is not reachable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Advice {
    /// A public host address whose probes fail: open the ports.
    OpenFirewall {
        ports: Vec<Port>,
        commands: Vec<FirewallCommand>,
    },
    /// A private host address: forward the ports on the router.
    ForwardOnRouter {
        host_address: String,
        ports: Vec<Port>,
    },
    /// A carrier-grade NAT host address: no forward on this side helps.
    CarrierGradeNat { host_address: String },
    /// No usable host address seen: forward or open the ports.
    OpenOrForward { ports: Vec<Port> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct FamilyReport {
    pub family: Family,
    /// This host's address that decides the advice, and its class.
    pub host_address: Option<String>,
    pub host_class: Option<HostClass>,
    pub checks: Vec<Check>,
    pub advice: Option<Advice>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Announced {
    pub published: bool,
    pub pubsub: Vec<String>,
    pub stream: Vec<String>,
    /// Where the pubsub address comes from: `config`
    /// (p2p.announceListenMultiaddr), `autonat`, `listen_address`, `none`,
    /// or `unpublished`.
    pub source: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Diagnosis {
    pub verdict: Verdict,
    pub exit_code: i32,
    /// AutoNAT's status: `public`, `private` or `unknown`.
    pub nat_status: String,
    pub probe_failure: Option<ProbeRun>,
    pub families: Vec<FamilyReport>,
    pub announced: Option<Announced>,
    /// The stream port (TCP), which AutoNAT does not probe.
    pub stream_port: Option<u16>,
    pub notes: Vec<String>,
    /// Why nothing could be read.
    pub error: Option<String>,
}

impl Diagnosis {
    fn unavailable(error: String) -> Self {
        Diagnosis {
            verdict: Verdict::Unknown,
            exit_code: Verdict::Unknown.exit_code(),
            nat_status: "unknown".to_string(),
            probe_failure: None,
            families: Vec::new(),
            announced: None,
            stream_port: None,
            notes: Vec::new(),
            error: Some(error),
        }
    }
}

/// The verdicts and advice for `obs`.
pub(crate) fn diagnose(obs: &Observation) -> Diagnosis {
    let report = &obs.report;
    let Assessment {
        verdict,
        families,
        probe_failure,
        ipv6_note,
    } = reachability::assess(report);
    let stream = Endpoint::parse(&obs.stream_listen);
    let reports: Vec<FamilyReport> = families
        .into_iter()
        .map(|checked| {
            let FamilyChecks {
                family,
                host,
                checks,
            } = checked;
            let advice = checks
                .iter()
                .any(|c| c.state == CheckState::NotReachable)
                .then(|| {
                    let mut ports: Vec<Port> = checks
                        .iter()
                        .filter(|c| c.state != CheckState::Reachable)
                        .filter_map(|c| {
                            c.port.map(|port| Port {
                                port,
                                protocol: c.transport.protocol(),
                            })
                        })
                        .collect();
                    if let Some(stream) = stream.filter(|s| s.family() == family) {
                        let port = Port {
                            port: stream.port,
                            protocol: "tcp",
                        };
                        if !ports.contains(&port) {
                            ports.push(port);
                        }
                    }
                    advice(host, ports)
                });
            FamilyReport {
                family,
                host_address: host.map(|(ip, _)| ip.to_string()),
                host_class: host.map(|(_, class)| class),
                checks,
                advice,
            }
        })
        .collect();

    let announced_view = Announced {
        published: report.announced,
        pubsub: report.announced_pubsub_multiaddrs.clone(),
        stream: report.announced_stream_multiaddrs.clone(),
        source: if !report.announced {
            "unpublished"
        } else if report.announced_pubsub_multiaddrs.is_empty() {
            "none"
        } else if obs.announce_override.is_some() {
            "config"
        } else if report
            .announced_pubsub_multiaddrs
            .iter()
            .any(|a| report.confirmed_multiaddrs.contains(a))
        {
            "autonat"
        } else {
            "listen_address"
        },
    };

    let mut notes = Vec::new();
    if let Some(stream) = stream {
        notes.push(format!(
            "AutoNAT does not probe the stream port {}/tcp; peers dial it too, so keep it open.",
            stream.port
        ));
    }
    if !report
        .listen_multiaddrs
        .iter()
        .any(|a| Endpoint::parse(a).is_some())
    {
        notes.push("The node reports no p2p listener; see its startup log lines.".to_string());
    }
    notes.extend(ipv6_note.map(|note| note.text()));
    if verdict != Verdict::Reachable {
        notes.push(
            "This command changes nothing. AutoNAT probes again within 15 min; rerun it after \
             a change."
                .to_string(),
        );
    }

    Diagnosis {
        verdict,
        exit_code: verdict.exit_code(),
        nat_status: report.nat_status.clone(),
        probe_failure,
        families: reports,
        announced: Some(announced_view),
        stream_port: stream.map(|s| s.port),
        notes,
        error: None,
    }
}

fn advice(host: Option<(IpAddr, HostClass)>, ports: Vec<Port>) -> Advice {
    match host {
        Some((_, HostClass::Public)) => Advice::OpenFirewall {
            commands: firewall_commands(&ports),
            ports,
        },
        Some((ip, HostClass::Private)) => Advice::ForwardOnRouter {
            host_address: ip.to_string(),
            ports,
        },
        Some((ip, HostClass::Cgnat)) => Advice::CarrierGradeNat {
            host_address: ip.to_string(),
        },
        None => Advice::OpenOrForward { ports },
    }
}

/// ufw, nftables and firewalld commands that open `ports`.
fn firewall_commands(ports: &[Port]) -> Vec<FirewallCommand> {
    let ufw = ports
        .iter()
        .map(|p| format!("sudo ufw allow {p}"))
        .collect::<Vec<_>>()
        .join(" && ");
    let nft = ["tcp", "udp"]
        .into_iter()
        .filter_map(|protocol| {
            let of: Vec<String> = ports
                .iter()
                .filter(|p| p.protocol == protocol)
                .map(|p| p.port.to_string())
                .collect();
            let set = match of.len() {
                0 => return None,
                1 => of[0].clone(),
                _ => format!("{{ {} }}", of.join(", ")),
            };
            Some(format!(
                "sudo nft add rule inet filter input {protocol} dport {set} accept"
            ))
        })
        .collect::<Vec<_>>()
        .join(" && ");
    let firewalld = format!(
        "sudo firewall-cmd --permanent {} && sudo firewall-cmd --reload",
        ports
            .iter()
            .map(|p| format!("--add-port={p}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    vec![
        FirewallCommand {
            tool: "ufw",
            command: ufw,
        },
        FirewallCommand {
            tool: "nftables",
            command: nft,
        },
        FirewallCommand {
            tool: "firewalld",
            command: firewalld,
        },
    ]
}

fn ports_text(ports: &[Port]) -> String {
    ports
        .iter()
        .map(Port::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The plain-text report.
pub(crate) fn render(d: &Diagnosis) -> String {
    let mut out = format!("Reachability of this node: {}\n", d.verdict.label());
    if let Some(error) = &d.error {
        out += &format!("{error}\n");
        return out;
    }
    out += &format!("AutoNAT status: {}", d.nat_status);
    if let Some(run) = &d.probe_failure {
        out += &format!("; {}", run_text(run));
    }
    out += "\n";
    for family in &d.families {
        out += &format!("\n{}", family.family.label());
        if let (Some(ip), Some(class)) = (&family.host_address, family.host_class) {
            let class = match class {
                HostClass::Public => "public",
                HostClass::Private => "private",
                HostClass::Cgnat => "carrier-grade NAT",
            };
            out += &format!(", host address {ip} ({class})");
        }
        out += "\n";
        for c in &family.checks {
            let port = c.port.map_or(String::new(), |p| p.to_string());
            out += &format!(
                "  {:<4} {:<5} {:<13}",
                c.transport.label(),
                port,
                c.state.label()
            );
            if c.state != CheckState::NoListener {
                out += &format!(" {}", c.evidence);
            }
            out = out.trim_end().to_string() + "\n";
        }
    }
    if let Some(a) = &d.announced {
        out += "\nAnnounced: ";
        out += &match a.source {
            "unpublished" => "no PeerInfo published yet".to_string(),
            "none" => {
                "no address; peers cannot dial this node until AutoNAT confirms one".to_string()
            }
            source => {
                let from = match source {
                    "config" => "from p2p.announceListenMultiaddr",
                    "autonat" => "confirmed by AutoNAT",
                    _ => "the listen address",
                };
                let mut text = format!("{} ({from})", a.pubsub.join(", "));
                if !a.stream.is_empty() {
                    text += &format!(", stream {}", a.stream.join(", "));
                }
                text
            }
        };
        out += "\n";
    }
    for family in &d.families {
        let Some(advice) = &family.advice else {
            continue;
        };
        out += &format!("\nTo make {} reachable:\n", family.family.label());
        match advice {
            Advice::OpenFirewall { ports, commands } => {
                out += &format!(
                    "This host's address is public, so a firewall on it or at its provider \
                     likely drops inbound connections. Open {}:\n",
                    ports_text(ports)
                );
                for c in commands {
                    out += &format!("  {:<10} {}\n", c.tool, c.command);
                }
                out += "On a cloud server, also allow them in its security group or network \
                        firewall.\n";
            }
            Advice::ForwardOnRouter {
                host_address,
                ports,
            } => {
                out += &format!(
                    "This host's address is private, behind a router's NAT. Forward {} on the \
                     router to {host_address}, and allow them in this host's firewall if it \
                     runs one.\n",
                    ports_text(ports)
                );
                if family.family == Family::Ipv4 {
                    out += "If the router's own WAN address is in 100.64.0.0/10, or it has no \
                            public IPv4 address (DS-Lite), the ISP uses carrier-grade NAT and no \
                            forward helps: ask it for a public IPv4 address, or run the node on \
                            a VPS.\n";
                }
            }
            Advice::CarrierGradeNat { host_address } => {
                out += &format!(
                    "{host_address} is in 100.64.0.0/10, the ISP's carrier-grade NAT, which \
                     drops inbound connections; no port forward on this side helps. Ask the \
                     ISP for a public IP address, or run the node on a VPS.\n"
                );
            }
            Advice::OpenOrForward { ports } => {
                out += &format!(
                    "Forward {} to this host on its router, or open them in its firewall.\n",
                    ports_text(ports)
                );
            }
        }
    }
    if !d.notes.is_empty() {
        out += "\n";
        for note in &d.notes {
            out += &format!("{note}\n");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_rpc::reachability::{ip_class, IpClass, Transport};
    use quil_types::proto::node::AutonatProbeFailure;

    const STREAM: &str = "/ip4/0.0.0.0/tcp/8340";

    fn observation(listen: &[&str], nat_status: &str, confirmed: &[&str]) -> Observation {
        Observation {
            report: NodeReachability {
                listen_multiaddrs: listen.iter().map(|s| s.to_string()).collect(),
                nat_status: nat_status.to_string(),
                confirmed_multiaddrs: confirmed.iter().map(|s| s.to_string()).collect(),
                probe_failure: None,
                announced: true,
                announced_pubsub_multiaddrs: confirmed
                    .first()
                    .map(|s| s.to_string())
                    .into_iter()
                    .collect(),
                announced_stream_multiaddrs: Vec::new(),
            },
            announce_override: None,
            stream_listen: STREAM.to_string(),
        }
    }

    fn failing(
        class: &str,
        probes: u32,
        secs: u64,
        unreachable: bool,
    ) -> Option<AutonatProbeFailure> {
        Some(AutonatProbeFailure {
            class: class.to_string(),
            probes,
            failing_secs: secs,
            unreachable,
        })
    }

    fn state(d: &Diagnosis, family: Family, transport: Transport) -> CheckState {
        d.families
            .iter()
            .find(|f| f.family == family)
            .and_then(|f| f.checks.iter().find(|c| c.transport == transport))
            .map(|c| c.state)
            .unwrap_or_else(|| panic!("no {family:?} {transport:?} check in {d:#?}"))
    }

    fn port(port: u16, protocol: &'static str) -> Port {
        Port { port, protocol }
    }

    #[test]
    fn a_confirmed_address_is_reachable_with_its_evidence() {
        // AutoNAT may hold a reachable node private (servers that refuse a
        // dial-back report it as failed); the confirmed address decides.
        let obs = observation(
            &["/ip4/127.0.0.1/tcp/8336", "/ip4/203.0.113.7/tcp/8336"],
            "private",
            &["/ip4/203.0.113.7/tcp/8336"],
        );
        let d = diagnose(&obs);
        assert_eq!(d.verdict, Verdict::Reachable);
        assert_eq!(d.exit_code, 0);
        assert_eq!(d.families.len(), 1, "no IPv6 without an IPv6 address");
        assert_eq!(
            state(&d, Family::Ipv4, Transport::Tcp),
            CheckState::Reachable
        );
        assert_eq!(
            state(&d, Family::Ipv4, Transport::Quic),
            CheckState::NoListener
        );
        assert_eq!(d.families[0].advice, None);
        assert_eq!(d.announced.as_ref().unwrap().source, "autonat");
        let text = render(&d);
        assert!(
            text.starts_with("Reachability of this node: reachable\n"),
            "{text}"
        );
        assert!(
            text.contains("TCP  8336  reachable     AutoNAT servers dialed this node back at 203.0.113.7:8336"),
            "{text}"
        );
        assert!(text.contains("stream port 8340/tcp"), "{text}");
        assert!(!text.contains("rerun"), "{text}");
    }

    #[test]
    fn a_public_host_whose_probes_fail_gets_firewall_commands() {
        let mut obs = observation(
            &[
                "/ip4/127.0.0.1/tcp/8336",
                "/ip4/198.51.100.4/tcp/8336",
                "/ip4/198.51.100.4/udp/8336/quic-v1",
            ],
            "unknown",
            &[],
        );
        obs.report.probe_failure = failing("dial_error", 14, 1_920, true);
        let d = diagnose(&obs);
        assert_eq!(d.verdict, Verdict::NotReachable);
        assert_eq!(d.exit_code, 1);
        assert_eq!(
            state(&d, Family::Ipv4, Transport::Tcp),
            CheckState::NotReachable
        );
        assert_eq!(
            state(&d, Family::Ipv4, Transport::Quic),
            CheckState::NotReachable
        );
        let Some(Advice::OpenFirewall { ports, commands }) = &d.families[0].advice else {
            panic!("{d:#?}");
        };
        assert_eq!(
            ports,
            &[port(8336, "tcp"), port(8336, "udp"), port(8340, "tcp")]
        );
        let commands: Vec<(&str, &str)> = commands
            .iter()
            .map(|c| (c.tool, c.command.as_str()))
            .collect();
        assert_eq!(
            commands,
            [
                (
                    "ufw",
                    "sudo ufw allow 8336/tcp && sudo ufw allow 8336/udp && sudo ufw allow 8340/tcp"
                ),
                (
                    "nftables",
                    "sudo nft add rule inet filter input tcp dport { 8336, 8340 } accept && \
                     sudo nft add rule inet filter input udp dport 8336 accept"
                ),
                (
                    "firewalld",
                    "sudo firewall-cmd --permanent --add-port=8336/tcp --add-port=8336/udp \
                     --add-port=8340/tcp && sudo firewall-cmd --reload"
                ),
            ]
        );
        let text = render(&d);
        assert!(
            text.contains("14 probes in a row without a dial-back over 32 min, mostly dial_error"),
            "{text}"
        );
        assert!(text.contains("security group"), "{text}");
        assert!(text.contains("rerun"), "{text}");
    }

    #[test]
    fn a_private_host_is_told_to_forward_ports_on_its_router() {
        // A VPN's shared-range address beside the LAN address does not make
        // the host CGNAT.
        let obs = observation(
            &[
                "/ip4/127.0.0.1/tcp/8336",
                "/ip4/100.101.102.103/tcp/8336",
                "/ip4/192.168.1.20/tcp/8336",
            ],
            "private",
            &[],
        );
        let d = diagnose(&obs);
        assert_eq!(d.verdict, Verdict::NotReachable);
        assert_eq!(d.families[0].host_class, Some(HostClass::Private));
        assert_eq!(
            d.families[0].advice,
            Some(Advice::ForwardOnRouter {
                host_address: "192.168.1.20".to_string(),
                ports: vec![port(8336, "tcp"), port(8340, "tcp")],
            })
        );
        let text = render(&d);
        assert!(
            text.contains("Forward 8336/tcp, 8340/tcp on the router to 192.168.1.20"),
            "{text}"
        );
        assert!(text.contains("100.64.0.0/10"), "{text}");
    }

    #[test]
    fn a_carrier_grade_nat_host_needs_a_public_ip_or_a_vps() {
        // No probe has finished, but nothing can dial in through the ISP's
        // NAT.
        let obs = observation(
            &["/ip4/127.0.0.1/tcp/8336", "/ip4/100.72.3.4/tcp/8336"],
            "unknown",
            &[],
        );
        let d = diagnose(&obs);
        assert_eq!(d.verdict, Verdict::NotReachable);
        assert_eq!(
            state(&d, Family::Ipv4, Transport::Tcp),
            CheckState::NotReachable
        );
        assert_eq!(
            d.families[0].advice,
            Some(Advice::CarrierGradeNat {
                host_address: "100.72.3.4".to_string()
            })
        );
        let text = render(&d);
        assert!(
            text.contains("public IP address, or run the node on a VPS"),
            "{text}"
        );
    }

    #[test]
    fn unsettled_or_inconclusive_probes_are_unknown() {
        let listen = ["/ip4/203.0.113.7/tcp/8336"];
        // No probe finished yet.
        let d = diagnose(&observation(&listen, "unknown", &[]));
        assert_eq!(d.verdict, Verdict::Unknown);
        assert_eq!(d.exit_code, 2);
        assert_eq!(d.families[0].advice, None);
        assert!(render(&d).contains("AutoNAT has finished no probe yet"));
        // Requests that fail before any dial-back tell nothing.
        let mut obs = observation(&listen, "unknown", &[]);
        obs.report.probe_failure = failing("io", 5, 600, false);
        let d = diagnose(&obs);
        assert_eq!(d.verdict, Verdict::Unknown);
        assert!(render(&d).contains("5 probes in a row without a dial-back over 10 min, mostly io"));
        // Dial errors from servers on one IP only are not yet a verdict.
        obs.report.probe_failure = failing("dial_error", 3, 200, false);
        assert_eq!(diagnose(&obs).verdict, Verdict::Unknown);
        // An unreadable node is unknown too.
        let d = Diagnosis::unavailable("this node does not report its reachability".into());
        assert_eq!((d.verdict, d.exit_code), (Verdict::Unknown, 2));
        assert!(render(&d).contains("does not report its reachability"));
    }

    #[test]
    fn ipv6_is_checked_apart_from_ipv4() {
        let listen = [
            "/ip4/203.0.113.7/tcp/8336",
            "/ip6/::1/tcp/8336",
            "/ip6/2001:db8::7/tcp/8336",
            "/ip6/2001:db8::7/udp/8336/quic-v1",
        ];
        let d = diagnose(&observation(
            &listen,
            "public",
            &["/ip4/203.0.113.7/tcp/8336"],
        ));
        assert_eq!(d.verdict, Verdict::Reachable);
        assert_eq!(
            state(&d, Family::Ipv4, Transport::Tcp),
            CheckState::Reachable
        );
        assert_eq!(state(&d, Family::Ipv6, Transport::Tcp), CheckState::Unknown);
        assert_eq!(
            state(&d, Family::Ipv6, Transport::Quic),
            CheckState::Unknown
        );
        let d = diagnose(&observation(
            &listen,
            "public",
            &["/ip6/2001:db8::7/udp/8336/quic-v1"],
        ));
        assert_eq!(
            state(&d, Family::Ipv6, Transport::Quic),
            CheckState::Reachable
        );
        assert_eq!(state(&d, Family::Ipv4, Transport::Tcp), CheckState::Unknown);
        assert!(render(&d).contains("dialed this node back at [2001:db8::7]:8336"));
        // With both families listened on, AutoNAT's failures name neither.
        let mut obs = observation(&listen, "private", &[]);
        obs.report.probe_failure = failing("dial_error", 14, 1_920, true);
        let d = diagnose(&obs);
        assert_eq!(d.verdict, Verdict::Unknown);
        assert_eq!(state(&d, Family::Ipv6, Transport::Tcp), CheckState::Unknown);
    }

    /// The notes that speak about IPv6.
    fn ipv6_notes(d: &Diagnosis) -> Vec<&str> {
        d.notes
            .iter()
            .map(String::as_str)
            .filter(|note| note.contains("IPv6"))
            .collect()
    }

    #[test]
    fn a_node_that_binds_no_ipv6_says_so_and_promises_nothing() {
        // DS-Lite: a private IPv4 address behind the ISP's NAT.
        let mut obs = observation(
            &["/ip4/127.0.0.1/tcp/8336", "/ip4/192.168.1.20/tcp/8336"],
            "private",
            &[],
        );
        obs.report.probe_failure = failing("dial_error", 14, 1_920, true);
        let d = diagnose(&obs);
        assert_eq!(
            ipv6_notes(&d),
            ["IPv6: this node binds no address peers could dial and publishes none."]
        );
        let text = render(&d);
        assert!(
            text.contains("no public IPv4 address (DS-Lite)")
                && text.contains("ask it for a public IPv4 address"),
            "{text}"
        );
        // A loopback IPv6 listener is no address peers could dial.
        let d = diagnose(&observation(
            &["/ip4/192.168.1.20/tcp/8336", "/ip6/::1/tcp/8336"],
            "private",
            &[],
        ));
        assert_eq!(
            ipv6_notes(&d),
            ["IPv6: this node binds no address peers could dial and publishes none."]
        );
        // A node peers reach over IPv4 needs no word about IPv6.
        let d = diagnose(&observation(
            &["/ip4/203.0.113.7/tcp/8336"],
            "public",
            &["/ip4/203.0.113.7/tcp/8336"],
        ));
        assert!(ipv6_notes(&d).is_empty(), "{:?}", d.notes);
    }

    #[test]
    fn a_bound_ipv6_address_is_never_called_unbound() {
        let listen = [
            "/ip4/192.168.1.20/tcp/8336",
            "/ip6/2001:db8::7/tcp/8336",
            "/ip6/2001:db8::7/udp/8336/quic-v1",
        ];
        // Bound, not published: named, whatever the verdict.
        let mut obs = observation(&listen, "unknown", &[]);
        let d = diagnose(&obs);
        assert_eq!(
            ipv6_notes(&d),
            ["IPv6: this node binds [2001:db8::7]:8336 but publishes no IPv6 address, so peers do not learn it."]
        );
        // No PeerInfo yet says nothing about what it will publish.
        obs.report.announced = false;
        assert!(ipv6_notes(&diagnose(&obs)).is_empty());
        // Bound, published, not confirmed: the checks speak; no note.
        let mut obs = observation(&listen, "unknown", &[]);
        obs.report
            .announced_pubsub_multiaddrs
            .push("/ip6/2001:db8::7/tcp/8336".to_string());
        let d = diagnose(&obs);
        assert!(ipv6_notes(&d).is_empty(), "{:?}", d.notes);
        assert_eq!(d.verdict, Verdict::Unknown);
        // Confirmed on IPv6 alone: reachable, with who cannot dial it.
        let d = diagnose(&observation(
            &listen,
            "public",
            &["/ip6/2001:db8::7/udp/8336/quic-v1"],
        ));
        assert_eq!(d.verdict, Verdict::Reachable);
        assert_eq!(
            ipv6_notes(&d),
            ["AutoNAT confirmed IPv6 only, so peers with IPv4 alone may not reach this node."]
        );
        // Confirmed on both: nothing to add.
        let d = diagnose(&observation(
            &listen,
            "public",
            &[
                "/ip6/2001:db8::7/udp/8336/quic-v1",
                "/ip4/203.0.113.7/tcp/8336",
            ],
        ));
        assert!(ipv6_notes(&d).is_empty(), "{:?}", d.notes);
    }

    #[test]
    fn a_private_ipv6_address_gets_no_ipv4_nat_advice() {
        let mut obs = observation(&["/ip6/fd00::7/tcp/8336"], "private", &[]);
        obs.report.probe_failure = failing("dial_error", 14, 1_920, true);
        let text = render(&diagnose(&obs));
        assert!(text.contains("To make IPv6 reachable"), "{text}");
        assert!(!text.contains("DS-Lite"), "{text}");
    }

    #[test]
    fn json_names_the_verdict_exit_code_and_advice() {
        let mut obs = observation(&["/ip4/192.168.1.20/tcp/8336"], "private", &[]);
        obs.report.probe_failure = failing("dial_error", 14, 1_920, true);
        let json = serde_json::to_value(diagnose(&obs)).unwrap();
        assert_eq!(json["verdict"], "not_reachable");
        assert_eq!(json["exit_code"], 1);
        assert_eq!(json["families"][0]["family"], "ipv4");
        assert_eq!(json["families"][0]["checks"][0]["state"], "not_reachable");
        assert_eq!(json["families"][0]["checks"][1]["state"], "no_listener");
        assert_eq!(json["families"][0]["advice"]["kind"], "forward_on_router");
        assert_eq!(json["families"][0]["advice"]["ports"][1]["port"], 8340);
        assert_eq!(json["probe_failure"]["probes"], 14);
    }

    #[test]
    fn host_addresses_are_classified_by_network() {
        let cases = [
            ("203.0.113.7", IpClass::Public),
            ("192.168.1.20", IpClass::Private),
            ("10.1.2.3", IpClass::Private),
            ("100.64.0.1", IpClass::Shared),
            ("100.127.255.255", IpClass::Shared),
            ("100.128.0.0", IpClass::Public),
            ("127.0.0.1", IpClass::Local),
            ("169.254.1.1", IpClass::Local),
            ("2001:db8::7", IpClass::Public),
            ("fd00::1", IpClass::Private),
            ("fe80::1", IpClass::Local),
            ("::ffff:100.64.0.1", IpClass::Shared),
        ];
        for (ip, class) in cases {
            assert_eq!(ip_class(ip.parse().unwrap()), class, "{ip}");
        }
    }
}
