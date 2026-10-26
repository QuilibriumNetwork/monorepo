use super::*;

fn some_peer() -> PeerId {
    Keypair::generate_ed25519().public().to_peer_id()
}

fn doc_addr() -> SocketAddr {
    "192.0.2.1:8336".parse().unwrap()
}

fn parse_err(multiaddr: &str, peer: Option<&str>) -> String {
    parse_target(multiaddr, peer).unwrap_err().to_string()
}

#[test]
fn parses_a_tcp_address_without_a_peer_id() {
    let target = parse_target(" /ip4/198.51.100.7/tcp/8336 ", None).unwrap();
    assert_eq!(target.host, Host::Ip("198.51.100.7".parse().unwrap()));
    assert_eq!(target.port, 8336);
    assert_eq!(target.carrier, Carrier::Tcp);
    assert_eq!(target.expected, None);
}

#[test]
fn takes_the_expected_peer_from_p2p_or_the_flag() {
    let peer = some_peer();
    let target = parse_target(&format!("/ip6/2001:db8::7/tcp/8336/p2p/{peer}"), None).unwrap();
    assert_eq!(target.host, Host::Ip("2001:db8::7".parse().unwrap()));
    assert_eq!(
        target.expected,
        Some(Expected {
            peer,
            source: "/p2p"
        })
    );

    let target = parse_target("/ip4/198.51.100.7/tcp/8336", Some(&peer.to_string())).unwrap();
    assert_eq!(
        target.expected,
        Some(Expected {
            peer,
            source: "--peer"
        })
    );

    let both = parse_target(
        &format!("/ip4/198.51.100.7/tcp/8336/p2p/{peer}"),
        Some(&peer.to_string()),
    )
    .unwrap();
    assert_eq!(
        both.expected,
        Some(Expected {
            peer,
            source: "--peer"
        })
    );
}

#[test]
fn refuses_a_flag_that_contradicts_the_address() {
    let (named, other) = (some_peer(), some_peer());
    let error = parse_err(
        &format!("/ip4/198.51.100.7/tcp/8336/p2p/{named}"),
        Some(&other.to_string()),
    );
    assert!(error.contains("name different peers"), "{error}");
    assert!(parse_err("/ip4/198.51.100.7/tcp/8336", Some("not-a-peer"))
        .contains("--peer not-a-peer: not a peer ID"));
}

#[test]
fn parses_quic_v1_and_dns_hosts() {
    let target = parse_target("/ip4/198.51.100.7/udp/8336/quic-v1", None).unwrap();
    assert_eq!(target.carrier, Carrier::Quic);
    assert_eq!(target.port, 8336);
    let target = parse_target("/dns4/node.example/tcp/8336", None).unwrap();
    assert_eq!(
        target.host,
        Host::Dns {
            name: "node.example".into(),
            family: Family::V4
        }
    );
    let target = parse_target("/dns/node.example/udp/8336/quic-v1", None).unwrap();
    assert_eq!(
        target.host,
        Host::Dns {
            name: "node.example".into(),
            family: Family::Any
        }
    );
}

#[test]
fn rejects_addresses_it_cannot_dial() {
    let cases = [
        ("garbage", "is not a multiaddr"),
        (
            "/ip4/198.51.100.7/udp/8336/quic",
            "/quic is the draft QUIC version",
        ),
        ("/ip4/198.51.100.7/udp/8336", "needs /quic-v1"),
        ("/ip4/198.51.100.7/tcp/8336/ws", "not /ws"),
        ("/ip4/198.51.100.7/tcp/0", "port 0"),
        ("/dnsaddr/bootstrap.example", "/dnsaddr lists addresses"),
        ("/tcp/8336", "must start with /ip4"),
        (
            "/ip4/198.51.100.7",
            "needs /tcp/<port> or /udp/<port>/quic-v1",
        ),
    ];
    for (addr, expected) in cases {
        let error = parse_err(addr, None);
        assert!(error.contains(expected), "{addr}: {error}");
    }
    let peer = some_peer();
    let error = parse_err(
        &format!("/ip4/198.51.100.7/tcp/8336/p2p/{peer}/tcp/1"),
        None,
    );
    assert!(error.contains("nothing may follow /p2p"), "{error}");
}

#[test]
fn builds_the_dial_address_from_the_socket() {
    assert_eq!(
        dial_multiaddr(doc_addr(), Carrier::Tcp).to_string(),
        "/ip4/192.0.2.1/tcp/8336"
    );
    let v6: SocketAddr = "[2001:db8::7]:8336".parse().unwrap();
    assert_eq!(
        dial_multiaddr(v6, Carrier::Quic).to_string(),
        "/ip6/2001:db8::7/udp/8336/quic-v1"
    );
}

#[test]
fn verify_peer_refuses_another_peer_id() {
    let (expected, actual) = (some_peer(), some_peer());
    let named = Some(Expected {
        peer: expected,
        source: "--peer",
    });
    assert_eq!(
        verify_peer(named, expected, "192.0.2.1:8336".into()),
        Ok(())
    );
    assert_eq!(verify_peer(None, actual, "192.0.2.1:8336".into()), Ok(()));
    let failure = verify_peer(named, actual, "192.0.2.1:8336".into()).unwrap_err();
    assert_eq!(
        failure.to_string(),
        format!("192.0.2.1:8336 answers as peer {actual}, not {expected} (--peer): the address belongs to another node now, or the peer ID is wrong")
    );
}

#[test]
fn classifies_transport_failures() {
    let refused = classify(
        Carrier::Tcp,
        &Stage::Io(ErrorKind::ConnectionRefused, "refused".into()),
        doc_addr(),
        3,
        "x",
    );
    assert_eq!(
        refused.to_string(),
        "nothing accepts connections on 192.0.2.1:8336: check port forwarding / Docker port publishing / firewall, and that the node listens on this port"
    );
    let refused = classify(
        Carrier::Quic,
        &Stage::Io(ErrorKind::ConnectionRefused, "refused".into()),
        doc_addr(),
        3,
        "x",
    );
    assert!(
        refused
            .to_string()
            .starts_with("nothing accepts QUIC on 192.0.2.1:8336 (UDP)"),
        "{refused}"
    );

    let timed_out = classify(
        Carrier::Tcp,
        &Stage::Io(ErrorKind::TimedOut, "timed out".into()),
        doc_addr(),
        3,
        "x",
    );
    assert_eq!(
        timed_out.to_string(),
        "no answer from 192.0.2.1:8336 within 3s: filtered by a firewall, or the host is down"
    );

    let unreachable = classify(
        Carrier::Tcp,
        &Stage::Io(ErrorKind::HostUnreachable, "no route".into()),
        doc_addr(),
        3,
        "x",
    );
    assert!(
        matches!(unreachable, DialFailure::Unreachable { .. }),
        "{unreachable:?}"
    );

    let handshake = classify(
        Carrier::Tcp,
        &Stage::TcpConnected(Instant::now()),
        doc_addr(),
        3,
        "protocol negotiation failed",
    );
    assert!(
        handshake.to_string().starts_with(
            "192.0.2.1:8336 answered, but the libp2p handshake failed (protocol negotiation failed): it is not a Quilibrium libp2p listener"
        ),
        "{handshake}"
    );
    let quic = classify(
        Carrier::Quic,
        &Stage::QuicRejected("crypto error".into()),
        doc_addr(),
        3,
        "x",
    );
    assert!(
        matches!(&quic, DialFailure::Handshake { detail, .. } if detail == "crypto error"),
        "{quic:?}"
    );
    let quiet = classify(Carrier::Quic, &Stage::QuicTimedOut, doc_addr(), 3, "x");
    assert!(
        quiet
            .to_string()
            .starts_with("no QUIC answer from 192.0.2.1:8336 (UDP) within 3s"),
        "{quiet}"
    );

    let other = classify(
        Carrier::Tcp,
        &Stage::Dialing,
        doc_addr(),
        3,
        "unsupported\naddress",
    );
    assert_eq!(
        other.to_string(),
        "dialing 192.0.2.1:8336 failed: unsupportedaddress"
    );
}

#[test]
fn a_timeout_names_the_step_that_did_not_answer() {
    assert_eq!(
        on_timeout(Carrier::Tcp, &Stage::Dialing, doc_addr(), 3).to_string(),
        "no answer from 192.0.2.1:8336 within 3s: filtered by a firewall, or the host is down"
    );
    assert_eq!(
        on_timeout(Carrier::Tcp, &Stage::TcpConnected(Instant::now()), doc_addr(), 3).to_string(),
        "192.0.2.1:8336 accepted the TCP connection, but the libp2p handshake did not finish within 3s: another service may own the port, or the node is overloaded"
    );
    assert!(matches!(
        on_timeout(Carrier::Quic, &Stage::Dialing, doc_addr(), 3),
        DialFailure::NoAnswer {
            carrier: Carrier::Quic,
            ..
        }
    ));
}

#[test]
fn error_chain_descends_through_io_errors_without_repeats() {
    let inner = std::io::Error::new(ErrorKind::ConnectionRefused, "connection refused");
    let outer = std::io::Error::other(inner);
    assert_eq!(error_chain(&outer), "connection refused");
    #[derive(Debug, thiserror::Error)]
    #[error("handshake")]
    struct Wrapper(#[source] std::io::Error);
    let wrapped = std::io::Error::other(Wrapper(std::io::Error::other("eof")));
    assert_eq!(error_chain(&wrapped), "handshake: eof");
}

fn sample_identity() -> Identity {
    let info = identify::Info {
        public_key: Keypair::generate_ed25519().public(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        agent_version: "node\u{1b}[31m/2.1".to_string(),
        listen_addrs: vec![
            "/ip4/198.51.100.7/tcp/8336".parse().unwrap(),
            "/ip4/10.0.0.2/tcp/8336".parse().unwrap(),
            "/dns4/node.example/tcp/8336".parse().unwrap(),
        ],
        protocols: [
            "/meshsub/1.1.0",
            "/ipfs/ping/1.0.0",
            "/ipfs/id/1.0.0",
            "/ipfs/ping/1.0.0",
        ]
        .into_iter()
        .map(|p| libp2p::StreamProtocol::new(p))
        .collect(),
        observed_addr: "/ip4/203.0.113.9/tcp/53122".parse().unwrap(),
        signed_peer_record: None,
    };
    info.into()
}

#[test]
fn identity_sorts_protocols_and_strips_control_characters() {
    let identity = sample_identity();
    assert_eq!(
        identity.protocols,
        ["/ipfs/id/1.0.0", "/ipfs/ping/1.0.0", "/meshsub/1.1.0"]
    );
    assert_eq!(identity.agent_version, "node[31m/2.1");
    assert_eq!(identity.observed_addr, "/ip4/203.0.113.9/tcp/53122");
}

fn sample_report(local: PeerId, peer: PeerId) -> Report {
    Report {
        dialed: "/ip4/198.51.100.7/tcp/8336".parse().unwrap(),
        carrier: Carrier::Tcp,
        local,
        peer,
        verified: Some("/p2p"),
        tcp_connect: Some(Duration::from_millis(85)),
        established: Duration::from_millis(240),
        identify: Ok(sample_identity()),
        ping: Ok(Duration::from_millis(81)),
        closed: None,
    }
}

#[test]
fn renders_a_report() {
    let (local, peer) = (some_peer(), some_peer());
    let expected = format!(
        "Dialed /ip4/198.51.100.7/tcp/8336 over TCP (PQNoise sntrup761, yamux) as throwaway identity {local}.
peer       {peer}  matches /p2p
connected  240 ms (TCP 85 ms, then the libp2p handshake)
ping       81 ms
agent      node[31m/2.1
protocol   /quilibrium/2.0.2/0
observed   /ip4/203.0.113.9/tcp/53122
listen     3 addresses, 1 private
           public   /ip4/198.51.100.7/tcp/8336
           private  /ip4/10.0.0.2/tcp/8336
           -        /dns4/node.example/tcp/8336
protocols  3
           /ipfs/id/1.0.0
           /ipfs/ping/1.0.0
           /meshsub/1.1.0
"
    );
    assert_eq!(render(&sample_report(local, peer)), expected);
}

#[test]
fn renders_missing_answers() {
    let (local, peer) = (some_peer(), some_peer());
    let mut report = sample_report(local, peer);
    report.carrier = Carrier::Quic;
    report.verified = None;
    report.tcp_connect = None;
    report.identify = Err("no answer within 3s".into());
    report.ping = Err("not supported by the peer".into());
    report.closed = Some("connection reset".into());
    let text = render(&report);
    assert!(
        text.contains(&format!(
            "peer       {peer}  not checked: name the expected one with --peer or /p2p/<peer-id>\n"
        )),
        "{text}"
    );
    assert!(
        text.contains("connected  240 ms (QUIC handshake)\n"),
        "{text}"
    );
    assert!(
        text.contains("ping       not supported by the peer\n"),
        "{text}"
    );
    assert!(text.contains("identify   no answer within 3s\n"), "{text}");
    assert!(
        text.contains("closed     the connection closed early: connection reset\n"),
        "{text}"
    );
    assert!(!text.contains("protocols"), "{text}");
}

#[test]
fn classifies_listen_address_reach() {
    assert_eq!(address_reach("/ip4/198.51.100.7/tcp/8336"), Reach::Public);
    assert_eq!(address_reach("/ip4/192.168.1.2/tcp/8336"), Reach::Private);
    assert_eq!(
        address_reach("/ip4/100.64.0.1/udp/8336/quic-v1"),
        Reach::Private
    );
    assert_eq!(address_reach("/ip6/2001:db8::7/tcp/8336"), Reach::Public);
    assert_eq!(address_reach("/ip6/fd00::1/tcp/8336"), Reach::Private);
    assert_eq!(
        address_reach("/ip6/::ffff:10.0.0.1/tcp/8336"),
        Reach::Private
    );
    assert_eq!(address_reach("/dns4/node.example/tcp/8336"), Reach::Unknown);
}

// In-process libp2p listeners built like `quil_p2p::node`'s swarm: a Falcon
// identity, PQNoise and yamux over TCP, QUIC v1, identify and ping.

#[derive(NetworkBehaviour)]
struct NodeBehaviour {
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

struct Listener {
    peer: PeerId,
    tcp: SocketAddr,
    quic: SocketAddr,
}

fn socket_of(addr: &Multiaddr) -> SocketAddr {
    let mut ip = None;
    let mut port = None;
    for part in addr.iter() {
        match part {
            Protocol::Ip4(v4) => ip = Some(IpAddr::V4(v4)),
            Protocol::Tcp(p) | Protocol::Udp(p) => port = Some(p),
            _ => {}
        }
    }
    SocketAddr::new(ip.unwrap(), port.unwrap())
}

async fn listener() -> Listener {
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(Keypair::generate_falcon())
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            PqNoiseConfig::new,
            libp2p::yamux::Config::default,
        )
        .unwrap()
        .with_quic()
        .with_behaviour(|key| NodeBehaviour {
            identify: identify::Behaviour::new(
                identify::Config::new(PROTOCOL_VERSION.to_string(), key.public())
                    .with_agent_version("test-node/1".into()),
            ),
            ping: ping::Behaviour::default(),
        })
        .unwrap()
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    swarm
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    swarm
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
        .unwrap();
    let (mut tcp, mut quic) = (None, None);
    while tcp.is_none() || quic.is_none() {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            if address.iter().any(|part| part == Protocol::QuicV1) {
                quic = Some(socket_of(&address));
            } else {
                tcp = Some(socket_of(&address));
            }
        }
    }
    let peer = *swarm.local_peer_id();
    tokio::spawn(async move {
        loop {
            swarm.select_next_some().await;
        }
    });
    Listener {
        peer,
        tcp: tcp.unwrap(),
        quic: quic.unwrap(),
    }
}

async fn dial_text(multiaddr: &str, peer: Option<&str>, secs: u64) -> Result<Report, DialFailure> {
    let target = parse_target(multiaddr, peer).unwrap();
    let addr = resolve(&target).await.unwrap();
    dial(&target, addr, Duration::from_secs(secs)).await
}

#[tokio::test]
async fn dials_a_tcp_listener_and_reads_identify_and_ping() {
    let node = listener().await;
    let addr = format!("/ip4/127.0.0.1/tcp/{}/p2p/{}", node.tcp.port(), node.peer);
    let report = dial_text(&addr, None, 10).await.unwrap();
    assert_eq!(report.peer, node.peer);
    assert_eq!(report.verified, Some("/p2p"));
    assert!(
        report
            .tcp_connect
            .is_some_and(|tcp| tcp <= report.established),
        "{report:?}"
    );
    assert!(report.ping.is_ok(), "{report:?}");
    let identity = report.identify.as_ref().unwrap();
    assert_eq!(identity.agent_version, "test-node/1");
    assert_eq!(identity.protocol_version, PROTOCOL_VERSION);
    assert!(
        identity.protocols.iter().any(|p| p == "/ipfs/id/1.0.0"),
        "{identity:?}"
    );
    assert!(
        identity.protocols.iter().any(|p| p == "/ipfs/ping/1.0.0"),
        "{identity:?}"
    );
    assert!(
        identity
            .listen_addrs
            .contains(&format!("/ip4/127.0.0.1/tcp/{}", node.tcp.port())),
        "{identity:?}"
    );
    assert!(
        identity.observed_addr.starts_with("/ip4/127.0.0.1/tcp/"),
        "{identity:?}"
    );
    let text = render(&report);
    assert!(
        text.contains(&format!("peer       {}  matches /p2p\n", node.peer)),
        "{text}"
    );
}

#[tokio::test]
async fn dials_a_quic_listener() {
    let node = listener().await;
    let addr = format!("/ip4/127.0.0.1/udp/{}/quic-v1", node.quic.port());
    let report = dial_text(&addr, Some(&node.peer.to_string()), 10)
        .await
        .unwrap();
    assert_eq!(report.peer, node.peer);
    assert_eq!(report.verified, Some("--peer"));
    assert_eq!(report.tcp_connect, None);
    assert!(report.ping.is_ok(), "{report:?}");
    let identity = report.identify.as_ref().unwrap();
    assert!(identity.observed_addr.ends_with("/quic-v1"), "{identity:?}");
}

#[tokio::test]
async fn refuses_a_listener_with_another_peer_id() {
    let node = listener().await;
    let named = some_peer();
    let addr = format!("/ip4/127.0.0.1/tcp/{}/p2p/{named}", node.tcp.port());
    match dial_text(&addr, None, 10).await {
        Err(DialFailure::PeerMismatch {
            expected, actual, ..
        }) => {
            assert_eq!(
                expected,
                Expected {
                    peer: named,
                    source: "/p2p"
                }
            );
            assert_eq!(actual, node.peer);
        }
        other => panic!("expected a peer ID mismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn a_closed_port_is_refused() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let failure = dial_text(&format!("/ip4/127.0.0.1/tcp/{port}"), None, 5)
        .await
        .unwrap_err();
    assert!(
        matches!(
            failure,
            DialFailure::Refused {
                carrier: Carrier::Tcp,
                ..
            }
        ),
        "{failure:?}"
    );
}

#[tokio::test]
async fn another_service_fails_the_handshake() {
    let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        while let Ok((mut socket, _)) = server.accept().await {
            let _ = socket.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        }
    });
    let failure = dial_text(&format!("/ip4/127.0.0.1/tcp/{port}"), None, 5)
        .await
        .unwrap_err();
    assert!(
        matches!(
            failure,
            DialFailure::Handshake {
                carrier: Carrier::Tcp,
                ..
            }
        ),
        "{failure:?}"
    );
}

#[tokio::test]
async fn a_silent_listener_stalls_the_handshake() {
    let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = server.accept().await {
            held.push(socket);
        }
    });
    let failure = dial_text(&format!("/ip4/127.0.0.1/tcp/{port}"), None, 1)
        .await
        .unwrap_err();
    assert!(
        matches!(failure, DialFailure::HandshakeStalled { secs: 1, .. }),
        "{failure:?}"
    );
}
