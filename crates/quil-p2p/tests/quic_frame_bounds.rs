//! One peer that finished a QUIC handshake, against a real node's listener and
//! libp2p-quic's own configuration: what its gapped stream frames and its
//! connection ID frames can make the node hold, and what honest traffic under
//! loss does to the same bounds.
//!
//! The peer handshakes through quinn-proto and the node's TLS configuration,
//! keeps the 1-RTT keys and then writes its own short-header packets, because
//! no QUIC stack sends these frames on request.
//! Each test runs in its own nextest process, so the allocator counters below
//! see only this test's node.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::core::muxing::StreamMuxerExt;
use libp2p::core::transport::{DialOpts, ListenerId, PortUse, Transport, TransportEvent};
use libp2p::core::Endpoint as Role;
use libp2p::{Multiaddr, PeerId};
use quil_p2p::P2PNode;
use quinn_proto::crypto::rustls::QuicClientConfig;
use quinn_proto::crypto::{self, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{
    ClientConfig, ConnectError, ConnectionId, DatagramEvent, Endpoint, EndpointConfig, Side,
    TransportError,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

struct CountingAlloc;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(by: usize) {
    let live = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        grew(layout.size());
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Both blocks exist while the contents move.
        grew(new_size);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

struct SharedPacketKey(Arc<dyn PacketKey>);

impl PacketKey for SharedPacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        self.0.encrypt(packet, buf, header_len)
    }
    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), crypto::CryptoError> {
        self.0.decrypt(packet, header, payload)
    }
    fn tag_len(&self) -> usize {
        self.0.tag_len()
    }
    fn confidentiality_limit(&self) -> u64 {
        self.0.confidentiality_limit()
    }
    fn integrity_limit(&self) -> u64 {
        self.0.integrity_limit()
    }
}

struct SharedHeaderKey(Arc<dyn HeaderKey>);

impl HeaderKey for SharedHeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.0.decrypt(pn_offset, packet)
    }
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.0.encrypt(pn_offset, packet)
    }
    fn sample_size(&self) -> usize {
        self.0.sample_size()
    }
}

#[derive(Clone)]
struct OneRttKeys {
    tx_header: Arc<dyn HeaderKey>,
    rx_header: Arc<dyn HeaderKey>,
    tx_packet: Arc<dyn PacketKey>,
    rx_packet: Arc<dyn PacketKey>,
}

/// The session and what the handshake's client derived from it, shared with the
/// raw peer: it outlives the handshake's connection and follows key updates.
#[derive(Default)]
struct KeyStore {
    one_rtt: Option<OneRttKeys>,
    /// Next-phase keys quinn-proto already took from the session, oldest first.
    next: VecDeque<KeyPair<Arc<dyn PacketKey>>>,
    session: Option<Arc<Mutex<Box<dyn crypto::Session>>>>,
}

type KeySlot = Arc<Mutex<KeyStore>>;

struct CapturingClient {
    inner: Arc<QuicClientConfig>,
    slot: KeySlot,
}

impl crypto::ClientConfig for CapturingClient {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        let inner = self
            .inner
            .clone()
            .start_session(version, server_name, params)?;
        let inner = Arc::new(Mutex::new(inner));
        self.slot.lock().unwrap().session = Some(inner.clone());
        Ok(Box::new(CapturingSession {
            inner,
            slot: self.slot.clone(),
        }))
    }
}

struct CapturingSession {
    inner: Arc<Mutex<Box<dyn crypto::Session>>>,
    slot: KeySlot,
}

impl CapturingSession {
    fn inner(&self) -> std::sync::MutexGuard<'_, Box<dyn crypto::Session>> {
        self.inner.lock().unwrap()
    }
}

impl crypto::Session for CapturingSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        self.inner().initial_keys(dst_cid, side)
    }
    fn handshake_data(&self) -> Option<Box<dyn std::any::Any>> {
        self.inner().handshake_data()
    }
    fn peer_identity(&self) -> Option<Box<dyn std::any::Any>> {
        self.inner().peer_identity()
    }
    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        self.inner().early_crypto()
    }
    fn early_data_accepted(&self) -> Option<bool> {
        self.inner().early_data_accepted()
    }
    fn is_handshaking(&self) -> bool {
        self.inner().is_handshaking()
    }
    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.inner().read_handshake(buf)
    }
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.inner().transport_parameters()
    }
    /// The client gets handshake keys, then 1-RTT keys, so the slot ends on the latter.
    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        let Keys { header, packet } = self.inner().write_handshake(buf)?;
        let keys = OneRttKeys {
            tx_header: Arc::from(header.local),
            rx_header: Arc::from(header.remote),
            tx_packet: Arc::from(packet.local),
            rx_packet: Arc::from(packet.remote),
        };
        self.slot.lock().unwrap().one_rtt = Some(keys.clone());
        Some(Keys {
            header: KeyPair {
                local: Box::new(SharedHeaderKey(keys.tx_header)),
                remote: Box::new(SharedHeaderKey(keys.rx_header)),
            },
            packet: KeyPair {
                local: Box::new(SharedPacketKey(keys.tx_packet)),
                remote: Box::new(SharedPacketKey(keys.rx_packet)),
            },
        })
    }
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        let keys = self.inner().next_1rtt_keys()?;
        let (local, remote): (Arc<dyn PacketKey>, Arc<dyn PacketKey>) =
            (Arc::from(keys.local), Arc::from(keys.remote));
        self.slot.lock().unwrap().next.push_back(KeyPair {
            local: local.clone(),
            remote: remote.clone(),
        });
        Some(KeyPair {
            local: Box::new(SharedPacketKey(local)),
            remote: Box::new(SharedPacketKey(remote)),
        })
    }
    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.inner().is_valid_retry(orig_dst_cid, header, payload)
    }
    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.inner().export_keying_material(output, label, context)
    }
}

/// Connection ID length of quinn-proto's default endpoint configuration.
const OUR_CID_LEN: usize = 8;
/// Stays under the kernel's default socket buffer, so the node's socket drops nothing.
const IN_FLIGHT_PACKETS: u64 = 64;
const MAX_PAYLOAD: usize = 1100;
const FIRST_RAW_PN: u64 = 64;
/// A flood gives up once the node has acknowledged nothing new for this long.
const STALL_LIMIT: Duration = Duration::from_secs(30);
/// A running flood prints a progress line this often.
const PROGRESS_EVERY: Duration = Duration::from_secs(5);
/// ACK ranges this peer reports, newest first.
const MAX_ACK_RANGES: usize = 32;

fn put_varint(buf: &mut Vec<u8>, v: u64) {
    match v {
        0..=0x3f => buf.push(v as u8),
        0x40..=0x3fff => buf.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
        0x4000..=0x3fff_ffff => buf.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
        _ => buf.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// STREAM frame with explicit offset and length.
fn stream_frame(stream: u64, offset: u64, data: &[u8], fin: bool) -> Vec<u8> {
    let mut f = vec![0x0e | u8::from(fin)];
    put_varint(&mut f, stream);
    put_varint(&mut f, offset);
    put_varint(&mut f, data.len() as u64);
    f.extend_from_slice(data);
    f
}

fn new_connection_id_frame(sequence: u64, retire_prior_to: u64, cid: &[u8]) -> Vec<u8> {
    let mut f = vec![0x18];
    put_varint(&mut f, sequence);
    put_varint(&mut f, retire_prior_to);
    f.push(cid.len() as u8);
    f.extend_from_slice(cid);
    f.extend_from_slice(&[0u8; 16]);
    f
}

struct FrameReader<'a>(&'a [u8]);

impl FrameReader<'_> {
    fn varint(&mut self) -> Option<u64> {
        let first = *self.0.first()?;
        let len = 1usize << (first >> 6);
        let raw = self.0.get(..len)?;
        let mut v = u64::from(first & 0x3f);
        for b in &raw[1..] {
            v = v << 8 | u64::from(*b);
        }
        self.0 = &self.0[len..];
        Some(v)
    }
    fn take(&mut self, n: u64) -> Option<&[u8]> {
        let n = usize::try_from(n).ok()?;
        let head = self.0.get(..n)?;
        self.0 = &self.0[n..];
        Some(head)
    }
}

/// A peer past its handshake, writing its own 1-RTT packets to the node.
struct RawPeer {
    socket: UdpSocket,
    server: SocketAddr,
    dcid: Vec<u8>,
    keys: OneRttKeys,
    key_store: KeySlot,
    /// The key phase bit in force; quinn updates keys after a few hundred packets,
    /// and a peer that does not follow can read nothing more from the node.
    key_phase: bool,
    next_pn: u64,
    largest_rx: u64,
    largest_acked: u64,
    close: Option<String>,
    /// Pace on the clock instead of the node's ACKs.
    clock_paced: bool,
    /// Acknowledge what the node sends.
    acks_node: bool,
    /// Packet numbers received from the node and not yet aged out.
    rx_pns: BTreeSet<u64>,
    ack_pending: bool,
    /// The flood gave up: no new ACK within `STALL_LIMIT`.
    stalled: bool,
    /// Frames received from the node, by frame type.
    rx_frames: BTreeMap<u64, u64>,
    /// What the node wrote on stream 0, by offset.
    rx_stream0: BTreeMap<u64, Vec<u8>>,
    started: Instant,
    last_progress: Instant,
    /// Streams the node sent STOP_SENDING for.
    stopped_by_node: BTreeSet<u64>,
    progress_every: Duration,
    key_updates: u64,
    /// A flood gives up at this time, sent or not.
    give_up_at: Option<Instant>,
}

impl RawPeer {
    async fn connect(server: SocketAddr) -> Self {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let tls = libp2p_tls::make_client_config(&keypair, None).unwrap();
        let slot = KeySlot::default();
        let client = CapturingClient {
            inner: Arc::new(QuicClientConfig::try_from(tls).unwrap()),
            slot: slot.clone(),
        };
        let mut endpoint = Endpoint::new(Arc::new(EndpointConfig::default()), None, false, None);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (handle, mut conn) = endpoint
            .connect(
                Instant::now(),
                ClientConfig::new(Arc::new(client)),
                server,
                "l",
            )
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut dcid = None;
        let mut rx = vec![0u8; 65536];
        let mut tx = Vec::new();
        loop {
            let now = Instant::now();
            assert!(now < deadline, "QUIC handshake did not finish in 20 s");
            while let Some(t) = conn.poll_transmit(now, 1, &mut tx) {
                socket.send_to(&tx[..t.size], t.destination).await.unwrap();
                tx.clear();
            }
            while let Some(e) = conn.poll_endpoint_events() {
                if let Some(e) = endpoint.handle_event(handle, e) {
                    conn.handle_event(e);
                }
            }
            while conn.poll().is_some() {}
            if conn.stats().frame_rx.handshake_done > 0 {
                break;
            }
            let wait = Duration::from_millis(20);
            match tokio::time::timeout(wait, socket.recv_from(&mut rx)).await {
                Ok(Ok((n, from))) => {
                    // Long header: flags, version, dcid length + dcid, scid length + scid.
                    if dcid.is_none() && rx[0] & 0x80 != 0 {
                        let scid_at = 6 + usize::from(rx[5]);
                        let len = usize::from(rx[scid_at]);
                        dcid = Some(rx[scid_at + 1..scid_at + 1 + len].to_vec());
                    }
                    let mut out = Vec::new();
                    let datagram = BytesMut::from(&rx[..n]);
                    if let Some(DatagramEvent::ConnectionEvent(_, e)) =
                        endpoint.handle(now, from, None, None, datagram, &mut out)
                    {
                        conn.handle_event(e);
                    }
                }
                _ => conn.handle_timeout(Instant::now()),
            }
        }
        let keys = slot
            .lock()
            .unwrap()
            .one_rtt
            .clone()
            .expect("handshake gave keys");
        Self {
            socket,
            server,
            dcid: dcid.expect("a server packet with a long header"),
            keys,
            key_store: slot,
            key_phase: false,
            next_pn: FIRST_RAW_PN,
            largest_rx: 0,
            largest_acked: FIRST_RAW_PN - 1,
            close: None,
            clock_paced: false,
            acks_node: true,
            rx_pns: BTreeSet::new(),
            ack_pending: false,
            stalled: false,
            rx_frames: BTreeMap::new(),
            rx_stream0: BTreeMap::new(),
            started: Instant::now(),
            last_progress: Instant::now(),
            stopped_by_node: BTreeSet::new(),
            progress_every: PROGRESS_EVERY,
            key_updates: 0,
            give_up_at: None,
        }
    }

    fn seal(&mut self, payload: &[u8]) -> Vec<u8> {
        let pn = self.next_pn;
        self.next_pn += 1;
        let mut packet = vec![0x43 | (u8::from(self.key_phase) << 2)];
        packet.extend_from_slice(&self.dcid);
        let pn_offset = packet.len();
        packet.extend_from_slice(&(pn as u32).to_be_bytes());
        let header_len = packet.len();
        packet.extend_from_slice(payload);
        packet.resize(packet.len() + self.keys.tx_packet.tag_len(), 0);
        self.keys.tx_packet.encrypt(pn, &mut packet, header_len);
        self.keys.tx_header.encrypt(pn_offset, &mut packet);
        packet
    }

    fn on_datagram(&mut self, datagram: &[u8]) {
        if datagram.first().is_none_or(|b| b & 0x80 != 0) {
            return; // Long header: a late handshake packet.
        }
        let pn_offset = 1 + OUR_CID_LEN;
        let mut packet = datagram.to_vec();
        self.keys.rx_header.decrypt(pn_offset, &mut packet);
        let pn_len = usize::from(packet[0] & 3) + 1;
        let truncated = packet[pn_offset..pn_offset + pn_len]
            .iter()
            .fold(0u64, |v, b| v << 8 | u64::from(*b));
        let window = 1u64 << (pn_len * 8);
        let expected = self.largest_rx + 1;
        let mut pn = expected & !(window - 1) | truncated;
        if pn + window / 2 <= expected {
            pn += window;
        } else if pn > expected + window / 2 && pn >= window {
            pn -= window;
        }
        let (header, body) = packet.split_at(pn_offset + pn_len);
        let mut body = BytesMut::from(body);
        let phase = packet[0] & 4 != 0;
        if phase != self.key_phase {
            let mut store = self.key_store.lock().unwrap();
            let next = store.next.pop_front().or_else(|| {
                let session = store.session.clone()?;
                let keys = session.lock().unwrap().next_1rtt_keys()?;
                Some(KeyPair {
                    local: Arc::from(keys.local),
                    remote: Arc::from(keys.remote),
                })
            });
            drop(store);
            let Some(next) = next else { return };
            if next.remote.decrypt(pn, header, &mut body).is_err() {
                self.key_store.lock().unwrap().next.push_front(next);
                return; // A stateless reset, or a packet from an old phase.
            }
            self.key_phase = phase;
            self.key_updates += 1;
            self.keys.tx_packet = next.local;
            self.keys.rx_packet = next.remote;
        } else if self.keys.rx_packet.decrypt(pn, header, &mut body).is_err() {
            return; // Not for these keys: e.g. a stateless reset.
        }
        self.largest_rx = self.largest_rx.max(pn);
        self.rx_pns.insert(pn);
        while self.rx_pns.len() > 1024 {
            self.rx_pns.pop_first();
        }
        self.ack_pending = true;
        self.on_frames(&body);
    }

    /// Reads the frames the node sends this peer; stops at one it has no use for.
    fn on_frames(&mut self, body: &[u8]) -> Option<()> {
        let mut r = FrameReader(body);
        while !r.0.is_empty() {
            let frame = r.varint()?;
            *self.rx_frames.entry(frame).or_default() += 1;
            match frame {
                // 0x1f, IMMEDIATE_ACK, comes before the ACK in quinn's packets.
                0x00 | 0x01 | 0x1e | 0x1f => {}
                t @ (0x02 | 0x03) => {
                    let largest = r.varint()?;
                    self.largest_acked = self.largest_acked.max(largest);
                    r.varint()?;
                    let ranges = r.varint()?;
                    r.varint()?;
                    for _ in 0..ranges * 2 {
                        r.varint()?;
                    }
                    if t == 0x03 {
                        for _ in 0..3 {
                            r.varint()?;
                        }
                    }
                }
                0x04 => {
                    for _ in 0..3 {
                        r.varint()?;
                    }
                }
                0x05 => {
                    self.stopped_by_node.insert(r.varint()?);
                    r.varint()?;
                }
                0x11 | 0x15 => {
                    r.varint()?;
                    r.varint()?;
                }
                0x06 => {
                    r.varint()?;
                    let n = r.varint()?;
                    r.take(n)?;
                }
                0x07 => {
                    let n = r.varint()?;
                    r.take(n)?;
                }
                t @ 0x08..=0x0f => {
                    let stream = r.varint()?;
                    let offset = if t & 4 != 0 { r.varint()? } else { 0 };
                    let n = if t & 2 != 0 {
                        r.varint()?
                    } else {
                        r.0.len() as u64
                    };
                    let data = r.take(n)?.to_vec();
                    if stream == 0 {
                        self.rx_stream0.insert(offset, data);
                    }
                }
                0x10 | 0x12 | 0x13 | 0x14 | 0x16 | 0x17 | 0x19 => {
                    r.varint()?;
                }
                0x18 => {
                    r.varint()?;
                    r.varint()?;
                    let n = u64::from(*r.take(1)?.first()?);
                    r.take(n + 16)?;
                }
                0x1a | 0x1b => {
                    r.take(8)?;
                }
                t @ (0x1c | 0x1d) => {
                    let code = r.varint()?;
                    if t == 0x1c {
                        r.varint()?;
                    }
                    let n = r.varint()?;
                    let reason = String::from_utf8_lossy(r.take(n)?).into_owned();
                    self.close = Some(format!("code {code:#x}: {reason}"));
                }
                _ => return None,
            }
        }
        Some(())
    }

    fn drain_socket(&mut self) {
        let mut rx = [0u8; 2048];
        while let Ok((n, _)) = self.socket.try_recv_from(&mut rx) {
            let datagram = rx[..n].to_vec();
            self.on_datagram(&datagram);
        }
    }

    async fn recv_for(&mut self, wait: Duration) -> bool {
        let mut rx = [0u8; 2048];
        match tokio::time::timeout(wait, self.socket.recv_from(&mut rx)).await {
            Ok(Ok((n, _))) => {
                let datagram = rx[..n].to_vec();
                self.on_datagram(&datagram);
                true
            }
            _ => false,
        }
    }

    /// An ACK frame for what the node sent, skipping the numbers it never used.
    fn ack_frame(&self) -> Vec<u8> {
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for &pn in self.rx_pns.iter().rev() {
            if let Some((low, _)) = ranges.last_mut().filter(|(low, _)| *low == pn + 1) {
                *low = pn;
            } else if ranges.len() == MAX_ACK_RANGES {
                break;
            } else {
                ranges.push((pn, pn));
            }
        }
        let mut f = vec![0x02];
        let Some(&(first_low, largest)) = ranges.first() else {
            return Vec::new();
        };
        put_varint(&mut f, largest);
        put_varint(&mut f, 0);
        put_varint(&mut f, ranges.len() as u64 - 1);
        put_varint(&mut f, largest - first_low);
        let mut low = first_low;
        for &(next_low, next_high) in &ranges[1..] {
            put_varint(&mut f, low - next_high - 2);
            put_varint(&mut f, next_high - next_low);
            low = next_low;
        }
        f
    }

    /// One line on what the node is doing: read by a person, not asserted.
    fn progress(&mut self, what: &str) {
        self.last_progress = Instant::now();
        println!(
            "t={:6.1}s {what}: pn {} acked {} heap {:+.1} MiB (peak {:.1}), node socket {}, frames \
             from node {:x?}, stopped streams {}, stream 0 stopped {}, key updates {}, close {:?}",
            self.started.elapsed().as_secs_f64(),
            self.next_pn,
            self.largest_acked,
            mib(LIVE.load(Ordering::Relaxed)),
            mib(PEAK.load(Ordering::Relaxed)),
            node_socket_queue(self.server.port()),
            self.rx_frames,
            self.stopped_by_node.len(),
            self.stopped_by_node.contains(&0),
            self.key_updates,
            self.close,
        );
    }

    async fn send_payload(&mut self, payload: &[u8]) {
        // Paced on the node's ACKs: it acknowledges a packet only after handling
        // it, so a node busy with this peer's frames slows the peer down.
        if self.clock_paced && self.next_pn % 16 == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let (mut acked, mut moved) = (self.largest_acked, Instant::now());
        while !self.clock_paced
            && self.close.is_none()
            && self.next_pn - self.largest_acked > IN_FLIGHT_PACKETS
        {
            if moved.elapsed() > STALL_LIMIT {
                self.stalled = true;
                self.progress("STALLED: no new ACK");
                return;
            }
            if self.acks_node && self.ack_pending {
                self.send_ack_only().await;
            }
            self.recv_for(Duration::from_millis(200)).await;
            if self.largest_acked != acked {
                (acked, moved) = (self.largest_acked, Instant::now());
            }
        }
        if self.close.is_some() {
            return;
        }
        let mut sealed = Vec::with_capacity(MAX_PAYLOAD + 256);
        if self.acks_node && self.ack_pending {
            sealed = self.ack_frame();
            self.ack_pending = false;
        }
        sealed.extend_from_slice(payload);
        let packet = self.seal(&sealed);
        self.socket.send_to(&packet, self.server).await.unwrap();
        self.drain_socket();
    }

    async fn send_ack_only(&mut self) {
        let frame = self.ack_frame();
        self.ack_pending = false;
        if !frame.is_empty() {
            let packet = self.seal(&frame);
            self.socket.send_to(&packet, self.server).await.unwrap();
        }
    }

    /// Sends the frames, in as few packets as fit, until they end, the node closes
    /// or the node stops acknowledging. Returns how many frames went out.
    async fn send_frames(&mut self, frames: impl IntoIterator<Item = Vec<u8>>) -> u64 {
        let mut sent = 0;
        let mut payload = Vec::with_capacity(MAX_PAYLOAD);
        for frame in frames {
            if payload.len() + frame.len() > MAX_PAYLOAD {
                self.send_payload(&payload).await;
                payload.clear();
                if self.close.is_some()
                    || self.stalled
                    || self.give_up_at.is_some_and(|t| Instant::now() > t)
                {
                    return sent;
                }
                if self.last_progress.elapsed() > self.progress_every {
                    self.progress(&format!("sent {sent} frames"));
                }
            }
            payload.extend_from_slice(&frame);
            sent += 1;
        }
        if !payload.is_empty() {
            self.send_payload(&payload).await;
        }
        sent
    }

    /// Whether the node acknowledged a PING, so it handled everything sent before.
    async fn settled(&mut self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline && !self.stalled {
            let ping = self.next_pn;
            self.send_payload(&[0x01]).await;
            let retry = Instant::now() + Duration::from_secs(2);
            while Instant::now() < retry {
                if self.close.is_some() {
                    return false;
                }
                if self.largest_acked >= ping {
                    return true;
                }
                self.recv_for(Duration::from_millis(100)).await;
            }
        }
        false
    }

    /// Waits a little for a CONNECTION_CLOSE that may still be on its way.
    async fn close_reason(&mut self, wait: Duration) -> Option<String> {
        let deadline = Instant::now() + wait;
        while self.close.is_none() && Instant::now() < deadline {
            self.recv_for(Duration::from_millis(100)).await;
        }
        self.close.clone()
    }

    fn wire_mib(&self) -> f64 {
        mib(self.next_pn.saturating_sub(FIRST_RAW_PN) as usize * (MAX_PAYLOAD + 29))
    }
}

/// The kernel's view of a UDP socket on `port`: unread bytes and drops. Unread
/// bytes piling up would mean the node stopped reading this socket.
fn node_socket_queue(port: u16) -> String {
    let wanted = format!(":{port:04X}");
    let table = std::fs::read_to_string("/proc/net/udp").unwrap_or_default();
    table
        .lines()
        .skip(1)
        .find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let local = fields.get(1)?;
            local.ends_with(&wanted).then(|| {
                let unread = fields[4].split(':').nth(1).unwrap_or("?");
                let drops = fields.last().unwrap_or(&"?");
                format!(
                    "unread {:#x} drops {drops}",
                    u64::from_str_radix(unread, 16).unwrap_or(0)
                )
            })
        })
        .unwrap_or_else(|| "absent".to_string())
}

/// A real node listening on QUIC only; dropping it stops the node.
struct NodeUnderTest {
    addr: SocketAddr,
    _keep: Box<dyn std::any::Any>,
}

async fn start_node() -> NodeUnderTest {
    let mut sup = quil_lifecycle::Supervisor::<anyhow::Error>::new();
    let mut config = quil_config::P2PConfig::default();
    config.network = 99;
    config.bootstrap_peers = Vec::new();
    config.direct_peers = Vec::new();
    let port = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let node = P2PNode::new_with_options(&config, true, None).unwrap();
    let (handle, inbound) = node
        .start(&mut sup, &format!("/ip4/127.0.0.1/udp/{port}/quic-v1"))
        .await
        .unwrap();
    NodeUnderTest {
        addr: format!("127.0.0.1:{port}").parse().unwrap(),
        _keep: Box::new((sup, handle, inbound)),
    }
}

/// Frames with a one-byte hole before each, leaving offset 0 unsent, on one stream:
/// `count` chunks that in-order reads never consume. All fit the stream's window.
fn gapped_chunks(stream: u64, count: u64) -> impl Iterator<Item = Vec<u8>> {
    (0..count).map(move |i| stream_frame(stream, 2 * i + 1, &[0xa5], false))
}

/// Above what a bound that closes the connection leaves on the node, far below
/// what the frames sent by these tests would hold without one.
const HEAP_LIMIT: usize = 4 << 20;

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .map_or(default, |v| v.parse().expect("a whole number"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gapped_stream_frames_from_one_peer_are_bounded() {
    let node = start_node().await;
    let mut peer = RawPeer::connect(node.addr).await;
    let chunks = env_u64("QUIC_BOUNDS_GAPPED_CHUNKS", 120_000);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let started = Instant::now();
    let sent = peer.send_frames(gapped_chunks(0, chunks)).await;
    let acked = peer.settled(Duration::from_secs(600)).await;
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(before);
    let held = LIVE.load(Ordering::Relaxed).saturating_sub(before);
    let close = peer.close_reason(Duration::from_secs(2)).await;
    println!(
        "gapped chunks: sent {sent}/{chunks} on one stream, wire {:.1} MiB, heap peak +{:.1} MiB, \
         held +{:.1} MiB, {:.1} s, all acknowledged: {acked}, stalled: {}, close: {close:?}",
        peer.wire_mib(),
        mib(peak),
        mib(held),
        started.elapsed().as_secs_f64(),
        peer.stalled,
    );
    assert!(
        peak < HEAP_LIMIT && close.is_some(),
        "unbounded memory from one peer: {sent} gapped stream chunks on one connection grew the \
         node's heap by {:.1} MiB at peak ({:.1} MiB still held, limit {:.1} MiB), and the node \
         {} the connection (close: {close:?})",
        mib(peak),
        mib(held),
        mib(HEAP_LIMIT),
        if close.is_some() {
            "closed"
        } else {
            "never closed"
        },
    );
    assert!(
        close
            .as_deref()
            .is_some_and(|c| c.contains("too many gaps")),
        "the node closed for another reason: {close:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retired_connection_id_frames_from_one_peer_are_bounded() {
    let node = start_node().await;
    let mut peer = RawPeer::connect(node.addr).await;
    peer.clock_paced = env_u64("QUIC_BOUNDS_RETIRE_CLOCK_PACED", 1) != 0;
    peer.acks_node = false;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    // Moves the node's window past sequence 1, which every later frame then names:
    // each queues a RETIRE_CONNECTION_ID that this peer never acknowledges.
    let window = 1_000_000;
    let first = new_connection_id_frame(window, window, &[7u8; OUR_CID_LEN]);
    let frames = env_u64("QUIC_BOUNDS_RETIRED_CIDS", 2_000_000);
    let sent = peer
        .send_frames(
            std::iter::once(first).chain((0..frames).map(|_| new_connection_id_frame(1, 0, &[7]))),
        )
        .await;
    // No ACK to wait for: give the node time to read what is in its socket.
    let close = peer.close_reason(Duration::from_secs(2)).await;
    let peak = PEAK.load(Ordering::Relaxed).saturating_sub(before);
    let held = LIVE.load(Ordering::Relaxed).saturating_sub(before);
    println!(
        "retired cids: sent {sent}/{frames}, wire {:.1} MiB, heap peak +{:.1} MiB, held +{:.1} \
         MiB, close: {close:?}",
        peer.wire_mib(),
        mib(peak),
        mib(held),
    );
    assert!(
        peak < HEAP_LIMIT && close.is_some(),
        "unbounded memory from one peer: {sent} NEW_CONNECTION_ID frames below the window grew \
         the node's heap by {:.1} MiB at peak ({:.1} MiB still held, limit {:.1} MiB), and the \
         node {} the connection (close: {close:?})",
        mib(peak),
        mib(held),
        mib(HEAP_LIMIT),
        if close.is_some() {
            "closed"
        } else {
            "never closed"
        },
    );
    assert!(
        close.as_deref().is_some_and(|c| c.contains("retired CIDs")),
        "the node closed for another reason: {close:?}"
    );
}

/// The bound must end only the offending connection: others carry on and the
/// peer can come back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_gap_bound_closes_only_that_connection_and_the_node_recovers() {
    let node = start_node().await;
    let mut bystander = RawPeer::connect(node.addr).await;
    let mut peer = RawPeer::connect(node.addr).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    peer.send_frames(gapped_chunks(0, 3000)).await;
    let close = peer.close_reason(Duration::from_secs(10)).await;
    assert!(
        close
            .as_deref()
            .is_some_and(|c| c.contains("too many gaps")),
        "the bound did not close the connection: {close:?}"
    );
    assert!(
        bystander.settled(Duration::from_secs(10)).await,
        "another connection stopped answering: {:?}",
        bystander.close
    );
    let mut returning = RawPeer::connect(node.addr).await;
    assert!(
        returning.settled(Duration::from_secs(10)).await,
        "a new connection after the bound did not answer: {:?}",
        returning.close
    );
    assert!(bystander.settled(Duration::from_secs(10)).await);
}

type ReadResult = Result<Vec<u8>, String>;

/// libp2p-quic with its own default configuration, the same as `.with_quic()`,
/// reading each inbound stream to its end. Reports what each read returned.
async fn start_reader() -> (SocketAddr, PeerId, mpsc::UnboundedReceiver<ReadResult>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();
    tokio::spawn(async move {
        let mut transport =
            libp2p::quic::tokio::Transport::new(libp2p::quic::Config::new(&keypair));
        let listen: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
        transport.listen_on(ListenerId::next(), listen).unwrap();
        let mut addr_tx = Some(addr_tx);
        loop {
            let event = std::future::poll_fn(|cx| Pin::new(&mut transport).poll(cx)).await;
            match event {
                TransportEvent::NewAddress { listen_addr, .. } => {
                    if let Some(s) = addr_tx.take() {
                        let port = listen_addr
                            .iter()
                            .find_map(|p| match p {
                                libp2p::multiaddr::Protocol::Udp(port) => Some(port),
                                _ => None,
                            })
                            .unwrap();
                        let _ = s.send(SocketAddr::from(([127, 0, 0, 1], port)));
                    }
                }
                TransportEvent::Incoming { upgrade, .. } => {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        if let Ok((_, connection)) = upgrade.await {
                            read_every_stream(connection, tx).await;
                        }
                    });
                }
                _ => {}
            }
        }
    });
    (addr_rx.await.unwrap(), peer_id, rx)
}

async fn read_every_stream(
    mut connection: libp2p::quic::Connection,
    tx: mpsc::UnboundedSender<ReadResult>,
) {
    loop {
        let inbound = std::future::poll_fn(|cx| {
            if let Poll::Ready(Err(e)) = connection.poll_unpin(cx) {
                return Poll::Ready(Err(e));
            }
            connection.poll_inbound_unpin(cx)
        })
        .await;
        let Ok(mut stream) = inbound else { return };
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut data = Vec::new();
            let result = stream.read_to_end(&mut data).await;
            let _ = tx.send(result.map(|_| data).map_err(|e| e.to_string()));
        });
    }
}

/// `spans` separate spans on stream 0, offset 0 missing, each then grown by a
/// neighbouring byte: enough chunks that the compaction threshold is crossed
/// with exactly `spans` disjoint spans left. Every byte equals `offset % 251`.
async fn send_spans_past_the_compaction_threshold(peer: &mut RawPeer, spans: u64) -> u64 {
    let frame = |offset: u64| stream_frame(0, offset, &[(offset % 251) as u8], false);
    let first = (0..spans).map(|i| frame(4 * i + 1));
    let grown = (0..spans).map(|i| frame(4 * i + 2));
    let extra = (0..1 + 2048u64.saturating_sub(2 * spans)).map(|i| frame(4 * i + 3));
    peer.send_frames(first.chain(grown).chain(extra)).await
}

/// One span too few to trip the bound, however many chunks pile up behind the
/// missing start of the stream; the filled stream then reads back whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_with_gaps_at_the_bound_stays_open_and_reads_whole() {
    let (addr, _, mut reads) = start_reader().await;
    let mut peer = RawPeer::connect(addr).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let spans: u64 = 1024;
    send_spans_past_the_compaction_threshold(&mut peer, spans).await;
    assert!(
        peer.settled(Duration::from_secs(20)).await,
        "{spans} gaps past compaction closed the connection: {:?}",
        peer.close
    );
    // Holes filled from the far end, offset 0 last, so the reader stays blocked.
    let total = 4 * spans;
    let fill = (0..total)
        .rev()
        .filter(|o| o % 4 == 0 || o % 4 == 3)
        .map(|o| {
            let fin = o + 1 == total;
            stream_frame(0, o, &[(o % 251) as u8], fin)
        });
    peer.send_frames(fill).await;
    assert!(
        peer.settled(Duration::from_secs(20)).await,
        "filling {spans} gaps closed the connection: {:?}",
        peer.close
    );
    let read = tokio::time::timeout(Duration::from_secs(20), reads.recv())
        .await
        .expect("the stream never read to its end")
        .expect("reader alive")
        .expect("the stream reads without error");
    let expected: Vec<u8> = (0..total).map(|o| (o % 251) as u8).collect();
    assert_eq!(read, expected, "the stream read back altered");
    assert_eq!(peer.close, None);
}

/// One span past the bound the connection closes, and a reader blocked on the
/// stream gets an error rather than hanging. Honest transfers use the same read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_gap_past_the_bound_closes_and_a_blocked_read_fails() {
    let (addr, _, mut reads) = start_reader().await;
    let mut peer = RawPeer::connect(addr).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    send_spans_past_the_compaction_threshold(&mut peer, 1025).await;
    let close = peer.close_reason(Duration::from_secs(10)).await;
    assert!(
        close
            .as_deref()
            .is_some_and(|c| c.contains("too many gaps")),
        "1025 gaps past compaction did not close the connection: {close:?}"
    );
    let read = tokio::time::timeout(Duration::from_secs(20), reads.recv())
        .await
        .expect("a blocked read outlived the connection")
        .expect("reader alive");
    assert!(read.is_err(), "the read returned data: {read:?}");
}

#[derive(Clone, Copy)]
struct Link {
    /// Per-million chance of dropping a client-to-server packet.
    loss_ppm: u64,
    /// One-way delay, each way.
    delay: Duration,
    /// Extra random delay on each client-to-server packet, which reorders them.
    jitter: Duration,
    /// Client-to-server packets forwarded untouched before loss starts.
    clean_packets: u64,
    /// Client-to-server packets the loss applies to, after which it stops.
    lossy_packets: u64,
}

#[derive(Default)]
struct LinkStats {
    forwarded: AtomicU64,
    dropped: AtomicU64,
    /// Separate holes the drops cut: runs of dropped packets.
    holes: AtomicU64,
    peak_in_flight: AtomicU64,
}

struct Delayed {
    due: Instant,
    seq: u64,
    to_server: bool,
    data: Vec<u8>,
}

impl PartialEq for Delayed {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq
    }
}
impl Eq for Delayed {}
impl PartialOrd for Delayed {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Delayed {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (other.due, other.seq).cmp(&(self.due, self.seq))
    }
}

/// A UDP relay between one client and one server, with loss and delay on the way.
async fn start_link(server: SocketAddr, link: Link, stats: Arc<LinkStats>) -> SocketAddr {
    let client_side = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_side = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = client_side.local_addr().unwrap();
    tokio::spawn(async move {
        let mut rng = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let mut client = None;
        let mut queue = BinaryHeap::<Delayed>::new();
        let (mut seq, mut to_server_seen, mut in_hole) = (0u64, 0u64, false);
        let (mut from_client, mut from_server) = (vec![0u8; 65536], vec![0u8; 65536]);
        loop {
            let due = queue.peek().map(|d| d.due);
            let sleep = async move {
                match due {
                    Some(at) => tokio::time::sleep_until(at.into()).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                got = client_side.recv_from(&mut from_client) => {
                    let (n, from) = got.unwrap();
                    client = Some(from);
                    to_server_seen += 1;
                    let lossy = to_server_seen > link.clean_packets
                        && to_server_seen <= link.clean_packets + link.lossy_packets;
                    if lossy && next() % 1_000_000 < link.loss_ppm {
                        stats.dropped.fetch_add(1, Ordering::Relaxed);
                        if !in_hole {
                            stats.holes.fetch_add(1, Ordering::Relaxed);
                        }
                        in_hole = true;
                    } else {
                        in_hole = false;
                        stats.forwarded.fetch_add(1, Ordering::Relaxed);
                        let jitter = if link.jitter.is_zero() {
                            Duration::ZERO
                        } else {
                            Duration::from_micros(next() % link.jitter.as_micros() as u64)
                        };
                        seq += 1;
                        queue.push(Delayed {
                            due: Instant::now() + link.delay + jitter,
                            seq,
                            to_server: true,
                            data: from_client[..n].to_vec(),
                        });
                        stats.peak_in_flight.fetch_max(queue.len() as u64, Ordering::Relaxed);
                    }
                }
                got = server_side.recv_from(&mut from_server) => {
                    let (n, _) = got.unwrap();
                    seq += 1;
                    queue.push(Delayed {
                        due: Instant::now() + link.delay,
                        seq,
                        to_server: false,
                        data: from_server[..n].to_vec(),
                    });
                }
                _ = sleep => {
                    let now = Instant::now();
                    while queue.peek().is_some_and(|d| d.due <= now) {
                        let d = queue.pop().unwrap();
                        if d.to_server {
                            let _ = server_side.send_to(&d.data, server).await;
                        } else if let Some(c) = client {
                            let _ = client_side.send_to(&d.data, c).await;
                        }
                    }
                }
            }
        }
    });
    addr
}

/// One honest stream from a libp2p-quic dialer through `link`, written in
/// `write_size` pieces. Returns what the far end's read returned.
async fn honest_transfer(
    link: Link,
    total: usize,
    write_size: usize,
) -> (ReadResult, Arc<LinkStats>) {
    let (server, server_id, mut reads) = start_reader().await;
    let stats = Arc::new(LinkStats::default());
    let relay = start_link(server, link, stats.clone()).await;
    let dial: Multiaddr = format!(
        "/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{server_id}",
        relay.port(),
    )
    .parse()
    .unwrap();

    let client_key = libp2p::identity::Keypair::generate_ed25519();
    let mut dialer = libp2p::quic::tokio::Transport::new(libp2p::quic::Config::new(&client_key));
    let dialing = dialer
        .dial(
            dial,
            DialOpts {
                role: Role::Dialer,
                port_use: PortUse::New,
            },
        )
        .unwrap();
    tokio::spawn(async move {
        loop {
            std::future::poll_fn(|cx| Pin::new(&mut dialer).poll(cx)).await;
        }
    });
    let (_, mut connection) = tokio::time::timeout(Duration::from_secs(30), dialing)
        .await
        .expect("dial timed out")
        .expect("dial failed");
    let mut stream = std::future::poll_fn(|cx| connection.poll_outbound_unpin(cx))
        .await
        .unwrap();
    tokio::spawn(async move {
        std::future::poll_fn(|cx| connection.poll_unpin(cx))
            .await
            .ok();
    });
    let data: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    let expected = data.clone();
    tokio::spawn(async move {
        for piece in data.chunks(write_size) {
            if stream.write_all(piece).await.is_err() {
                return;
            }
        }
        let _ = stream.close().await;
    });
    let read = tokio::time::timeout(Duration::from_secs(300), reads.recv())
        .await
        .expect("the honest transfer did not finish in 300 s")
        .expect("reader alive");
    if let Ok(read) = &read {
        assert_eq!(read.len(), expected.len(), "short read");
        assert!(read == &expected, "the stream read back altered");
    }
    (read, stats)
}

fn lossy(loss_ppm: u64, delay_ms: u64, jitter_ms: u64) -> Link {
    Link {
        loss_ppm,
        delay: Duration::from_millis(delay_ms),
        jitter: Duration::from_millis(jitter_ms),
        clean_packets: 20,
        lossy_packets: u64::MAX / 2,
    }
}

async fn assert_transfer_completes(link: Link, total: usize, write_size: usize) {
    let (read, stats) = honest_transfer(link, total, write_size).await;
    let (dropped, holes) = (
        stats.dropped.load(Ordering::Relaxed),
        stats.holes.load(Ordering::Relaxed),
    );
    println!(
        "honest transfer: {total} B in {write_size} B writes, loss {} ppm: forwarded {}, dropped \
         {dropped}, holes {holes}, peak in flight {} packets",
        link.loss_ppm,
        stats.forwarded.load(Ordering::Relaxed),
        stats.peak_in_flight.load(Ordering::Relaxed),
    );
    assert!(dropped > 0, "the link dropped nothing: this tested no loss");
    read.expect("an honest transfer lost its connection");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn honest_bulk_transfer_survives_one_percent_loss() {
    assert_transfer_completes(lossy(10_000, 20, 0), 8 << 20, 64 << 10).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn honest_bulk_transfer_survives_five_percent_loss_with_reordering() {
    assert_transfer_completes(lossy(50_000, 20, 10), 4 << 20, 64 << 10).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn honest_transfer_survives_twenty_percent_loss_with_reordering() {
    assert_transfer_completes(lossy(200_000, 5, 5), 1 << 20, 64 << 10).await;
}

/// Gossip's shape: many small writes, each its own frame when the link is slow.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn honest_small_messages_survive_ten_percent_loss() {
    assert_transfer_completes(lossy(100_000, 5, 2), 1 << 20, 200).await;
}

/// Measurement, not a pass/fail: the worst an honest flow can see. The window
/// fills on a clean link, then one flight loses `QUIC_BOUNDS_BURST_PPM` of its
/// packets at random. Prints whether the connection lived.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement; run with --run-ignored only"]
async fn measure_one_lossy_flight_at_a_full_window() {
    let link = Link {
        loss_ppm: env_u64("QUIC_BOUNDS_BURST_PPM", 150_000),
        delay: Duration::from_millis(env_u64("QUIC_BOUNDS_BURST_DELAY_MS", 50)),
        jitter: Duration::ZERO,
        clean_packets: env_u64("QUIC_BOUNDS_BURST_CLEAN_PACKETS", 12_000),
        lossy_packets: env_u64("QUIC_BOUNDS_BURST_PACKETS", 8_000),
    };
    let total = env_u64("QUIC_BOUNDS_BURST_TOTAL", 96 << 20) as usize;
    let (read, stats) = honest_transfer(link, total, 256 << 10).await;
    println!(
        "lossy flight: loss {} ppm over {} packets after {} clean: forwarded {}, dropped {}, \
         holes {}, peak in flight {} packets, connection {}",
        link.loss_ppm,
        link.lossy_packets,
        link.clean_packets,
        stats.forwarded.load(Ordering::Relaxed),
        stats.dropped.load(Ordering::Relaxed),
        stats.holes.load(Ordering::Relaxed),
        stats.peak_in_flight.load(Ordering::Relaxed),
        match read {
            Ok(_) => "lived".to_string(),
            Err(e) => format!("closed: {e}"),
        },
    );
}

/// Multistream-select's opening plus the choice of `protocol`, in one write.
fn multistream_select(protocol: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for line in ["/multistream/1.0.0\n".to_string(), format!("{protocol}\n")] {
        out.push(u8::try_from(line.len()).unwrap());
        out.extend_from_slice(line.as_bytes());
    }
    out
}

/// Measurement, not a pass/fail: a gap flood on one stream, then a per-second view
/// of the node's heap, its socket and its frames while the peer only keeps the
/// connection alive. It answers what the node does with the peer and how long the
/// memory stays. `QUIC_BOUNDS_PEER_ACKS=0` withholds this peer's ACKs,
/// `QUIC_BOUNDS_NEGOTIATE=<protocol>` finishes multistream-select first, so the
/// stream is past the swarm's negotiation timeout, `QUIC_BOUNDS_STREAM=<id>` picks
/// the stream, which opens every lower one too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement; run with --run-ignored only"]
async fn measure_the_node_during_and_after_a_gap_flood() {
    if let Ok(filter) = std::env::var("QUIC_BOUNDS_TRACE") {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_timer(tracing_subscriber::fmt::time::uptime())
            .init();
    }
    let node = start_node().await;
    let bystander = start_bystander(node.addr).await;
    let mut peer = RawPeer::connect(node.addr).await;
    peer.progress_every = Duration::from_millis(env_u64("QUIC_BOUNDS_PROGRESS_MS", 5000));
    peer.give_up_at =
        Some(Instant::now() + Duration::from_secs(env_u64("QUIC_BOUNDS_MAX_SECS", 300)));
    peer.acks_node = env_u64("QUIC_BOUNDS_PEER_ACKS", 1) != 0;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let stream = env_u64("QUIC_BOUNDS_STREAM", 0);
    let streams = env_u64("QUIC_BOUNDS_STREAMS", 1);
    let mut hole = 0;
    if let Ok(protocol) = std::env::var("QUIC_BOUNDS_NEGOTIATE") {
        let hello = multistream_select(&protocol);
        hole = hello.len() as u64;
        peer.send_frames([stream_frame(stream, 0, &hello, false)])
            .await;
        let deadline = Instant::now() + Duration::from_secs(5);
        let echoed = |peer: &RawPeer| {
            let seen: Vec<u8> = peer.rx_stream0.values().flatten().copied().collect();
            seen.windows(protocol.len())
                .any(|w| w == protocol.as_bytes())
        };
        while !echoed(&peer) && Instant::now() < deadline {
            peer.send_frames([vec![0x01]]).await;
            peer.recv_for(Duration::from_millis(100)).await;
        }
        let seen: Vec<u8> = peer.rx_stream0.values().flatten().copied().collect();
        println!(
            "negotiated {protocol}: {}, node wrote {:?}",
            echoed(&peer),
            String::from_utf8_lossy(&seen)
        );
    }
    let chunks = env_u64("QUIC_BOUNDS_GAPPED_CHUNKS", 120_000);
    peer.progress("flood starts");
    // Round robin over client-opened bidirectional streams, ids 4 apart.
    let frames = (0..chunks).map(|i| {
        let on = stream + 4 * (i % streams);
        stream_frame(on, hole + 2 * (i / streams) + 1, &[0xa5], false)
    });
    let sent = peer.send_frames(frames).await;
    peer.progress(&format!("flood ended, sent {sent}/{chunks} frames"));
    println!("another connection so far: {}", bystander.lock().unwrap());
    let addr = node.addr;
    let fresh = tokio::spawn(async move {
        let mut fresh = RawPeer::connect(addr).await;
        fresh.settled(Duration::from_secs(10)).await
    })
    .await;
    println!("a new connection answers: {fresh:?}");
    let silent = peer.stalled;
    peer.stalled = false;
    let answered = peer.settled(Duration::from_secs(10)).await;
    println!(
        "the flooding connection answers a ping: {answered}, close {:?}",
        peer.close
    );
    if silent && !answered {
        return;
    }
    let hold = env_u64("QUIC_BOUNDS_HOLD_SECS", 30);
    for second in 0..hold {
        // Keeps the connection past its idle timeout, as an attacker would.
        peer.send_frames([vec![0x01]]).await;
        let until = Instant::now() + Duration::from_secs(1);
        while Instant::now() < until {
            peer.recv_for(Duration::from_millis(100)).await;
        }
        peer.progress(&format!("hold {second}"));
    }
    println!(
        "another connection at the end: {}",
        bystander.lock().unwrap()
    );
}

/// A second connection pinging once a second, reporting how long each answer took.
async fn start_bystander(addr: SocketAddr) -> Arc<Mutex<String>> {
    let mut peer = RawPeer::connect(addr).await;
    let report = Arc::new(Mutex::new(String::new()));
    let out = report.clone();
    tokio::spawn(async move {
        let (mut answered, mut slowest, mut unanswered) = (0u64, Duration::ZERO, 0u64);
        loop {
            let asked = Instant::now();
            if peer.settled(Duration::from_secs(5)).await {
                answered += 1;
                slowest = slowest.max(asked.elapsed());
            } else {
                unanswered += 1;
            }
            *out.lock().unwrap() = format!(
                "{answered} pings answered, slowest {slowest:?}, {unanswered} unanswered, close {:?}",
                peer.close
            );
            if peer.close.is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    report
}

/// Measurement, not a pass/fail: the same flood from several connections, each kept
/// alive after its turn, so the node holds them all at once. Connections come from
/// fresh identities, which cost nothing, so the connection limit is the only cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement; run with --run-ignored only"]
async fn measure_the_node_holding_several_flooding_connections() {
    let node = start_node().await;
    let bystander = start_bystander(node.addr).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let base = LIVE.load(Ordering::Relaxed);
    let connections = env_u64("QUIC_BOUNDS_CONNECTIONS", 3);
    let chunks = env_u64("QUIC_BOUNDS_GAPPED_CHUNKS", 7_400_000);
    let streams = env_u64("QUIC_BOUNDS_STREAMS", 200);
    let started = Instant::now();
    let mut wire = 0.0;
    for connection in 0..connections {
        let mut peer = RawPeer::connect(node.addr).await;
        let frames = (0..chunks)
            .map(|i| stream_frame(4 * (i % streams), 2 * (i / streams) + 1, &[0xa5], false));
        let sent = peer.send_frames(frames).await;
        wire += peer.wire_mib();
        println!(
            "connection {connection}: sent {sent}/{chunks} on {streams} streams, close {:?}, \
             stalled {}; all so far: wire {wire:.1} MiB, heap held +{:.1} MiB, peak +{:.1} MiB, \
             {:.0} s, other connection: {}",
            peer.close,
            peer.stalled,
            mib(LIVE.load(Ordering::Relaxed).saturating_sub(base)),
            mib(PEAK.load(Ordering::Relaxed).saturating_sub(base)),
            started.elapsed().as_secs_f64(),
            bystander.lock().unwrap(),
        );
        // Keeps this connection past the idle timeout while the next one floods.
        tokio::spawn(async move {
            loop {
                peer.settled(Duration::from_secs(5)).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
    }
    tokio::time::sleep(Duration::from_secs(15)).await;
    println!(
        "15 s after the last flood: heap held +{:.1} MiB, other connection: {}",
        mib(LIVE.load(Ordering::Relaxed).saturating_sub(base)),
        bystander.lock().unwrap(),
    );
}
