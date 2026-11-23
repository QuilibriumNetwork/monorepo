//! Loopback transport test. Payloads are structurally valid fixtures, not
//! native proofs; this test establishes delivery/authentication, not admission.
use super::*;
use quil_lattice_ct::confidential::{memo::open_output, relation::membership::IDENTITY_BYTES};
use std::sync::{Arc, Mutex};

/// A coin as any sender can build it for a published address: its memo
/// opens for `wallet` but carries `amount + 1`, while the commitment and
/// owner are those of `amount`. Only the recipient can open a memo, so no
/// verifier sees the difference. The layout is the memo module's: KEM
/// ciphertext, AEAD nonce, encrypted amount and note seed, tag.
fn mismatched_output(wallet: &RecipientWallet, amount: u128) -> Output {
    use aes_gcm::{
        aead::{AeadInPlace, KeyInit},
        Aes256Gcm, Nonce,
    };
    use quil_lattice_ct::confidential::{memo::create_output_with_nonce, transfer::MEMO_BYTES};
    const KEM_END: usize = 1039;
    const NONCE_END: usize = KEM_END + 12;
    const BODY_END: usize = NONCE_END + 48;
    let address = wallet.address();
    let seed = [77u8; 32];
    let mut output = create_output_with_nonce(&wallet.context, address, amount, &seed)
        .unwrap()
        .output;
    let (shared, kem) = sntrup761::encapsulate(&address.kem_public_key()[..]).unwrap();
    output.memo[..KEM_END].copy_from_slice(&kem);
    output.memo[KEM_END..NONCE_END].copy_from_slice(&[5; 12]);
    let mut hash = Shake256::default();
    hash.update(b"quil/token/memo-key/v2\0");
    hash.update(&wallet.context);
    hash.update(&kem);
    hash.update(&shared);
    let mut key = [0u8; 32];
    hash.finalize_xof().read(&mut key);
    let mut aad = b"quil/token/memo-aad/v2\0".to_vec();
    aad.extend_from_slice(&wallet.context);
    aad.extend_from_slice(address.recipient_key());
    aad.extend_from_slice(&output.commitment.to_bytes());
    aad.extend_from_slice(&output.owner);
    aad.extend_from_slice(&kem);
    let mut body = [0u8; 48];
    body[..16].copy_from_slice(&(amount + 1).to_le_bytes());
    body[16..].copy_from_slice(&seed);
    let tag = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt_in_place_detached(Nonce::from_slice(&[5; 12]), &aad, &mut body)
        .unwrap();
    output.memo[NONCE_END..BODY_END].copy_from_slice(&body);
    output.memo[BODY_END..MEMO_BYTES].copy_from_slice(&tag);
    output
}

#[tokio::test]
async fn wallet_scans_owned_unspent_coins_over_rpc() {
    use quil_lattice_ct::confidential::{coin_tree::CoinRecord, memo::create_output};
    use quil_types::store::*;
    struct Pages {
        network: [u8; 32],
        application: [u8; 32],
        root: Vec<u8>,
        coins: Vec<([u8; 32], Output, u64)>,
        fail_continuation: std::sync::atomic::AtomicBool,
        /// Continuation reads that fail as a cut transfer does on a node.
        cut_reads: std::sync::atomic::AtomicUsize,
        /// A continuation read reports its snapshot expired.
        expired: std::sync::atomic::AtomicBool,
        continuations: std::sync::atomic::AtomicUsize,
    }
    impl CoinWitnessProvider for Pages {
        fn coin_page(
            &self,
            domain: &[u8; 32],
            snapshot: Option<&[u8; 32]>,
            after: Option<&[u8; 32]>,
        ) -> quil_types::error::Result<Option<CoinPageData>> {
            use std::sync::atomic::Ordering::SeqCst;
            assert_eq!(domain, &self.application);
            assert!(snapshot.is_none() || snapshot == Some(&[33; 32]));
            if after.is_some() {
                self.continuations.fetch_add(1, SeqCst);
                if self.expired.load(SeqCst) {
                    return Err(quil_types::error::QuilError::NotFound(
                        "coin scan snapshot unavailable or expired; restart scan".into(),
                    ));
                }
                if self
                    .cut_reads
                    .fetch_update(SeqCst, SeqCst, |left| left.checked_sub(1))
                    .is_ok()
                {
                    return Err(quil_types::error::QuilError::ExecutionUnavailable(
                        "1 peer declined: 1x Unknown: h2 protocol error: error reading a body \
                         from connection"
                            .into(),
                    ));
                }
            }
            if after.is_some()
                && self
                    .fail_continuation
                    .load(std::sync::atomic::Ordering::SeqCst)
            {
                return Err(quil_types::error::QuilError::ExecutionUnavailable(
                    "injected continuation failure".into(),
                ));
            }
            let index = self
                .coins
                .partition_point(|(address, _, _)| after.is_some_and(|old| address <= old));
            let next = self.coins.get(index);
            Ok(Some(CoinPageData {
                network: self.network,
                snapshot_id: [33; 32],
                root_record: self.root.clone(),
                coins: next
                    .into_iter()
                    .map(|(address, output, position)| CoinData {
                        address: *address,
                        frame_number: 1,
                        position: *position,
                        owner: output.owner.to_vec(),
                        commitment: output.commitment.to_bytes().to_vec(),
                        memo: output.memo.to_vec(),
                    })
                    .collect(),
                cursor: next.map(|(address, _, _)| *address).or(after.copied()),
                has_more: index + 1 < self.coins.len(),
            }))
        }
    }
    let network = [31; 32];
    let application = quil_execution::domains::QUIL_TOKEN;
    let make_wallet = || {
        let keys = sntrup761::Sntrup761KeyPair::generate();
        Arc::new(
            RecipientWallet::from_keys(
                &network,
                &application,
                &keys.public,
                Zeroizing::new(keys.secret),
            )
            .unwrap(),
        )
    };
    let wallet = make_wallet();
    let other = make_wallet();
    // Coins sit in the block their address selects, at that block's next free
    // index — the wallet refuses a scanned coin whose position says otherwise.
    use quil_execution::token_intrinsic::coin_blocks;
    let width = coin_blocks::INITIAL_BLOCK_BITS;
    let mut next_local: std::collections::BTreeMap<u64, u64> = Default::default();
    let mut coins = Vec::new();
    let mut spent_image = None;
    let mut place = |output: &Output| {
        let identity =
            quil_execution::token_intrinsic::state::coin_identity(&wallet.context, 1, output)
                .unwrap()
                .0;
        let block = coin_blocks::block_for_address(width, &identity).unwrap();
        let local = next_local.entry(block).or_default();
        let position = coin_blocks::position(width, block, *local).unwrap();
        *local += 1;
        let address = quil_execution::token_intrinsic::state::create_coin(
            &wallet.context,
            1,
            output,
            position,
        )
        .unwrap()
        .0;
        (address, position)
    };
    for (recipient, amount) in [(&wallet, 7), (&wallet, 11), (&other, 13), (&wallet, 17)] {
        let output = create_output(&wallet.context, recipient.address(), amount)
            .unwrap()
            .output;
        let (address, position) = place(&output);
        if amount == 7 {
            spent_image = Some(
                wallet
                    .recover_page(vec![(address, output.clone())])
                    .unwrap()
                    .0[0]
                    .image,
            );
        }
        coins.push((address, output, position));
    }
    // Anyone holding the wallet's address can add a coin whose memo opens
    // for it but names another amount than the commitment holds.
    let mismatched = mismatched_output(&wallet, 5);
    assert!(matches!(
        open_output(
            &wallet.context,
            &wallet.kem_secret,
            &wallet.recipient,
            &mismatched
        ),
        Err(quil_lattice_ct::confidential::memo::MemoError::InconsistentOutput)
    ));
    let (mismatched_address, position) = place(&mismatched);
    coins.push((mismatched_address, mismatched, position));
    coins.sort_by_key(|(address, _, _)| *address);
    let records: Vec<_> = coins
        .iter()
        .map(|(address, output, position)| CoinRecord {
            address: *address,
            owner: output.owner,
            commitment: output.commitment.clone(),
            position: *position,
        })
        .collect();
    let shape = quil_lattice_ct::confidential::sharded_tree::Shape {
        shard_bits: coin_blocks::BLOCK_INDEX_BITS,
        subtree_bits: coin_blocks::SUBTREE_BITS,
    };
    let tree = quil_lattice_ct::confidential::sharded_tree::ShardedCoinTree::build(
        &wallet.context,
        shape,
        &records,
    )
    .unwrap();
    let root = tree
        .root_at_depth(tree.current_depth())
        .unwrap()
        .encode()
        .unwrap()
        .to_vec();
    let listed: Vec<_> = coins
        .iter()
        .filter(|(address, _, _)| *address != mismatched_address)
        .cloned()
        .collect();
    let provider = Arc::new(Pages {
        network,
        application,
        root,
        coins,
        fail_continuation: std::sync::atomic::AtomicBool::new(false),
        cut_reads: Default::default(),
        expired: Default::default(),
        continuations: Default::default(),
    });
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    // A spend is spent once the global commit says so: its consumption record
    // lives in GLOBAL, which is where the wallet's hint looks.
    let marker = quil_execution::token_intrinsic::spent::marker_address(
        &network,
        &application,
        &spent_image.unwrap(),
    )
    .unwrap();
    let global = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS;
    let consumed =
        quil_execution::token_intrinsic::global_commit::consumed_address(&application, &marker)
            .unwrap();
    let mut marker_vertex = global.to_vec();
    marker_vertex.extend_from_slice(&consumed);
    let shard = quil_hypergraph::addressing::shard_key_for_location(
        &quil_hypergraph::addressing::Location {
            app_address: global,
            data_address: consumed,
        },
    );
    let txn = store.new_transaction(false).unwrap();
    store
        .save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &marker_vertex, &[])
        .unwrap();
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_hypergraph_store(store)
        .with_coin_witness_provider(provider.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let incoming = futures::stream::unfold(listener, |listener| async {
        let result = listener.accept().await.map(|(socket, _)| socket);
        Some((result, listener))
    });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async {
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
    let channel = tonic::transport::Endpoint::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let client = quil_types::proto::node::node_service_client::NodeServiceClient::new(channel);
    let unspent = wallet
        .clone()
        .scan_unspent(&client, 4, 2)
        .await
        .expect("skipped coins: the scan goes on past a coin whose memo does not match");
    let mut amounts: Vec<_> = unspent.iter().map(|coin| *coin.amount).collect();
    amounts.sort();
    assert_eq!(amounts, [11, 17]);
    // The mismatched coin is skipped and counted, never owned or spent; the
    // scan still returns the honest coins and balance, and ends with one
    // warning naming the coin.
    let mut report = ScanReport::default();
    let (notes, mut lines) = tokio::sync::mpsc::unbounded_channel();
    let scanned = crate::commands::token::output::capture(
        notes,
        wallet
            .clone()
            .scan_unspent_or_rootless(&client, 4, 2, &mut report),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(scanned.iter().map(|coin| *coin.amount).sum::<u128>(), 28);
    assert!(scanned
        .iter()
        .all(|coin| coin.address != mismatched_address));
    let line = report.line(std::time::Duration::ZERO);
    assert!(line.contains(", 1 skipped"), "{line}");
    let mut warnings = Vec::new();
    while let Ok(line) = lines.try_recv() {
        if line.starts_with("warning:") {
            warnings.push(line);
        }
    }
    let expected = format!(
        "warning: skipped 1 coin(s) whose memo opens for this wallet but does not match the \
         coin's amount or owner; they are not in the balance and are never spent: 0x{}",
        hex::encode(mismatched_address)
    );
    assert_eq!(warnings, [expected]);
    // One page carries every coin: the node gathers the provider's pages of
    // one coin into the page of up to 64 the wallet asks for.
    let one_page = wallet.clone().scan_unspent(&client, 1, 2).await.unwrap();
    assert_eq!(one_page.len(), 2);
    // Past its limit the scan keeps the largest coin and goes on.
    let largest = wallet.clone().scan_unspent(&client, 4, 1).await.unwrap();
    assert_eq!(
        largest.iter().map(|coin| *coin.amount).collect::<Vec<_>>(),
        [17]
    );
    provider
        .fail_continuation
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(wallet.clone().scan_unspent(&client, 4, 2).await.is_err());
    provider
        .fail_continuation
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        wallet
            .clone()
            .scan_unspent(&client, 4, 2)
            .await
            .unwrap()
            .len(),
        2
    );
    // An operation's coins are found by content, whoever owns them; one the
    // node does not list stays missing.
    #[cfg(feature = "native-proof")]
    {
        let missing = create_output(&wallet.context, other.address(), 19)
            .unwrap()
            .output;
        let wanted: Vec<Output> = listed
            .iter()
            .rev()
            .map(|(_, output, _)| output.clone())
            .chain([missing])
            .collect();
        let found = wallet
            .find_coins(
                &client,
                &wanted,
                4,
                std::time::Instant::now() + std::time::Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(
            found,
            listed
                .iter()
                .rev()
                .map(|(address, _, _)| Some(*address))
                .chain([None])
                .collect::<Vec<_>>()
        );
        let owned: Vec<bool> = wanted.iter().map(|output| wallet.owns(output)).collect();
        let expected: Vec<bool> = listed
            .iter()
            .rev()
            .map(|(_, output, _)| other.owns(output))
            .map(|theirs| !theirs)
            .chain([false])
            .collect();
        assert_eq!(owned, expected);
        assert_eq!(owned.iter().filter(|own| **own).count(), 3);
    }
    // neon, Nov 2: one cut page ended a scan minutes in and threw its pages
    // away. The first cut read only ends the node's gathering of the first
    // page; each one after fails an asking of page 2. Three askings again are
    // allowed: the last recovers, with the scan where it was.
    use std::sync::atomic::Ordering::SeqCst;
    let allowed = 1 + SCAN_READ_RETRIES;
    provider.cut_reads.store(allowed, SeqCst);
    assert_eq!(
        wallet
            .clone()
            .scan_unspent(&client, 4, 2)
            .await
            .unwrap()
            .len(),
        2,
        "the scan went on from its cursor"
    );
    assert_eq!(provider.cut_reads.load(SeqCst), 0);
    // One more cut and the scan ends, naming the page and how far it got.
    provider.cut_reads.store(allowed + 1, SeqCst);
    let stopped = wallet
        .clone()
        .scan_unspent(&client, 4, 2)
        .await
        .err()
        .expect("past the bound the scan stops")
        .to_string();
    assert!(
        stopped.starts_with("scan stopped at page 2 after 1 coins in 1 pages: "),
        "{stopped}"
    );
    assert!(
        stopped.contains("error reading a body from connection"),
        "{stopped}"
    );
    assert_eq!(provider.cut_reads.load(SeqCst), 0);
    // An expired snapshot takes a new scan: no asking again.
    provider.expired.store(true, SeqCst);
    provider.continuations.store(0, SeqCst);
    let expired = wallet
        .clone()
        .scan_unspent(&client, 4, 2)
        .await
        .err()
        .expect("the snapshot is gone")
        .to_string();
    assert!(expired.contains("restart scan"), "{expired}");
    assert_eq!(
        provider.continuations.load(SeqCst),
        2,
        "the node's gathering and one asking, not four"
    );
    provider.expired.store(false, SeqCst);
    assert_eq!(wallet.scan_unspent(&client, 4, 2).await.unwrap().len(), 2);
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// The application's coins in address order, eight a page as a node's
/// store answers them: `(address, frame, position, output)`; and its
/// escrows in address order, eight a page: `(address, blob)`. After each
/// listing, `tail` empty pages more, as a node passes over other users'
/// records: a scan's page count grows with them, not with its own.
#[cfg(feature = "native-proof")]
struct Listed {
    network: [u8; 32],
    root: Vec<u8>,
    coins: Vec<([u8; 32], u64, u64, Output)>,
    escrows: Vec<([u8; 32], Vec<u8>)>,
    tail: u64,
}

/// The cursor of a listing's `n`th empty page past its records: above
/// every address (a coin's encodes a field element, so its top byte never
/// reaches 0xff).
#[cfg(feature = "native-proof")]
fn tail_cursor(n: u64) -> [u8; 32] {
    let mut cursor = [0xff; 32];
    cursor[24..].copy_from_slice(&n.to_be_bytes());
    cursor
}

#[cfg(feature = "native-proof")]
impl Listed {
    /// The next empty page past the records after `after`, if the records
    /// are done and one is left: its cursor and whether more follow.
    fn tail_page(&self, after: Option<&[u8; 32]>, records_done: bool) -> Option<([u8; 32], bool)> {
        let done = after
            .filter(|after| after[..24] == [0xff; 24])
            .map(|after| u64::from_be_bytes(after[24..].try_into().unwrap()));
        let n = match done {
            Some(n) => n + 1,
            None if records_done && self.tail > 0 => 1,
            None => return None,
        };
        Some((tail_cursor(n), n < self.tail))
    }
}

#[cfg(feature = "native-proof")]
impl quil_types::store::CoinWitnessProvider for Listed {
    fn coin_page(
        &self,
        _: &[u8; 32],
        _: Option<&[u8; 32]>,
        after: Option<&[u8; 32]>,
    ) -> quil_types::error::Result<Option<quil_types::store::CoinPageData>> {
        use quil_types::store::{CoinData, CoinPageData};
        let start = self
            .coins
            .partition_point(|(address, ..)| after.is_some_and(|after| address <= after));
        if let Some((cursor, has_more)) = self.tail_page(after, start == self.coins.len()) {
            return Ok(Some(CoinPageData {
                network: self.network,
                snapshot_id: [33; 32],
                root_record: self.root.clone(),
                coins: Vec::new(),
                cursor: Some(cursor),
                has_more,
            }));
        }
        let page = &self.coins[start..self.coins.len().min(start + 8)];
        Ok(Some(CoinPageData {
            network: self.network,
            snapshot_id: [33; 32],
            root_record: self.root.clone(),
            coins: page
                .iter()
                .map(|(address, frame_number, position, output)| CoinData {
                    address: *address,
                    frame_number: *frame_number,
                    position: *position,
                    owner: output.owner.to_vec(),
                    commitment: output.commitment.to_bytes().to_vec(),
                    memo: output.memo.to_vec(),
                })
                .collect(),
            cursor: page.last().map(|coin| coin.0).or(after.copied()),
            has_more: start + page.len() < self.coins.len() || self.tail > 0,
        }))
    }

    fn escrow_page(
        &self,
        _: &[u8; 32],
        _: Option<&[u8; 32]>,
        after: Option<&[u8; 32]>,
    ) -> quil_types::error::Result<Option<quil_types::store::EscrowPageData>> {
        let start = self
            .escrows
            .partition_point(|(address, _)| after.is_some_and(|after| address <= after));
        if let Some((cursor, has_more)) = self.tail_page(after, start == self.escrows.len()) {
            return Ok(Some(quil_types::store::EscrowPageData {
                network: self.network,
                snapshot_id: [33; 32],
                escrows: Vec::new(),
                cursor: Some(cursor),
                has_more,
            }));
        }
        let page = &self.escrows[start..self.escrows.len().min(start + 8)];
        Ok(Some(quil_types::store::EscrowPageData {
            network: self.network,
            snapshot_id: [33; 32],
            escrows: page.to_vec(),
            cursor: page.last().map(|escrow| escrow.0).or(after.copied()),
            has_more: start + page.len() < self.escrows.len() || self.tail > 0,
        }))
    }
}

/// What a node answers a read of a scan snapshot it released.
#[cfg(feature = "native-proof")]
const SNAPSHOT_EXPIRED: &str = "coin scan snapshot unavailable or expired; restart scan";

/// [`Listed`] behind a node that fails some continuation reads: the next
/// `cut_escrow_reads` escrow reads fail as a cut transfer does, and with
/// `expired_coins` or `expired_escrows` every coin or escrow read finds
/// the scan's snapshot released.
#[cfg(feature = "native-proof")]
struct Failing {
    listed: Listed,
    cut_escrow_reads: std::sync::atomic::AtomicUsize,
    expired_coins: bool,
    expired_escrows: bool,
}

#[cfg(feature = "native-proof")]
impl quil_types::store::CoinWitnessProvider for Failing {
    fn coin_page(
        &self,
        domain: &[u8; 32],
        snapshot: Option<&[u8; 32]>,
        after: Option<&[u8; 32]>,
    ) -> quil_types::error::Result<Option<quil_types::store::CoinPageData>> {
        use quil_types::{error::QuilError, store::CoinWitnessProvider};
        if after.is_some() && self.expired_coins {
            return Err(QuilError::NotFound(SNAPSHOT_EXPIRED.into()));
        }
        CoinWitnessProvider::coin_page(&self.listed, domain, snapshot, after)
    }

    fn escrow_page(
        &self,
        domain: &[u8; 32],
        snapshot: Option<&[u8; 32]>,
        after: Option<&[u8; 32]>,
    ) -> quil_types::error::Result<Option<quil_types::store::EscrowPageData>> {
        use quil_types::{error::QuilError, store::CoinWitnessProvider};
        use std::sync::atomic::Ordering::SeqCst;
        if after.is_some() && self.expired_escrows {
            return Err(QuilError::NotFound(SNAPSHOT_EXPIRED.into()));
        }
        if after.is_some()
            && self
                .cut_escrow_reads
                .fetch_update(SeqCst, SeqCst, |left| left.checked_sub(1))
                .is_ok()
        {
            return Err(QuilError::ExecutionUnavailable(
                "1 peer declined: 1x Unknown: h2 protocol error: error reading a body from \
                 connection"
                    .into(),
            ));
        }
        CoinWitnessProvider::escrow_page(&self.listed, domain, snapshot, after)
    }
}

/// `outputs`, each `(frame, output)`, placed in their blocks and listed in
/// address order under a root over the first one (a scan only reads the
/// root), with `escrows`.
#[cfg(feature = "native-proof")]
fn listed(
    wallet: &RecipientWallet,
    outputs: Vec<(u64, Output)>,
    mut escrows: Vec<([u8; 32], Vec<u8>)>,
) -> Listed {
    use quil_execution::token_intrinsic::{coin_blocks, state};
    use quil_lattice_ct::confidential::{
        coin_tree::CoinRecord,
        sharded_tree::{Shape, ShardedCoinTree},
    };
    let width = coin_blocks::INITIAL_BLOCK_BITS;
    let mut next_local = std::collections::BTreeMap::<u64, u64>::new();
    let mut coins: Vec<_> = outputs
        .into_iter()
        .map(|(frame, output)| {
            let identity = state::coin_identity(&wallet.context, frame, &output)
                .unwrap()
                .0;
            let block = coin_blocks::block_for_address(width, &identity).unwrap();
            let local = next_local.entry(block).or_default();
            let position = coin_blocks::position(width, block, *local).unwrap();
            *local += 1;
            let address = state::create_coin(&wallet.context, frame, &output, position)
                .unwrap()
                .0;
            (address, frame, position, output)
        })
        .collect();
    let first = &coins[0];
    let tree = ShardedCoinTree::build(
        &wallet.context,
        Shape {
            shard_bits: coin_blocks::BLOCK_INDEX_BITS,
            subtree_bits: coin_blocks::SUBTREE_BITS,
        },
        &[CoinRecord {
            address: first.0,
            owner: first.3.owner,
            commitment: first.3.commitment.clone(),
            position: first.2,
        }],
    )
    .unwrap();
    let root = tree
        .root_at_depth(tree.current_depth())
        .unwrap()
        .encode()
        .unwrap()
        .to_vec();
    coins.sort_by_key(|coin| coin.0);
    escrows.sort();
    Listed {
        network: wallet.network,
        root,
        coins,
        escrows,
        tail: 0,
    }
}

/// An escrow naming `authority` as its recipient whose memo opens for
/// `wallet`, its creation committed and unconsumed in `store`: its address
/// and blob.
#[cfg(feature = "native-proof")]
fn open_escrow(
    store: &quil_hypergraph::testing::MemStore,
    wallet: &RecipientWallet,
    authority: &[u8; 897],
    amount: u128,
) -> ([u8; 32], Vec<u8>) {
    use quil_lattice_ct::confidential::{
        memo::create_escrow_recovery, pending_claim::EscrowPolicy,
    };
    let recovery =
        create_escrow_recovery(&wallet.context, wallet.address(), wallet.address(), amount)
            .unwrap();
    committed_escrow(
        store,
        wallet,
        quil_execution::token_intrinsic::escrow::StoredEscrow {
            frame_number: 1,
            output: Output {
                commitment: recovery.commitment,
                owner: recovery.recipient.owner,
                memo: recovery.recipient.ciphertext,
            },
            policy: EscrowPolicy {
                recipient: *authority,
                refund: [23; 897],
                refund_after_global_frame: 100,
            },
            refund_recovery: recovery.refund,
        },
    )
}

/// An escrow whose refund branch names `authority` and whose refund memo
/// opens for `wallet`, refundable from GLOBAL frame `refund_after`, its
/// recipient another key; committed and unconsumed in `store`. Anyone can
/// create one naming a wallet's key and claim it back before that frame.
#[cfg(feature = "native-proof")]
fn refund_escrow(
    store: &quil_hypergraph::testing::MemStore,
    wallet: &RecipientWallet,
    authority: &[u8; 897],
    amount: u128,
    refund_after: u64,
) -> ([u8; 32], Vec<u8>) {
    use quil_lattice_ct::confidential::{
        memo::create_escrow_recovery, pending_claim::EscrowPolicy,
    };
    let recovery =
        create_escrow_recovery(&wallet.context, wallet.address(), wallet.address(), amount)
            .unwrap();
    committed_escrow(
        store,
        wallet,
        quil_execution::token_intrinsic::escrow::StoredEscrow {
            frame_number: 1,
            output: Output {
                commitment: recovery.commitment,
                owner: recovery.recipient.owner,
                memo: recovery.recipient.ciphertext,
            },
            policy: EscrowPolicy {
                recipient: [24; 897],
                refund: *authority,
                refund_after_global_frame: refund_after,
            },
            refund_recovery: recovery.refund,
        },
    )
}

/// An escrow naming `authority` as its recipient whose memo opens for
/// `wallet` but carries another amount than its commitment, as
/// [`mismatched_output`] builds it; committed and unconsumed in `store`.
#[cfg(feature = "native-proof")]
fn mismatched_escrow(
    store: &quil_hypergraph::testing::MemStore,
    wallet: &RecipientWallet,
    authority: &[u8; 897],
    amount: u128,
) -> ([u8; 32], Vec<u8>) {
    use quil_lattice_ct::confidential::{
        memo::create_escrow_recovery, pending_claim::EscrowPolicy,
    };
    let output = mismatched_output(wallet, amount);
    let refund = create_escrow_recovery(&wallet.context, wallet.address(), wallet.address(), 1)
        .unwrap()
        .refund;
    committed_escrow(
        store,
        wallet,
        quil_execution::token_intrinsic::escrow::StoredEscrow {
            frame_number: 1,
            output,
            policy: EscrowPolicy {
                recipient: *authority,
                refund: [23; 897],
                refund_after_global_frame: 100,
            },
            refund_recovery: refund,
        },
    )
}

/// `escrow`'s address and blob, its creation committed and unconsumed in
/// `store`.
#[cfg(feature = "native-proof")]
fn committed_escrow(
    store: &quil_hypergraph::testing::MemStore,
    wallet: &RecipientWallet,
    escrow: quil_execution::token_intrinsic::escrow::StoredEscrow,
) -> ([u8; 32], Vec<u8>) {
    use quil_execution::token_intrinsic::global_commit;
    use quil_types::store::*;
    let (address, blob) = escrow.encode(&wallet.context).unwrap();
    let global = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS;
    let global_shard = ShardKey {
        l1: quil_hypergraph::addressing::get_bloom_filter_indices(&global, 256, 3),
        l2: global,
    };
    let mut record = global.to_vec();
    record
        .extend_from_slice(&global_commit::escrow_address(&wallet.application, &address).unwrap());
    let txn = store.new_transaction(false).unwrap();
    store
        .save_vertex_underlying(
            txn.as_ref(),
            "vertex",
            "adds",
            &global_shard,
            &record,
            &global_commit::encode_escrow_record(&[5; 32], 100, false).unwrap(),
        )
        .unwrap();
    (address, blob)
}

/// A node for `tc`'s wallet, served on `listener`, holding what its scans
/// must leave out: beside an honest 20 and 6, the 6 sent again in a later
/// frame, a coin whose memo does not match and a 3 past a limit of two
/// coins; and pending transfers of 7, 9 and 11 to its prover key, with one
/// whose memo does not match.
#[cfg(feature = "native-proof")]
pub(crate) fn serve_left_out(
    tc: &TokenCtx,
    listener: tokio::net::TcpListener,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    serve_left_out_with(tc, listener, 0, false)
}

/// [`serve_left_out`]'s node, each listing followed by `tail` empty pages
/// (other users' records, read in pages of eight), and with `broken` an
/// escrow record the wallet cannot decode, which fails its escrow scan.
#[cfg(feature = "native-proof")]
pub(crate) fn serve_left_out_with(
    tc: &TokenCtx,
    listener: tokio::net::TcpListener,
    tail: u64,
    broken: bool,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    serve_left_out_failing(tc, listener, tail, broken, None)
}

/// [`serve_left_out`]'s node with an empty page after each listing, on
/// which the coin scan, or with `escrows` the escrow scan, finds its
/// snapshot released.
#[cfg(feature = "native-proof")]
pub(crate) fn serve_left_out_expiring(
    tc: &TokenCtx,
    listener: tokio::net::TcpListener,
    escrows: bool,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    serve_left_out_failing(tc, listener, 1, false, Some(escrows))
}

/// [`serve_left_out_with`]'s node. With `expired`, the coin scan
/// (`Some(false)`) or the escrow scan (`Some(true)`) finds its snapshot
/// released past page 1.
#[cfg(feature = "native-proof")]
fn serve_left_out_failing(
    tc: &TokenCtx,
    listener: tokio::net::TcpListener,
    tail: u64,
    broken: bool,
    expired: Option<bool>,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    use quil_lattice_ct::confidential::memo::create_output;
    let network =
        quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = RecipientWallet::load(tc, &network, &quil_execution::domains::QUIL_TOKEN).unwrap();
    let output = |amount| {
        create_output(&wallet.context, wallet.address(), amount)
            .unwrap()
            .output
    };
    let six = output(6);
    let outputs = vec![
        (1, output(20)),
        (1, six.clone()),
        (2, six),
        (1, mismatched_output(&wallet, 5)),
        (1, output(3)),
    ];
    let authority: [u8; 897] = tc
        .key_manager
        .get_public_key_bytes_by_id("q-prover-key")
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    let mut escrows: Vec<_> = [7, 9, 11]
        .into_iter()
        .map(|amount| open_escrow(&store, &wallet, &authority, amount))
        .collect();
    escrows.push(mismatched_escrow(&store, &wallet, &authority, 13));
    if broken {
        escrows.push(([0x80; 32], vec![1, 2, 3]));
    }
    let mut listed = listed(&wallet, outputs, escrows);
    listed.tail = tail;
    let failing = Failing {
        listed,
        cut_escrow_reads: Default::default(),
        expired_coins: expired == Some(false),
        expired_escrows: expired == Some(true),
    };
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_hypergraph_store(store)
        .with_coin_witness_provider(Arc::new(failing));
    serve_node(listener, server)
}

/// A sender can give two coins of a wallet one spend image: one output
/// sent again in a later frame, or one nonce used twice. Spending either
/// consumes the image, so a scan keeps one coin per image (the largest; of
/// equal ones the oldest, then the lower address) and names the others;
/// the balance, the coin limit, coin selection and a merge see each image
/// once. A scan meets coins in address order, and the fixture fixes that
/// order so that every run meets each kind of pair.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_wallet_scan_keeps_one_coin_per_spend_image() {
    use quil_execution::token_intrinsic::state;
    use quil_lattice_ct::confidential::memo::{create_output, create_output_with_nonce};
    let network = [31; 32];
    let application = quil_execution::domains::QUIL_TOKEN;
    let keys = sntrup761::Sntrup761KeyPair::generate();
    let wallet = Arc::new(
        RecipientWallet::from_keys(
            &network,
            &application,
            &keys.public,
            Zeroizing::new(keys.secret),
        )
        .unwrap(),
    );
    let with_nonce = |amount, nonce: u8| {
        create_output_with_nonce(&wallet.context, wallet.address(), amount, &[nonce; 32])
            .unwrap()
            .output
    };
    let address = |(frame, output): &(u64, Output)| {
        state::coin_identity(&wallet.context, *frame, output)
            .unwrap()
            .0
    };
    // A fresh memo moves a coin's address: draw memos until a group lists
    // in the order given.
    let in_order = |make: &dyn Fn() -> Vec<(u64, Output)>| {
        for _ in 0..256 {
            let group = make();
            if group
                .windows(2)
                .all(|pair| address(&pair[0]) < address(&pair[1]))
            {
                return group;
            }
        }
        panic!("no memo draw lists the group in order");
    };
    let honest = (
        1,
        create_output(&wallet.context, wallet.address(), 20)
            .unwrap()
            .output,
    );
    // A 6 listed first from frame 2, then the same output from frame 1,
    // then another 6 on its nonce from frame 1: the second counts.
    let sixes = in_order(&|| {
        let six = with_nonce(6, 1);
        vec![(2, six.clone()), (1, six), (1, with_nonce(6, 1))]
    });
    // On one nonce a 3 then a 9: the 9 replaces the 3. On another an 8
    // then a 4: the 8 stays.
    let rising = in_order(&|| vec![(1, with_nonce(3, 2)), (1, with_nonce(9, 2))]);
    let falling = in_order(&|| vec![(1, with_nonce(8, 3)), (1, with_nonce(4, 3))]);
    let expected: std::collections::BTreeSet<[u8; 32]> = [
        address(&honest),
        address(&sixes[1]),
        address(&rising[1]),
        address(&falling[0]),
    ]
    .into();
    let mut outputs = vec![honest];
    outputs.extend(sixes);
    outputs.extend(rising);
    outputs.extend(falling);
    let listed = listed(&wallet, outputs, Vec::new());
    let all: Vec<[u8; 32]> = listed.coins.iter().map(|coin| coin.0).collect();
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_hypergraph_store(Arc::new(quil_hypergraph::testing::MemStore::new()))
        .with_coin_witness_provider(Arc::new(listed));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, serving) = serve_node(listener, server);
    let client = quil_types::proto::node::node_service_client::NodeServiceClient::new(
        tonic::transport::Endpoint::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    let mut report = ScanReport::default();
    let (notes, mut lines) = tokio::sync::mpsc::unbounded_channel();
    let scanned = crate::commands::token::output::capture(
        notes,
        wallet
            .clone()
            .scan_unspent_or_rootless(&client, 4, 8, &mut report),
    )
    .await
    .unwrap()
    .unwrap();
    let mut amounts: Vec<u128> = scanned.iter().map(|coin| *coin.amount).collect();
    amounts.sort();
    assert_eq!(
        amounts,
        [6, 8, 9, 20],
        "skipped coins: each spend image counts once, for its largest coin"
    );
    let kept: std::collections::BTreeSet<[u8; 32]> =
        scanned.iter().map(|coin| coin.address).collect();
    assert_eq!(
        kept, expected,
        "skipped coins: of equal coins on one image the oldest counts, then the lower address"
    );
    let skipped: Vec<[u8; 32]> = all
        .iter()
        .copied()
        .filter(|address| !kept.contains(address))
        .collect();
    assert_eq!(skipped.len(), 4);
    let line = report.line(std::time::Duration::ZERO);
    assert!(line.contains(", 4 skipped"), "{line}");
    let mut warnings = Vec::new();
    while let Ok(line) = lines.try_recv() {
        if line.starts_with("warning:") {
            warnings.push(line);
        }
    }
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    let warning = &warnings[0];
    let prefix = "warning: skipped 4 coin(s) sharing a spend image with another coin of this \
                  wallet; only one coin per image can be spent, so the balance counts the \
                  largest: 0x";
    assert!(warning.starts_with(prefix), "{warning}");
    assert!(!warning.ends_with("..."), "{warning}");
    for address in &all {
        let named = warning.contains(&format!("0x{}", hex::encode(address)));
        assert_eq!(named, skipped.contains(address), "{warning}");
    }
    // The coin limit counts images, and the whole balance funds one
    // transfer or merge without a second coin of an image.
    let four = wallet.clone().scan_unspent(&client, 4, 4).await.unwrap();
    let (selected, change) = select_coins(four, 43, 0, 4).unwrap();
    assert_eq!((selected.len(), *change), (4, 0));
    let again = wallet.clone().scan_unspent(&client, 4, 4).await.unwrap();
    let (merged, total) = merge_selection(again, &[], 4).unwrap();
    assert_eq!(total, 43);
    let images: std::collections::BTreeSet<_> = merged.iter().map(|coin| coin.image).collect();
    assert_eq!(images.len(), merged.len());
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// Anyone can send a wallet coins, at the cost of fees. Past its limit a
/// scan keeps the coins that rank first (the largest; of equal ones the
/// oldest, then the lower address), names the rest in a warning, and goes
/// on; hiding a coin takes more than the limit's count of larger ones.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_scan_past_its_coin_limit_keeps_the_largest() {
    use quil_lattice_ct::confidential::memo::create_output;
    let keys = sntrup761::Sntrup761KeyPair::generate();
    let wallet = Arc::new(
        RecipientWallet::from_keys(
            &[31; 32],
            &quil_execution::domains::QUIL_TOKEN,
            &keys.public,
            Zeroizing::new(keys.secret),
        )
        .unwrap(),
    );
    let output = |amount| {
        create_output(&wallet.context, wallet.address(), amount)
            .unwrap()
            .output
    };
    // Two coins of 11, from frames 2 and 1: of the two the older counts.
    let older = output(11);
    let older_address =
        quil_execution::token_intrinsic::state::coin_identity(&wallet.context, 1, &older)
            .unwrap()
            .0;
    let listed = listed(
        &wallet,
        vec![
            (1, output(5)),
            (2, output(11)),
            (1, output(7)),
            (1, older),
            (1, output(13)),
        ],
        Vec::new(),
    );
    let all: Vec<[u8; 32]> = listed.coins.iter().map(|coin| coin.0).collect();
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_hypergraph_store(Arc::new(quil_hypergraph::testing::MemStore::new()))
        .with_coin_witness_provider(Arc::new(listed));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, serving) = serve_node(listener, server);
    let client = quil_types::proto::node::node_service_client::NodeServiceClient::new(
        tonic::transport::Endpoint::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    let mut report = ScanReport::default();
    let (notes, mut lines) = tokio::sync::mpsc::unbounded_channel();
    let kept = crate::commands::token::output::capture(
        notes,
        wallet
            .clone()
            .scan_unspent_or_rootless(&client, 4, 2, &mut report),
    )
    .await
    .expect("skipped coins: a scan past its coin limit goes on")
    .unwrap();
    let mut amounts: Vec<u128> = kept.iter().map(|coin| *coin.amount).collect();
    amounts.sort();
    assert_eq!(
        amounts,
        [11, 13],
        "skipped coins: past the limit the largest coins count"
    );
    assert!(
        kept.iter().any(|coin| coin.address == older_address),
        "skipped coins: of equal coins past the limit the oldest counts"
    );
    let line = report.line(std::time::Duration::ZERO);
    assert!(line.contains(", 3 skipped"), "{line}");
    let warnings: Vec<String> = std::iter::from_fn(|| lines.try_recv().ok())
        .filter(|line| line.starts_with("warning:"))
        .collect();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    let warning = &warnings[0];
    let prefix = "warning: left out 3 coin(s) past the scan's coin limit; the balance counts \
                  the largest; a larger --max-coins counts more, and merging coins brings more \
                  into the count: 0x";
    assert!(warning.starts_with(prefix), "{warning}");
    for address in &all {
        let named = warning.contains(&format!("0x{}", hex::encode(address)));
        let counted = kept.iter().any(|coin| coin.address == *address);
        assert_eq!(named, !counted, "{warning}");
    }
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// Anyone can name a wallet in an escrow, at the cost of fees. Past its
/// limit an escrow scan keeps the largest, in scan order, warns how many it
/// left out, and goes on.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn an_escrow_scan_past_its_limit_keeps_the_largest() {
    let keys = sntrup761::Sntrup761KeyPair::generate();
    let wallet = Arc::new(
        RecipientWallet::from_keys(
            &[31; 32],
            &quil_execution::domains::QUIL_TOKEN,
            &keys.public,
            Zeroizing::new(keys.secret),
        )
        .unwrap(),
    );
    let authority = [22; 897];
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    let mut escrows: Vec<_> = [5, 11, 7, 13, 9]
        .into_iter()
        .map(|amount| open_escrow(&store, &wallet, &authority, amount))
        .collect();
    escrows.sort();
    let listed = Listed {
        network: wallet.network,
        root: Vec::new(),
        coins: Vec::new(),
        escrows,
        tail: 0,
    };
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_hypergraph_store(store)
        .with_coin_witness_provider(Arc::new(listed));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, serving) = serve_node(listener, server);
    let client = quil_types::proto::node::node_service_client::NodeServiceClient::new(
        tonic::transport::Endpoint::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    let (notes, mut lines) = tokio::sync::mpsc::unbounded_channel();
    let (kept, left_out) = crate::commands::token::output::capture(
        notes,
        wallet
            .clone()
            .scan_escrows(&client, authority.to_vec(), 4, 2),
    )
    .await
    .expect("skipped coins: an escrow scan past its limit goes on");
    let mut amounts: Vec<u128> = kept.iter().map(|escrow| *escrow.1).collect();
    amounts.sort();
    assert_eq!(
        amounts,
        [11, 13],
        "skipped coins: past the limit the largest escrows are kept"
    );
    assert!(kept.windows(2).all(|pair| pair[0].0 < pair[1].0));
    assert!(kept.iter().all(|escrow| !escrow.2 && escrow.3 == 100));
    assert_eq!(left_out.limited, 3);
    let warnings: Vec<String> = std::iter::from_fn(|| lines.try_recv().ok())
        .filter(|line| line.starts_with("warning:"))
        .collect();
    let expected = "warning: left out 3 of 5 unconsumed escrow(s) naming this wallet: past the \
                    limit of 2 the scan keeps those this wallet can act on now, then the \
                    largest; a larger --max-escrows lists more";
    assert_eq!(warnings, [expected]);
    // Within the limit it keeps them all, without a warning.
    let (notes, mut lines) = tokio::sync::mpsc::unbounded_channel();
    let (all, left_out) = crate::commands::token::output::capture(
        notes,
        wallet
            .clone()
            .scan_escrows(&client, authority.to_vec(), 4, 5),
    )
    .await
    .unwrap();
    assert_eq!((all.len(), left_out.limited), (5, 0));
    assert!(std::iter::from_fn(|| lines.try_recv().ok()).all(|line| !line.starts_with("warning:")));
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// A scan's warnings: one line per kind of skipped coin, each counting
/// every coin of its kind and naming the first four.
#[test]
fn scan_warnings_count_every_skipped_coin_and_name_the_first_four() {
    let mut report = ScanReport::default();
    assert!(report.warnings().is_empty());
    for n in 1..=6 {
        report.skip_mismatched([n; 32]);
    }
    report.skip_duplicate([9; 32]);
    let named = |of: &[u8]| {
        of.iter()
            .map(|n| format!("0x{}", hex::encode([*n; 32])))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mismatched = format!(
        "warning: skipped 6 coin(s) whose memo opens for this wallet but does not match the \
         coin's amount or owner; they are not in the balance and are never spent: {}, ...",
        named(&[1, 2, 3, 4])
    );
    let duplicate = format!(
        "warning: skipped 1 coin(s) sharing a spend image with another coin of this wallet; \
         only one coin per image can be spent, so the balance counts the largest: {}",
        named(&[9])
    );
    assert_eq!(
        report.warnings(),
        [mismatched, duplicate],
        "skipped coins: one warning per kind, naming the first four"
    );
    let line = report.line(std::time::Duration::ZERO);
    assert!(line.ends_with(", 7 skipped"), "{line}");
}

/// A wallet for the scan tests, on a test network's QUIL.
#[cfg(feature = "native-proof")]
fn scan_wallet() -> Arc<RecipientWallet> {
    let keys = sntrup761::Sntrup761KeyPair::generate();
    Arc::new(
        RecipientWallet::from_keys(
            &[31; 32],
            &quil_execution::domains::QUIL_TOKEN,
            &keys.public,
            Zeroizing::new(keys.secret),
        )
        .unwrap(),
    )
}

/// `listed` served over loopback with `store`, the node reporting GLOBAL
/// head `head`: a client and the node's shutdown.
#[cfg(feature = "native-proof")]
async fn serve_listed(
    listed: impl quil_types::store::CoinWitnessProvider + 'static,
    store: Arc<quil_hypergraph::testing::MemStore>,
    head: u64,
) -> (
    quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_hypergraph_store(store)
        .with_coin_witness_provider(Arc::new(listed));
    server
        .last_global_head_frame
        .store(head, std::sync::atomic::Ordering::Relaxed);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, serving) = serve_node(listener, server);
    let client = quil_types::proto::node::node_service_client::NodeServiceClient::new(
        tonic::transport::Endpoint::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    (client, stop, serving)
}

/// The warning lines a captured run printed.
#[cfg(feature = "native-proof")]
fn warning_lines(lines: &mut tokio::sync::mpsc::UnboundedReceiver<String>) -> Vec<String> {
    std::iter::from_fn(|| lines.try_recv().ok())
        .filter(|line| line.starts_with("warning:"))
        .collect()
}

/// A/B reproducer: a scan's pages hold every coin or escrow of the
/// application, nearly all of them other users', so a page budget let
/// anyone end every scan for fees: by default 2,048 pages (131,072 coins
/// at 64 a page). With no default cap, a coin scan and an escrow scan read
/// past that many pages. Empty pages stand in for full ones: a node
/// gathers eight reads per page, and a budget counted pages either way.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_default_scan_reads_past_the_old_page_budget() {
    use clap::Parser;
    use quil_lattice_ct::confidential::memo::create_output;
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        token: super::super::TokenArgs,
    }
    let defaults = Cli::try_parse_from(["qclient", "balance"]).unwrap().token;
    let wallet = scan_wallet();
    let authority = [22; 897];
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    let escrow = open_escrow(&store, &wallet, &authority, 7);
    let coin = create_output(&wallet.context, wallet.address(), 5)
        .unwrap()
        .output;
    let mut listed = listed(&wallet, vec![(1, coin)], vec![escrow]);
    let pages = 2_048 + 8;
    listed.tail = pages * 8;
    let (client, stop, serving) = serve_listed(listed, store, 0).await;
    let (escrows, _) = wallet
        .clone()
        .scan_escrows(
            &client,
            authority.to_vec(),
            defaults.page_cap(),
            defaults.max_coins,
        )
        .await
        .unwrap_or_else(|error| {
            panic!(
                "skipped coins: none, but a default escrow scan of {pages} pages stopped: {error}"
            )
        });
    assert_eq!(escrows.len(), 1);
    assert_eq!(*escrows[0].1, 7);
    let coins = wallet
        .clone()
        .scan_unspent(&client, defaults.page_cap(), defaults.max_coins)
        .await
        .unwrap_or_else(|error| {
            panic!("skipped coins: none, but a default coin scan of {pages} pages stopped: {error}")
        });
    assert_eq!(coins.len(), 1);
    assert_eq!(*coins[0].amount, 5);
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// Anyone can name a wallet's key as an escrow's refund, with a far refund
/// frame, and claim the escrow back at will: such an escrow costs its
/// creator only fees. Past its limit an escrow scan keeps first the
/// escrows the wallet can act on now (its recipient branch, or its refund
/// branch from the refund frame), then the largest, so larger escrows of
/// that kind do not push the wallet's incoming transfers out.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn an_escrow_scan_keeps_what_the_wallet_can_act_on_first() {
    let wallet = scan_wallet();
    let authority = [22; 897];
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    let mut escrows = vec![
        open_escrow(&store, &wallet, &authority, 5),
        refund_escrow(&store, &wallet, &authority, 3, 400),
    ];
    for amount in 100..104 {
        let far = 1_000_000;
        escrows.push(refund_escrow(&store, &wallet, &authority, amount, far));
    }
    escrows.sort();
    let listed = Listed {
        network: wallet.network,
        root: Vec::new(),
        coins: Vec::new(),
        escrows,
        tail: 0,
    };
    let (client, stop, serving) = serve_listed(listed, store, 500).await;
    let (notes, mut lines) = tokio::sync::mpsc::unbounded_channel();
    let (kept, left_out) = crate::commands::token::output::capture(
        notes,
        wallet
            .clone()
            .scan_escrows(&client, authority.to_vec(), 4, 3),
    )
    .await
    .expect("skipped coins: an escrow scan past its limit goes on");
    let mut amounts: Vec<(u128, bool)> = kept.iter().map(|escrow| (*escrow.1, escrow.2)).collect();
    amounts.sort();
    assert_eq!(
        amounts,
        [(3, true), (5, false), (103, true)],
        "skipped coins: past the limit the escrows this wallet can act on now are kept first"
    );
    assert!(kept.windows(2).all(|pair| pair[0].0 < pair[1].0));
    assert_eq!(left_out.limited, 3);
    let expected = "warning: left out 3 of 6 unconsumed escrow(s) naming this wallet: past the \
                    limit of 3 the scan keeps those this wallet can act on now, then the \
                    largest; a larger --max-escrows lists more";
    assert_eq!(warning_lines(&mut lines), [expected]);
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// An escrow's creator chooses its memo, which no verifier can open: one
/// that opens for the wallet but does not match the escrow can be neither
/// accepted nor refunded. The scan counts it and warns, as it does for
/// such a coin, and lists the others.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn an_escrow_whose_memo_does_not_match_is_counted() {
    let wallet = scan_wallet();
    let authority = [22; 897];
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    let mut escrows = vec![
        open_escrow(&store, &wallet, &authority, 7),
        mismatched_escrow(&store, &wallet, &authority, 9),
    ];
    escrows.sort();
    let listed = Listed {
        network: wallet.network,
        root: Vec::new(),
        coins: Vec::new(),
        escrows,
        tail: 0,
    };
    let (client, stop, serving) = serve_listed(listed, store, 0).await;
    let (notes, mut lines) = tokio::sync::mpsc::unbounded_channel();
    let (kept, skipped) = crate::commands::token::output::capture(
        notes,
        wallet
            .clone()
            .scan_escrows(&client, authority.to_vec(), 4, 4),
    )
    .await
    .unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(*kept[0].1, 7);
    assert_eq!(
        skipped.mismatched, 1,
        "skipped coins: an escrow whose memo does not match is counted"
    );
    assert_eq!(skipped.limited, 0);
    let expected = "warning: skipped 1 unconsumed escrow(s) naming this wallet whose memo opens \
                    for it but does not match the escrow; this wallet can neither accept nor \
                    refund them";
    assert_eq!(warning_lines(&mut lines), [expected]);
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// A node can fail to deliver a page, as when a transfer is cut, and a
/// scan can last an hour: an escrow scan asks again for such a page, as a
/// coin scan does, and goes on from its cursor rather than losing the whole
/// read. The first cut read only ends the node's gathering of page 1; the
/// second fails the first asking of page 2.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn an_escrow_scan_asks_again_for_a_page_the_node_could_not_deliver() {
    let wallet = scan_wallet();
    let authority = [22; 897];
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    let failing = Failing {
        listed: Listed {
            network: wallet.network,
            root: Vec::new(),
            coins: Vec::new(),
            escrows: vec![open_escrow(&store, &wallet, &authority, 7)],
            tail: 1,
        },
        cut_escrow_reads: std::sync::atomic::AtomicUsize::new(2),
        expired_coins: false,
        expired_escrows: false,
    };
    let (client, stop, serving) = serve_listed(failing, store, 0).await;
    let (kept, _) = wallet
        .clone()
        .scan_escrows(&client, authority.to_vec(), 4, 4)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "skipped coins: none, but an escrow scan stopped at one transient page error: \
                 {error}"
            )
        });
    assert_eq!(kept.len(), 1);
    assert_eq!(*kept[0].1, 7);
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// What an escrow scan with a limit of one keeps, as `(amount, refund
/// branch)`, of an incoming 5 and a refund of 9 from GLOBAL frame
/// `refund_after`, at head 500. With `no_head` the node refuses the scan's
/// read of the head: a scan within the limit, which reads no head, counts
/// the calls before it, and the node refuses the limited scan's next one.
#[cfg(feature = "native-proof")]
#[allow(clippy::result_large_err)] // tonic's interceptor returns its Status by value
async fn due_refund_or_incoming(refund_after: u64, no_head: bool) -> Vec<(u128, bool)> {
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    let wallet = scan_wallet();
    let authority = [22; 897];
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    let mut escrows = vec![
        open_escrow(&store, &wallet, &authority, 5),
        refund_escrow(&store, &wallet, &authority, 9, refund_after),
    ];
    escrows.sort();
    let listed = Listed {
        network: wallet.network,
        root: Vec::new(),
        coins: Vec::new(),
        escrows,
        tail: 0,
    };
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_hypergraph_store(store)
        .with_coin_witness_provider(Arc::new(listed));
    server.last_global_head_frame.store(500, SeqCst);
    let calls = Arc::new(AtomicUsize::new(0));
    // The call the node refuses, counted from one; none while zero.
    let refused = Arc::new(AtomicUsize::new(0));
    let (seen, refuse) = (calls.clone(), refused.clone());
    let service = quil_types::proto::node::node_service_server::NodeServiceServer::with_interceptor(
        server,
        move |request: tonic::Request<()>| {
            if seen.fetch_add(1, SeqCst) + 1 == refuse.load(SeqCst) {
                Err(tonic::Status::unavailable(
                    "this node reports no GLOBAL head",
                ))
            } else {
                Ok(request)
            }
        },
    );
    let (listener, multiaddr) = bind_loopback().await;
    let incoming = futures::stream::unfold(listener, |listener| async {
        let result = listener.accept().await.map(|(socket, _)| socket);
        Some((result, listener))
    });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let client = client_at(&multiaddr).await;
    let (all, _) = wallet
        .clone()
        .scan_escrows(&client, authority.to_vec(), 4, 2)
        .await
        .unwrap();
    assert_eq!(all.len(), 2);
    let before_head = calls.load(SeqCst);
    let head_read = 2 * before_head + 1;
    if no_head {
        refused.store(head_read, SeqCst);
    }
    let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
    let (kept, left_out) = crate::commands::token::output::capture(
        notes,
        wallet
            .clone()
            .scan_escrows(&client, authority.to_vec(), 4, 1),
    )
    .await
    .expect("skipped coins: an escrow scan past its limit goes on");
    assert_eq!(left_out.limited, 1);
    assert_eq!(calls.load(SeqCst), head_read, "the head was read last");
    stop.send(()).unwrap();
    serving.await.unwrap();
    kept.iter().map(|escrow| (*escrow.1, escrow.2)).collect()
}

/// Execution admits a refund from its refund frame on, so a refund branch
/// is one the wallet can act on from that frame: at GLOBAL head 500 a
/// refund from frame 500 ranks with the incoming transfers and, larger,
/// is kept; one from frame 501 ranks after them.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_refund_is_actionable_from_its_refund_frame() {
    assert_eq!(
        due_refund_or_incoming(500, false).await,
        [(9, true)],
        "skipped coins: a refund at its refund frame is one the wallet can act on"
    );
    assert_eq!(due_refund_or_incoming(501, false).await, [(5, false)]);
}

/// Without a GLOBAL head (the node's info read fails), no refund ranks as
/// one the wallet can act on: the scan goes on and keeps the incoming
/// transfers first. With the head read, the same node's refund from frame
/// 400 is kept.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn without_a_global_head_refunds_rank_after_incoming_transfers() {
    assert_eq!(due_refund_or_incoming(400, false).await, [(9, true)]);
    assert_eq!(
        due_refund_or_incoming(400, true).await,
        [(5, false)],
        "skipped coins: without a GLOBAL head the incoming transfer is kept first"
    );
}

/// A/B reproducer: a bundle payment (`deploy`, a paid write) scans the
/// payer's coins with the page cap a balance scan has: none by default. A
/// budget of 128 pages ended every payment once the network held more
/// than 8,192 coins (128 full pages of 64), which anyone can send for
/// fees. The payment runs through `pay_for_bundle` against a node whose
/// coins take more than 128 pages, and the payer holds 1 base unit: past
/// its scan the payment fails for funds, not for its page count. Empty
/// pages stand in for full ones.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_bundle_payment_scans_past_page_128() {
    use quil_lattice_ct::confidential::memo::create_output;
    let directory = tempfile::tempdir().unwrap();
    let key_manager = Arc::new(
        quil_keys::FileKeyManager::new(
            directory.path().join("keys.yml"),
            &hex::encode([9; 32]),
            "q-prover-key".into(),
            Box::new(quil_crypto::FalconKeyConstructor),
        )
        .unwrap(),
    );
    key_manager.create_agreement_key("q-onion-key", 9).unwrap();
    let (listener, multiaddr) = bind_loopback().await;
    let opts = crate::rpc::ConnectOpts {
        listen_grpc_multiaddr: multiaddr,
        ..Default::default()
    };
    let tc = TokenCtx {
        node_config: quil_config::Config::default(),
        config_dir: directory.path().to_path_buf(),
        key_manager: key_manager.clone(),
        connect_opts: opts.clone(),
        submit_opts: opts,
        submit_key_manager: key_manager,
        submit_config_dir: directory.path().to_path_buf(),
        submit_identity: Default::default(),
        peer_id_bytes: Vec::new(),
        read_flags: Vec::new(),
        max_fee: u128::MAX,
    };
    let network = quote_network();
    let application = quil_execution::domains::QUIL_TOKEN;
    let wallet = RecipientWallet::load(&tc, &network, &application).unwrap();
    let coin = create_output(&wallet.context, wallet.address(), 1)
        .unwrap()
        .output;
    let mut listed = listed(&wallet, vec![(1, coin)], Vec::new());
    // Pages of eight reads, past 128 pages.
    listed.tail = (128 + 8) * 8;
    let server = quoting_node()
        .with_hypergraph_store(Arc::new(quil_hypergraph::testing::MemStore::new()))
        .with_coin_witness_provider(Arc::new(listed));
    let (stop, serving) = serve_node(listener, server);
    let rest = quil_execution::message_envelope::CanonicalMessageBundle {
        requests: vec![None],
        timestamp: 0,
    };
    let payment = pay_for_bundle(&tc, [0x42; 32], &rest, None, std::time::Duration::ZERO);
    let error = Box::pin(payment)
        .await
        .expect_err("the payer holds 1 base unit")
        .to_string();
    assert!(
        error.contains("insufficient node-reported unspent funds"),
        "skipped coins: none, but the payment stopped before its scan read every page: {error}"
    );
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// A node can answer a page that holds no coin: `recover_page` returns at
/// once for it, without deriving the keys that open a coin and give its
/// spend image.
#[cfg(feature = "native-proof")]
#[test]
fn an_empty_scan_page_derives_no_key() {
    use quil_lattice_ct::confidential::memo::create_output;
    let wallet = scan_wallet();
    let derived = || KEY_DERIVATIONS.with(std::cell::Cell::get);
    let before = derived();
    let (owned, mismatched) = wallet.recover_page(Vec::new()).unwrap();
    assert!(owned.is_empty() && mismatched.is_empty());
    assert_eq!(
        derived(),
        before,
        "a page holding no coin derived the wallet's keys"
    );
    let output = create_output(&wallet.context, wallet.address(), 3)
        .unwrap()
        .output;
    let (owned, _) = wallet.recover_page(vec![([1; 32], output)]).unwrap();
    assert_eq!(owned.len(), 1);
    assert_eq!(
        derived(),
        before + 1,
        "a page holding a coin derives the keys once"
    );
}

/// The node releases a scan's snapshot an hour after the scan starts. A
/// scan stopped by that says so, and that running it again on that node
/// fails the same way; one whose snapshot went sooner (left idle, a node
/// restart) or whose pin was lost says to run it again.
#[test]
fn a_scan_that_outlives_its_snapshot_says_why() {
    const EXPIRED: &str = "coin scan snapshot unavailable or expired; restart scan";
    const UNPINNED: &str = "the peer serving this scan is no longer pinned; restart the scan";
    let status = |message: &str| anyhow::Error::from(tonic::Status::not_found(message));
    let report = ScanReport {
        pages: 9,
        coins: 576,
        ..Default::default()
    };
    let hour = report
        .stopped(status(EXPIRED), SCAN_SNAPSHOT_MAX_AGE)
        .to_string();
    assert!(
        hour.starts_with("scan stopped at page 10 after 576 coins in 9 pages and 60 min: "),
        "{hour}"
    );
    assert!(hour.contains("fails the same way"), "{hour}");
    let sooner = report
        .stopped(status(EXPIRED), SCAN_SNAPSHOT_MAX_AGE / 2)
        .to_string();
    assert!(sooner.ends_with("run it again"), "{sooner}");
    let unpinned = report
        .stopped(status(UNPINNED), SCAN_SNAPSHOT_MAX_AGE)
        .to_string();
    assert!(unpinned.ends_with("run it again"), "{unpinned}");
}

/// A scan of the whole application can take up to the hour the node keeps
/// its snapshot, so a coin or escrow scan that goes on prints how far it
/// got every 64 pages. Empty pages stand in for full ones.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_long_scan_reports_its_progress() {
    use quil_lattice_ct::confidential::memo::create_output;
    let wallet = scan_wallet();
    let authority = [22; 897];
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    let escrow = open_escrow(&store, &wallet, &authority, 7);
    let coin = create_output(&wallet.context, wallet.address(), 5)
        .unwrap()
        .output;
    let mut listed = listed(&wallet, vec![(1, coin)], vec![escrow]);
    // Pages of eight reads, past 128 pages.
    listed.tail = (128 + 8) * 8;
    let (client, stop, serving) = serve_listed(listed, store, 0).await;
    let uncapped = super::super::SCAN_PAGES_UNCAPPED;
    let (notes, mut lines) = tokio::sync::mpsc::unbounded_channel();
    let coins = crate::commands::token::output::capture(
        notes.clone(),
        wallet.clone().scan_unspent(&client, uncapped, 4),
    )
    .await
    .unwrap();
    assert_eq!(coins.len(), 1);
    let (escrows, _) = crate::commands::token::output::capture(
        notes,
        wallet
            .clone()
            .scan_escrows(&client, authority.to_vec(), uncapped, 4),
    )
    .await
    .unwrap();
    assert_eq!(escrows.len(), 1);
    let lines: Vec<String> = std::iter::from_fn(|| lines.try_recv().ok()).collect();
    for expected in [
        "confidential scan: 64 pages, 1 coins in ",
        "confidential scan: 128 pages, 1 coins in ",
        "confidential scan: 64 pages, 1 escrows in ",
        "confidential scan: 128 pages, 1 escrows in ",
    ] {
        assert!(
            lines.iter().any(|line| line.starts_with(expected)),
            "skipped coins: none, but no progress line {expected:?}: {lines:?}"
        );
    }
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// The error of a coin scan, or with `escrows` an escrow scan, begun the
/// hour the node keeps its snapshot ago, whose page 2 finds the snapshot
/// released: as the scan's own call sites report it.
#[cfg(feature = "native-proof")]
async fn outlived_scan(escrows: bool) -> anyhow::Error {
    use quil_lattice_ct::confidential::memo::create_output;
    let wallet = scan_wallet();
    let authority = [22; 897];
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    let escrow = open_escrow(&store, &wallet, &authority, 7);
    let coin = create_output(&wallet.context, wallet.address(), 5)
        .unwrap()
        .output;
    let mut listed = listed(&wallet, vec![(1, coin)], vec![escrow]);
    listed.tail = 1;
    let failing = Failing {
        listed,
        cut_escrow_reads: Default::default(),
        expired_coins: !escrows,
        expired_escrows: escrows,
    };
    let (client, stop, serving) = serve_listed(failing, store, 0).await;
    scans_begin_ago(SCAN_SNAPSHOT_MAX_AGE);
    let error = if escrows {
        wallet
            .scan_escrows(&client, authority.to_vec(), 4, 4)
            .await
            .err()
    } else {
        wallet.scan_unspent(&client, 4, 4).await.err()
    };
    scans_begin_ago(std::time::Duration::ZERO);
    stop.send(()).unwrap();
    serving.await.unwrap();
    error.expect("page 2 finds the snapshot released")
}

/// The node releases a scan's snapshot an hour after the scan starts. A
/// coin scan stopped by that says so from the time it ran: given no time,
/// it would say to run it again, which stops the same way.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_coin_scan_stopped_by_its_snapshot_hour_says_so() {
    let error = outlived_scan(false).await;
    let stopped = error
        .downcast_ref::<ScanStopped>()
        .unwrap_or_else(|| panic!("the coin scan's error is the node's bare one: {error:#}"));
    assert_eq!(
        stopped.outlived(),
        Some(60),
        "the coin scan's error says to run it again: {error}"
    );
    let text = error.to_string();
    assert!(
        text.starts_with("scan stopped at page 2 after 1 coins in 1 pages and 60 min: "),
        "{text}"
    );
}

/// An escrow scan stopped by the node's snapshot hour says so, as a coin
/// scan does: its page errors are the scan's, from the time it ran.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn an_escrow_scan_stopped_by_its_snapshot_hour_says_so() {
    let error = outlived_scan(true).await;
    let stopped = error
        .downcast_ref::<ScanStopped>()
        .unwrap_or_else(|| panic!("the escrow scan's error is the node's bare one: {error:#}"));
    assert_eq!(
        stopped.outlived(),
        Some(60),
        "the escrow scan's error says to run it again: {error}"
    );
    let text = error.to_string();
    assert!(
        text.starts_with("scan stopped at page 2 after 1 escrows in 1 pages and 60 min: "),
        "{text}"
    );
}

/// `token split` and `token merge` name their coins. One the scan left out
/// is refused with the reason and what to do: past the coin limit (a
/// larger --max-coins), a second coin of a spend image, or a memo that
/// does not match; not as an unknown coin.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_named_coin_the_scan_left_out_is_refused_with_why() {
    use quil_execution::token_intrinsic::state;
    use quil_lattice_ct::confidential::memo::create_output;
    let wallet = scan_wallet();
    let output = |amount| {
        create_output(&wallet.context, wallet.address(), amount)
            .unwrap()
            .output
    };
    let address = |frame, output: &Output| {
        state::coin_identity(&wallet.context, frame, output)
            .unwrap()
            .0
    };
    let (twenty, six, three) = (output(20), output(6), output(3));
    let mismatched = mismatched_output(&wallet, 5);
    let (twenty_at, six_at, again_at, three_at, mismatched_at) = (
        address(1, &twenty),
        address(1, &six),
        address(2, &six),
        address(1, &three),
        address(1, &mismatched),
    );
    let listed = listed(
        &wallet,
        vec![
            (1, twenty),
            (1, six.clone()),
            (2, six),
            (1, mismatched),
            (1, three),
        ],
        Vec::new(),
    );
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    let (client, stop, serving) = serve_listed(listed, store, 0).await;
    let refused = |named: Vec<[u8; 32]>| {
        let wallet = wallet.clone();
        let client = client.clone();
        async move {
            let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
            match crate::commands::token::output::capture(
                notes,
                wallet.scan_spendable_named(&client, 4, 2, &named),
            )
            .await
            {
                Ok(coins) => format!("kept {}", coins.len()),
                Err(error) => error.to_string(),
            }
        }
    };
    let coin = |address: &[u8; 32]| format!("coin 0x{}", hex::encode(address));
    let past_limit = refused(vec![twenty_at, three_at]).await;
    assert_eq!(
        past_limit,
        format!(
            "{} is past this scan's coin limit, which keeps the largest coins; run again with a \
             larger --max-coins",
            coin(&three_at)
        ),
        "skipped coins: a named coin past the limit is refused with why"
    );
    assert_eq!(
        refused(vec![again_at]).await,
        format!(
            "{} shares a spend image with another coin of this wallet, which the scan kept and \
             `token coins` lists; only one coin per image can be spent",
            coin(&again_at)
        ),
        "skipped coins: a named second coin of an image is refused with why"
    );
    assert_eq!(
        refused(vec![mismatched_at]).await,
        format!(
            "{} has a memo that opens for this wallet but does not match the coin; it can never \
             be spent",
            coin(&mismatched_at)
        ),
        "skipped coins: a named coin whose memo does not match is refused with why"
    );
    assert_eq!(
        refused(vec![[9; 32]]).await,
        format!("{} is not an unspent coin of this wallet", coin(&[9; 32]))
    );
    assert_eq!(
        refused(vec![twenty_at, twenty_at]).await,
        format!("{} is named twice", coin(&twenty_at))
    );
    assert_eq!(refused(vec![twenty_at, six_at]).await, "kept 2");
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// Past twice its limit a scan trims what it holds to the limit and goes
/// on; a coin of a kept coin's spend image met after the trim must still
/// find that coin. Here coins of 1, 9, 8 and 2 come first, in address
/// order, and the trim at four keeps the 9 and the 8; then a 20 on the
/// 9's image replaces the 9. A spend scan's witnesses then cover the 20.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_coin_scan_trimmed_mid_scan_keeps_one_coin_per_image() {
    use quil_execution::token_intrinsic::state;
    use quil_lattice_ct::confidential::memo::{create_output, create_output_with_nonce};
    let wallet = scan_wallet();
    let outputs = [
        create_output(&wallet.context, wallet.address(), 1),
        create_output_with_nonce(&wallet.context, wallet.address(), 9, &[5; 32]),
        create_output(&wallet.context, wallet.address(), 8),
        create_output(&wallet.context, wallet.address(), 2),
        create_output_with_nonce(&wallet.context, wallet.address(), 20, &[5; 32]),
    ]
    .map(|created| created.unwrap().output);
    // A coin's address hashes its frame: give each the frame placing it
    // lowest above the one before, so the scan meets them in this order.
    let mut previous = [0; 32];
    let placed: Vec<(u64, Output, [u8; 32])> = outputs
        .into_iter()
        .map(|output| {
            let (address, frame) = (1..=64)
                .map(|frame| {
                    (
                        state::coin_identity(&wallet.context, frame, &output)
                            .unwrap()
                            .0,
                        frame,
                    )
                })
                .filter(|(address, _)| *address > previous)
                .min()
                .expect("a frame places the coin after the one before");
            previous = address;
            (frame, output, address)
        })
        .collect();
    let replacing = placed[4].2;
    let listed = listed(
        &wallet,
        placed
            .iter()
            .map(|(frame, output, _)| (*frame, output.clone()))
            .collect(),
        Vec::new(),
    );
    assert_eq!(
        listed.coins.iter().map(|coin| coin.0).collect::<Vec<_>>(),
        placed.iter().map(|coin| coin.2).collect::<Vec<_>>()
    );
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    let (client, stop, serving) = serve_listed(listed, store, 0).await;
    let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
    let kept = crate::commands::token::output::capture(
        notes,
        wallet
            .clone()
            .scan_unspent_or_rootless(&client, 4, 2, &mut ScanReport::default()),
    )
    .await
    .expect("skipped coins: a scan past its coin limit goes on")
    .unwrap();
    let mut amounts: Vec<u128> = kept.iter().map(|coin| *coin.amount).collect();
    amounts.sort();
    assert_eq!(
        amounts,
        [8, 20],
        "skipped coins: after a trim the scan keeps one coin per spend image, the largest"
    );
    let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
    let spendable = crate::commands::token::output::capture(
        notes,
        wallet.clone().scan_spendable(&client, 4, 2),
    )
    .await
    .unwrap();
    assert!(spendable.iter().any(|coin| coin.address == replacing));
    let witnessed = wallet
        .prepared
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|scan| scan.owned.contains_key(&replacing));
    assert!(
        witnessed,
        "skipped coins: the spend scan keeps the witness of a coin that replaced another of its \
         image"
    );
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// A submitted operation's decision is read from the node's GLOBAL state at
/// the commit's record for it: committed or rejected with its frame, and
/// absent while undecided.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn the_global_commit_decision_is_read_over_rpc() {
    use quil_execution::token_intrinsic::global_commit::{
        decision_address, encode_decision_record, Decision,
    };
    use quil_types::store::HypergraphStore;
    let application = quil_execution::domains::QUIL_TOKEN;
    let global = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS;
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    let txn = store.new_transaction(false).unwrap();
    let decided = [
        ([1u8; 32], Decision::Committed { frame: 965_690 }),
        (
            [2u8; 32],
            Decision::Rejected {
                frame: 965_691,
                reason: "already consumed".into(),
            },
        ),
    ];
    for (operation, decision) in &decided {
        let record = decision_address(&application, operation).unwrap();
        let mut vertex = global.to_vec();
        vertex.extend_from_slice(&record);
        let shard = quil_hypergraph::addressing::shard_key_for_location(
            &quil_hypergraph::addressing::Location {
                app_address: global,
                data_address: record,
            },
        );
        store
            .save_vertex_underlying(
                txn.as_ref(),
                "vertex",
                "adds",
                &shard,
                &vertex,
                &encode_decision_record(decision).unwrap(),
            )
            .unwrap();
    }
    let server = quil_rpc::node_service::NodeRpcServer::new().with_hypergraph_store(store);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, serving) = serve_node(listener, server);
    let client = quil_types::proto::node::node_service_client::NodeServiceClient::new(
        tonic::transport::Endpoint::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap(),
    );
    for (operation, decision) in &decided {
        assert_eq!(
            inclusion::read_decision(&client, &application, operation)
                .await
                .unwrap()
                .as_ref(),
            Some(decision)
        );
    }
    assert_eq!(
        inclusion::read_decision(&client, &application, &[3; 32])
            .await
            .unwrap(),
        None,
        "undecided"
    );
    assert_eq!(
        inclusion::read_decision(&client, &[9; 32], &[1; 32])
            .await
            .unwrap(),
        None,
        "decisions are per application"
    );
    stop.send(()).unwrap();
    serving.await.unwrap();
}

#[tokio::test]
async fn wallet_fetches_content_bound_escrow_over_rpc() {
    use quil_execution::token_intrinsic::escrow::StoredEscrow;
    use quil_lattice_ct::confidential::{
        memo::create_escrow_recovery, pending_claim::EscrowPolicy,
    };
    use quil_types::store::*;
    struct EscrowPages {
        network: [u8; 32],
        address: [u8; 32],
        blob: Vec<u8>,
    }
    impl CoinWitnessProvider for EscrowPages {
        fn escrow_page(
            &self,
            _: &[u8; 32],
            id: Option<&[u8; 32]>,
            after: Option<&[u8; 32]>,
        ) -> quil_types::error::Result<Option<EscrowPageData>> {
            assert!(id.is_none() || id == Some(&[33; 32]));
            // Begin with an empty metadata page to exercise continuation.
            Ok(Some(EscrowPageData {
                network: self.network,
                snapshot_id: [33; 32],
                escrows: if after.is_some() {
                    vec![(self.address, self.blob.clone())]
                } else {
                    vec![]
                },
                cursor: Some(if after.is_some() {
                    self.address
                } else {
                    [0; 32]
                }),
                has_more: after.is_none(),
            }))
        }
    }
    let keys = sntrup761::Sntrup761KeyPair::generate();
    let wallet = RecipientWallet::from_keys(
        &[21; 32],
        &quil_execution::domains::QUIL_TOKEN,
        &keys.public,
        Zeroizing::new(keys.secret),
    )
    .unwrap();
    let recovery =
        create_escrow_recovery(&wallet.context, wallet.address(), wallet.address(), 7).unwrap();
    // Record lookup fixture; no claim signature or amount proof is admitted.
    let escrow = StoredEscrow {
        frame_number: 1,
        output: Output {
            commitment: recovery.commitment,
            owner: recovery.recipient.owner,
            memo: recovery.recipient.ciphertext,
        },
        policy: EscrowPolicy {
            recipient: [22; 897],
            refund: [23; 897],
            refund_after_global_frame: 100,
        },
        refund_recovery: recovery.refund,
    };
    let (address, blob) = escrow.encode(&wallet.context).unwrap();
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    let shard = quil_hypergraph::addressing::shard_key_for_location(
        &quil_hypergraph::addressing::Location {
            app_address: wallet.application,
            data_address: address,
        },
    );
    let mut vertex = wallet.application.to_vec();
    vertex.extend_from_slice(&address);
    let txn = store.new_transaction(false).unwrap();
    store
        .save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &vertex, &blob)
        .unwrap();
    use quil_execution::token_intrinsic::global_commit;
    let global = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS;
    let global_shard = quil_types::store::ShardKey {
        l1: quil_hypergraph::addressing::get_bloom_filter_indices(&global, 256, 3),
        l2: global,
    };
    // The escrow's creation committed, unconsumed.
    let mut open_vertex = global.to_vec();
    open_vertex
        .extend_from_slice(&global_commit::escrow_address(&wallet.application, &address).unwrap());
    store
        .save_vertex_underlying(
            txn.as_ref(),
            "vertex",
            "adds",
            &global_shard,
            &open_vertex,
            &global_commit::encode_escrow_record(&[5; 32], 100, false).unwrap(),
        )
        .unwrap();
    let wallet = Arc::new(wallet);
    let provider = Arc::new(EscrowPages {
        network: wallet.network,
        address,
        blob: blob.clone(),
    });
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_hypergraph_store(store.clone())
        .with_coin_witness_provider(provider);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let incoming = futures::stream::unfold(listener, |listener| async {
        let result = listener.accept().await.map(|(socket, _)| socket);
        Some((result, listener))
    });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async {
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
    let channel = tonic::transport::Endpoint::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let client = quil_types::proto::node::node_service_client::NodeServiceClient::new(channel);
    let recipient = wallet
        .clone()
        .scan_escrows(&client, vec![22; 897], 2, 1)
        .await
        .unwrap()
        .0;
    assert_eq!(
        (
            recipient[0].0,
            *recipient[0].1,
            recipient[0].2,
            recipient[0].3
        ),
        (address, 7, false, 100)
    );
    let refund = wallet
        .clone()
        .scan_escrows(&client, vec![23; 897], 2, 1)
        .await
        .unwrap()
        .0;
    assert_eq!((refund[0].0, *refund[0].1, refund[0].2), (address, 7, true));
    assert!(wallet
        .clone()
        .scan_escrows(&client, vec![24; 897], 2, 1)
        .await
        .unwrap()
        .0
        .is_empty());
    // One page carries the empty first page and the escrow behind it: the
    // node gathers both into the page of up to 64 the wallet asks for.
    let one_page = wallet
        .clone()
        .scan_escrows(&client, vec![22; 897], 1, 1)
        .await
        .unwrap()
        .0;
    assert_eq!(one_page.len(), 1);
    // Consumption is the global commit's: the GLOBAL escrow record flips.
    let mut consumed_vertex = global.to_vec();
    consumed_vertex
        .extend_from_slice(&global_commit::escrow_address(&wallet.application, &address).unwrap());
    store
        .save_vertex_underlying(
            txn.as_ref(),
            "vertex",
            "adds",
            &global_shard,
            &consumed_vertex,
            &global_commit::encode_escrow_record(&[5; 32], 100, true).unwrap(),
        )
        .unwrap();
    assert!(wallet
        .clone()
        .scan_escrows(&client, vec![22; 897], 2, 1)
        .await
        .unwrap()
        .0
        .is_empty());
    assert!(wallet
        .clone()
        .scan_escrows(&client, vec![23; 897], 2, 1)
        .await
        .unwrap()
        .0
        .is_empty());
    // A malformed record fails the scan rather than reading as open.
    store
        .save_vertex_underlying(
            txn.as_ref(),
            "vertex",
            "adds",
            &global_shard,
            &consumed_vertex,
            &[1, 2, 3],
        )
        .unwrap();
    assert!(wallet
        .clone()
        .scan_escrows(&client, vec![22; 897], 2, 1)
        .await
        .is_err());
    let image = [24; IDENTITY_BYTES];
    assert!(wallet.is_unspent_hint(&client, &image).await.unwrap());
    let marker = quil_execution::token_intrinsic::spent::marker_address(
        &wallet.network,
        &wallet.application,
        &image,
    )
    .unwrap();
    // A local marker is not a commit.
    let mut local_marker = wallet.application.to_vec();
    local_marker.extend_from_slice(&marker);
    store
        .save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &local_marker, &[])
        .unwrap();
    assert!(wallet.is_unspent_hint(&client, &image).await.unwrap());
    let mut marker_vertex = global.to_vec();
    marker_vertex
        .extend_from_slice(&global_commit::consumed_address(&wallet.application, &marker).unwrap());
    store
        .save_vertex_underlying(
            txn.as_ref(),
            "vertex",
            "adds",
            &global_shard,
            &marker_vertex,
            &[],
        )
        .unwrap();
    assert!(!wallet.is_unspent_hint(&client, &image).await.unwrap());
    store
        .save_vertex_underlying(
            txn.as_ref(),
            "vertex",
            "adds",
            &global_shard,
            &marker_vertex,
            &[1, 2, 3],
        )
        .unwrap();
    assert!(!wallet.is_unspent_hint(&client, &image).await.unwrap());
    assert_eq!(wallet.fetch_escrow(&client, address).await.unwrap(), escrow);
    assert!(wallet.fetch_escrow(&client, [0; 32]).await.is_err());
    let mut altered = blob.clone();
    altered.push(0);
    store
        .save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &vertex, &altered)
        .unwrap();
    assert!(wallet.fetch_escrow(&client, address).await.is_err());
    let oversized = vec![0; quil_execution::token_intrinsic::escrow::MAX_ESCROW_BLOB_BYTES + 2048];
    store
        .save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &vertex, &oversized)
        .unwrap();
    assert!(wallet.fetch_escrow(&client, address).await.is_err());
    // A failed response cannot poison a later valid lookup.
    store
        .save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &vertex, &blob)
        .unwrap();
    assert_eq!(wallet.fetch_escrow(&client, address).await.unwrap(), escrow);
    stop.send(()).unwrap();
    serving.await.unwrap();
}

#[cfg(feature = "native-proof")]
#[tokio::test]
async fn wallet_submits_over_authenticated_rpc() {
    use quil_lattice_ct::confidential::{
        memo::create_output,
        mint::{Mint, MintStatement, RewardClaim},
        mint_claim::MintClaim,
    };
    let keys = sntrup761::Sntrup761KeyPair::generate();
    let wallet = RecipientWallet::from_keys(
        &[1; 32],
        &quil_execution::domains::QUIL_TOKEN,
        &keys.public,
        Zeroizing::new(keys.secret),
    )
    .unwrap();
    let output = create_output(&wallet.context, wallet.address(), 7)
        .unwrap()
        .output;
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    let mint = Mint {
        statement: MintStatement {
            network: wallet.network,
            application: wallet.application,
            cited_frame: 1,
            reward_root: [3; 32],
            fee: 1,
            outputs: vec![output.clone()],
            claims: vec![RewardClaim {
                owner: [4; 32],
                value: 8,
                public_key: [0; 897],
                forest_proof: vec![1],
            }],
        },
        signatures: vec![[0; 666]],
        proof,
    }
    .encode()
    .unwrap();
    let claim = MintClaim {
        network: wallet.network,
        application: wallet.application,
        cited_global_frame: 3,
        global_root: [5; 32],
        receipt: [6; 32],
        fee: 1,
        outputs: vec![output],
        forest_proof: vec![1],
    }
    .encode()
    .unwrap();

    let directory = tempfile::tempdir().unwrap();
    let km = quil_keys::FileKeyManager::new(
        directory.path().join("keys.yml"),
        &hex::encode([7; 32]),
        "q-prover-key".into(),
        Box::new(quil_crypto::FalconKeyConstructor),
    )
    .unwrap();
    let seed = [8; 57];
    let public = quil_crypto::Ed448Signer::derive_public(&seed).unwrap();
    let mut peer = seed.to_vec();
    peer.extend_from_slice(&public);
    km.set_peer_priv_key_hex(&hex::encode(peer));

    let received = Arc::new(Mutex::new(Vec::new()));
    let captured = received.clone();
    let server = quil_rpc::node_service::NodeRpcServer::new().with_send_handler_fn(Arc::new(
        move |domain, payload, authentication| {
            let public = public.clone();
            let captured = captured.clone();
            Box::pin(async move {
                let mut signed = crate::send::node_auth_domain(&domain);
                signed.extend_from_slice(&payload);
                if !quil_crypto::ed448_verify(&public, &signed, &authentication) {
                    return Err("invalid test authentication".into());
                }
                let bundle =
                    quil_execution::message_envelope::CanonicalMessageBundle::from_canonical_bytes(
                        &payload,
                    )
                    .map_err(|e| e.to_string())?;
                if bundle.requests.len() != 1 {
                    return Err("expected one operation".into());
                }
                let request = bundle.requests[0].as_ref().ok_or("missing operation")?;
                let mut received = captured.lock().unwrap();
                if received.len() >= 2 {
                    return Err("test delivery rejected".into());
                }
                received.push((domain, request.inner_bytes.clone()));
                Ok(())
            })
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let incoming = futures::stream::unfold(listener, |listener| async {
        let result = listener.accept().await.map(|(socket, _)| socket);
        Some((result, listener))
    });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async {
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
    let channel = tonic::transport::Endpoint::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = quil_types::proto::node::node_service_client::NodeServiceClient::new(channel);
    let checked = |bytes: &Vec<u8>| RootChecked::citing_none(&wallet, bytes.clone()).unwrap();
    wallet
        .submit(&mut client, &km, checked(&mint))
        .await
        .unwrap();
    wallet
        .submit(&mut client, &km, checked(&claim))
        .await
        .unwrap();
    assert!(wallet
        .submit(&mut client, &km, checked(&mint))
        .await
        .is_err());
    assert_eq!(
        *received.lock().unwrap(),
        vec![
            (quil_execution::domains::GLOBAL.to_vec(), mint),
            (wallet.application.to_vec(), claim)
        ]
    );
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// A loopback node serving only fee quotes from `snapshot`; returns its gRPC
/// multiaddr, its quote count and its shutdown.
#[cfg(feature = "native-proof")]
async fn fee_quote_server(
    snapshot: quil_rpc::node_service::TokenFeeSnapshot,
) -> (
    String,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = calls.clone();
    let server = quil_rpc::node_service::NodeRpcServer::new().with_token_fee_provider(Arc::new(
        move |application, _global_venue| {
            assert_eq!(application, quil_execution::domains::QUIL_TOKEN);
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(snapshot.clone())
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let multiaddr = format!(
        "/ip4/127.0.0.1/tcp/{}",
        listener.local_addr().unwrap().port()
    );
    let incoming = futures::stream::unfold(listener, |listener| async {
        let result = listener.accept().await.map(|(socket, _)| socket);
        Some((result, listener))
    });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async {
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
    (multiaddr, calls, stop, serving)
}

#[cfg(feature = "native-proof")]
#[tokio::test]
async fn automatic_quil_fee_is_quoted_by_the_configured_node_and_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let key_manager = Arc::new(
        quil_keys::FileKeyManager::new(
            directory.path().join("keys.yml"),
            &hex::encode([9; 32]),
            "q-prover-key".into(),
            Box::new(quil_crypto::FalconKeyConstructor),
        )
        .unwrap(),
    );
    let node_config = quil_config::Config::default();
    let network = quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(
        node_config.p2p.network,
    )
    .network;
    // Both quotes are self-consistent global prices at vote one; only the
    // world size differs. The read node's would charge thousands of QUIL.
    let snapshot = |world_state_bytes| quil_rpc::node_service::TokenFeeSnapshot {
        network,
        observed_frame: 42,
        global_execution: true,
        difficulty: 50_000,
        world_state_bytes,
        fee_multiplier_vote: 1,
    };
    let (configured, configured_calls, stop_configured, configured_serving) =
        fee_quote_server(snapshot(1 << 40)).await;
    let (read, read_calls, stop_read, read_serving) = fee_quote_server(snapshot(1 << 24)).await;
    let mut tc = TokenCtx {
        node_config,
        config_dir: directory.path().to_path_buf(),
        key_manager: key_manager.clone(),
        connect_opts: crate::rpc::ConnectOpts {
            listen_grpc_multiaddr: read.clone(),
            ..Default::default()
        },
        submit_opts: crate::rpc::ConnectOpts {
            listen_grpc_multiaddr: configured,
            ..Default::default()
        },
        submit_key_manager: key_manager,
        submit_config_dir: directory.path().to_path_buf(),
        submit_identity: Default::default(),
        peer_id_bytes: Vec::new(),
        max_fee: crate::commands::token::DEFAULT_MAX_AUTOMATIC_FEE,
        read_flags: Vec::new(),
    };
    // 4096 bytes in a 1 TiB world cost one unit per byte, plus the headroom.
    assert_eq!(
        quoted_quil_fee_for_cost(&tc, None, 4096, false)
            .await
            .unwrap(),
        with_fee_headroom(4096).unwrap()
    );
    assert_eq!(
        (
            configured_calls.load(std::sync::atomic::Ordering::SeqCst),
            read_calls.load(std::sync::atomic::Ordering::SeqCst)
        ),
        (1, 0)
    );
    // An inflated quote from the node that takes the submission is refused
    // under the default limit, and paid only once the operator raises it.
    tc.submit_opts.listen_grpc_multiaddr = read;
    let error = quoted_quil_fee_for_cost(&tc, None, 4096, false)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("automatic fee limit"), "{error}");
    tc.max_fee = u128::MAX;
    assert!(
        quoted_quil_fee_for_cost(&tc, None, 4096, false)
            .await
            .unwrap()
            > crate::commands::token::DEFAULT_MAX_AUTOMATIC_FEE
    );
    // An explicit fee is the operator's own choice and is never quoted.
    tc.max_fee = 0;
    assert_eq!(
        quoted_quil_fee_for_cost(&tc, Some(7), 4096, false)
            .await
            .unwrap(),
        7
    );
    assert_eq!(read_calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    stop_configured.send(()).unwrap();
    stop_read.send(()).unwrap();
    configured_serving.await.unwrap();
    read_serving.await.unwrap();
}

/// A/B reproducer: a wallet scan lists every confidential coin the application
/// ever placed, spent or not (a spend reveals a key image, never which coin
/// it spent), so a wallet must find its own coin behind all of them within
/// its page budget. At eight coins a page the default budget (2,048 pages)
/// reached 16,384 coins, and every default `token balance` and `token coins`
/// failed once the application held one more. A wallet checks and
/// trial-decrypts every coin it scans, about 0.1 s each in the test profile,
/// so the test keeps the wallet's own page size, which is what changed, and
/// scales the budget down to 16 pages, with one coin more behind them than
/// they reach at eight coins a page.
#[tokio::test]
async fn a_default_wallet_scan_finds_its_coin_behind_the_old_page_budget() {
    use clap::Parser;
    use quil_execution::token_intrinsic::{coin_blocks, state};
    use quil_lattice_ct::confidential::{coin_tree::CoinRecord, memo::create_output};
    use quil_types::store::*;

    /// The application's coins in address order, eight a page as a node's
    /// store answers them.
    struct Coins {
        network: [u8; 32],
        root: Vec<u8>,
        /// `(address, frame, position, the wallet's own)`.
        coins: Vec<([u8; 32], u64, u64, bool)>,
        /// `(owner, commitment, memo)` of the others' output, then the
        /// wallet's.
        outputs: [(Vec<u8>, Vec<u8>, Vec<u8>); 2],
    }
    impl CoinWitnessProvider for Coins {
        fn coin_page(
            &self,
            _: &[u8; 32],
            _: Option<&[u8; 32]>,
            after: Option<&[u8; 32]>,
        ) -> quil_types::error::Result<Option<CoinPageData>> {
            let start = self
                .coins
                .partition_point(|(address, ..)| after.is_some_and(|after| address <= after));
            let page = &self.coins[start..self.coins.len().min(start + 8)];
            Ok(Some(CoinPageData {
                network: self.network,
                snapshot_id: [33; 32],
                root_record: self.root.clone(),
                coins: page
                    .iter()
                    .map(|&(address, frame_number, position, mine)| {
                        let (owner, commitment, memo) = &self.outputs[usize::from(mine)];
                        CoinData {
                            address,
                            frame_number,
                            position,
                            owner: owner.clone(),
                            commitment: commitment.clone(),
                            memo: memo.clone(),
                        }
                    })
                    .collect(),
                cursor: page.last().map(|coin| coin.0).or(after.copied()),
                has_more: start + page.len() < self.coins.len(),
            }))
        }
    }

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        token: super::super::TokenArgs,
    }
    let defaults = Cli::try_parse_from(["qclient", "balance"]).unwrap().token;
    // One coin more than pages of eight reach within the budget.
    let pages = 16;
    let others = pages * 8;

    let network = [31; 32];
    let application = quil_execution::domains::QUIL_TOKEN;
    let make_wallet = || {
        let keys = sntrup761::Sntrup761KeyPair::generate();
        Arc::new(
            RecipientWallet::from_keys(
                &network,
                &application,
                &keys.public,
                Zeroizing::new(keys.secret),
            )
            .unwrap(),
        )
    };
    let wallet = make_wallet();
    let other = make_wallet();
    let mine = create_output(&wallet.context, wallet.address(), 5)
        .unwrap()
        .output;
    let theirs = create_output(&wallet.context, other.address(), 7)
        .unwrap()
        .output;
    let identity = |output: &Output, frame: u64| {
        state::coin_identity(&wallet.context, frame, output)
            .unwrap()
            .0
    };
    // The wallet's coin sorts after every other coin, so the scan reaches it
    // last: it takes the highest address of a few frames, and the others are
    // drawn below it. (An address encodes a field element, so its top byte
    // never reaches 0xff.)
    let (my_address, my_frame) = (1..=16)
        .map(|frame| (identity(&mine, frame), frame))
        .max()
        .unwrap();
    let mut placed = vec![(my_address, my_frame, true)];
    let mut frame = 0;
    while placed.len() <= others {
        frame += 1;
        let address = identity(&theirs, frame);
        if address < my_address {
            placed.push((address, frame, false));
        }
    }
    placed.sort();
    // Each coin sits in the block its address selects, at that block's next
    // free index, as the wallet checks.
    let width = coin_blocks::INITIAL_BLOCK_BITS;
    let mut next_local = std::collections::BTreeMap::<u64, u64>::new();
    let coins: Vec<_> = placed
        .into_iter()
        .map(|(address, frame, mine)| {
            let block = coin_blocks::block_for_address(width, &address).unwrap();
            let local = next_local.entry(block).or_default();
            let position = coin_blocks::position(width, block, *local).unwrap();
            *local += 1;
            (address, frame, position, mine)
        })
        .collect();
    let my_position = coins.last().unwrap().2;
    let tree = quil_lattice_ct::confidential::sharded_tree::ShardedCoinTree::build(
        &wallet.context,
        quil_lattice_ct::confidential::sharded_tree::Shape {
            shard_bits: coin_blocks::BLOCK_INDEX_BITS,
            subtree_bits: coin_blocks::SUBTREE_BITS,
        },
        &[CoinRecord {
            address: my_address,
            owner: mine.owner,
            commitment: mine.commitment.clone(),
            position: my_position,
        }],
    )
    .unwrap();
    let root = tree
        .root_at_depth(tree.current_depth())
        .unwrap()
        .encode()
        .unwrap()
        .to_vec();
    let bytes = |output: &Output| {
        (
            output.owner.to_vec(),
            output.commitment.to_bytes().to_vec(),
            output.memo.to_vec(),
        )
    };
    let provider = Arc::new(Coins {
        network,
        root,
        coins,
        outputs: [bytes(&theirs), bytes(&mine)],
    });
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_hypergraph_store(Arc::new(quil_hypergraph::testing::MemStore::new()))
        .with_coin_witness_provider(provider);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let incoming = futures::stream::unfold(listener, |listener| async {
        let result = listener.accept().await.map(|(socket, _)| socket);
        Some((result, listener))
    });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async {
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
    let channel = tonic::transport::Endpoint::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let client = quil_types::proto::node::node_service_client::NodeServiceClient::new(channel);
    let unspent = wallet
        .clone()
        .scan_unspent(&client, pages, defaults.max_coins)
        .await
        .unwrap_or_else(|error| {
            panic!("a scan of {pages} pages must reach the wallet's coin behind {others}: {error}")
        });
    assert_eq!(unspent.len(), 1);
    assert_eq!(unspent[0].address, my_address);
    assert_eq!(*unspent[0].amount, 5);
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// Serve `server` on `listener` until the returned sender fires.
#[cfg(feature = "native-proof")]
fn serve_node(
    listener: tokio::net::TcpListener,
    server: quil_rpc::node_service::NodeRpcServer,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let incoming = futures::stream::unfold(listener, |listener| async {
        let result = listener.accept().await.map(|(socket, _)| socket);
        Some((result, listener))
    });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async {
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
    (stop, serving)
}

#[cfg(feature = "native-proof")]
async fn bind_loopback() -> (tokio::net::TcpListener, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let multiaddr = format!(
        "/ip4/127.0.0.1/tcp/{}",
        listener.local_addr().unwrap().port()
    );
    (listener, multiaddr)
}

/// Parse and dispatch a token command against a loaded context.
#[cfg(feature = "native-proof")]
async fn run_token_command(tc: &TokenCtx, arguments: &[&str]) -> anyhow::Result<()> {
    use clap::Parser;
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        token: super::super::TokenArgs,
    }
    // Boxed: the command's future outgrows a test thread's stack.
    Box::pin(super::super::run_with_context(
        tc,
        &Cli::try_parse_from(arguments)?.token,
    ))
    .await
}

/// A reward mint from a config other than the running node's is refused
/// before its fee quote and proof, naming both peers and the fix; nothing is
/// saved or sent. Through the node's own config the check passes and the
/// mint goes on to its fee quote.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_mint_from_another_config_fails_before_proving() {
    use super::super::{short_peer, test_nodes};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let directory = tempfile::tempdir().unwrap();
    let (listener, listen) = bind_loopback().await;
    let node = test_nodes::write(&directory.path().join("node"), 41, &listen);
    // A dormant prover's config naming the same listener, as a copy does.
    let dormant = test_nodes::write(&directory.path().join("dormant"), 42, &listen);
    let calls = Arc::new(AtomicUsize::new(0));
    let (quoted, sent) = (calls.clone(), calls.clone());
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_peer_id(node.peer_id.clone())
        .with_token_fee_provider(Arc::new(move |_, _| {
            quoted.fetch_add(1, Ordering::SeqCst);
            Err(quil_types::error::QuilError::ExecutionUnavailable(
                "test node has no fee snapshot".into(),
            ))
        }))
        .with_send_handler_fn(Arc::new(move |_, _, _| {
            sent.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err("test node takes no submissions".into()) })
        }));
    let (stop, serving) = serve_node(listener, server);

    let tc = TokenCtx::from_context(
        &test_nodes::context(false),
        &test_nodes::common(&dormant.dir, None, false),
    )
    .unwrap();
    let error = run_token_command(&tc, &["token", "mint"])
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.starts_with(&format!(
            "the node at {listen} is peer {}, but submissions would be signed by {} (peer {})",
            short_peer(&node.peer_id),
            dormant.dir.display(),
            short_peer(&dormant.peer_id)
        )),
        "{error}"
    );
    assert!(error.ends_with("pass --submit-config <DIR> with the running node's config directory"));
    assert_eq!(calls.load(Ordering::SeqCst), 0, "a quote or send was made");
    let saved: Vec<_> = std::fs::read_dir(&dormant.dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("mint-"))
        .collect();
    assert!(saved.is_empty(), "a mint was saved: {saved:?}");

    // Through the running node's config, the mint passes the check and asks
    // that node for its fee quote.
    let tc = TokenCtx::from_context(
        &test_nodes::context(false),
        &test_nodes::common(&dormant.dir, Some(&node.dir), false),
    )
    .unwrap();
    tc.check_submit_identity().await.unwrap();
    let error = run_token_command(&tc, &["token", "mint"])
        .await
        .unwrap_err()
        .to_string();
    assert!(error.starts_with("fee estimate unavailable"), "{error}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    stop.send(()).unwrap();
    serving.await.unwrap();

    // A node that reports no peer ID is not second-guessed.
    let (listener, _) = bind_loopback().await;
    let mut tc = TokenCtx::from_context(
        &test_nodes::context(false),
        &test_nodes::common(&dormant.dir, None, false),
    )
    .unwrap();
    tc.submit_opts.listen_grpc_multiaddr = format!(
        "/ip4/127.0.0.1/tcp/{}",
        listener.local_addr().unwrap().port()
    );
    let (stop, serving) = serve_node(listener, quil_rpc::node_service::NodeRpcServer::new());
    tc.check_submit_identity().await.unwrap();
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// With `--submit-config`, the Send authentication is signed with the running
/// node's peer key, which that node's check (Ed448 over `NODE_AUTHENTICATION
/// ‖ domain ‖ payload`) accepts, while the reward mint inside is signed with
/// the `--config` prover key. Signed with the `--config` peer key, the same
/// submission is refused.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn submit_config_signs_the_send_and_the_wallet_signs_the_mint() {
    use super::super::test_nodes;
    use quil_lattice_ct::confidential::mint::{Mint, RewardClaim};
    use quil_types::crypto::Signer;
    let directory = tempfile::tempdir().unwrap();
    let (listener, listen) = bind_loopback().await;
    let node = test_nodes::write(&directory.path().join("node"), 51, &listen);
    let dormant = test_nodes::write(
        &directory.path().join("dormant"),
        52,
        "/ip4/127.0.0.1/tcp/9",
    );
    let received = Arc::new(Mutex::new(Vec::new()));
    let captured = received.clone();
    let node_public = node.ed448_public.clone();
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_peer_id(node.peer_id.clone())
        .with_send_handler_fn(Arc::new(move |domain, payload, authentication| {
            let public = node_public.clone();
            let captured = captured.clone();
            Box::pin(async move {
                // The node's Send check, against its own peer key.
                let mut digest = b"NODE_AUTHENTICATION".to_vec();
                digest.extend_from_slice(&domain);
                digest.extend_from_slice(&payload);
                if !quil_crypto::ed448_verify(&public, &digest, &authentication) {
                    return Err("authentication failed: InvalidSignature".into());
                }
                let bundle =
                    quil_execution::message_envelope::CanonicalMessageBundle::from_canonical_bytes(
                        &payload,
                    )
                    .map_err(|e| e.to_string())?;
                let request = bundle
                    .requests
                    .into_iter()
                    .flatten()
                    .next()
                    .ok_or("missing operation")?;
                captured.lock().unwrap().push((domain, request.inner_bytes));
                Ok(())
            })
        }));
    let (stop, serving) = serve_node(listener, server);

    let tc = TokenCtx::from_context(
        &test_nodes::context(false),
        &test_nodes::common(&dormant.dir, Some(&node.dir), false),
    )
    .unwrap();
    let network =
        quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet =
        RecipientWallet::load(&tc, &network, &quil_execution::domains::QUIL_TOKEN).unwrap();
    // The reward claimant is the --config prover key, as `token mint` signs it.
    let signer = falcon_signer(&tc).unwrap();
    assert_eq!(signer.public_key(), dormant.falcon_public.as_slice());
    let claim = RewardClaim {
        owner: quil_crypto::poseidon::hash_bytes_to_32(&dormant.falcon_public).unwrap(),
        value: 8,
        public_key: dormant.falcon_public.as_slice().try_into().unwrap(),
        forest_proof: vec![1],
    };
    let signer: std::sync::Arc<dyn Signer> = signer;
    let signers = vec![signer];
    let (statement, signatures, _) = wallet
        .prepare_mint(
            1,
            [3; 32],
            &[claim],
            &signers,
            &[(wallet.address().clone(), 7)],
            1,
            1,
            1,
        )
        .unwrap();
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    let mint = Mint {
        statement,
        signatures,
        proof,
    }
    .encode()
    .unwrap();

    // Signed with the dormant config's own peer key, the node refuses it.
    let refused = wallet
        .submit(
            &mut tc.connect_submit().await.unwrap(),
            &tc.key_manager,
            RootChecked::citing_none(&wallet, mint.clone()).unwrap(),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("authentication failed"), "{refused}");
    let checked = RootChecked::citing_none(&wallet, mint.clone()).unwrap();
    deliver_operation(&tc, &wallet, checked).await.unwrap();
    let received = received.lock().unwrap().clone();
    assert_eq!(
        received,
        vec![(quil_execution::domains::GLOBAL.to_vec(), mint)]
    );
    let delivered = Mint::decode(
        &received[0].1,
        &network,
        &quil_execution::domains::QUIL_TOKEN,
    )
    .unwrap();
    assert!(quil_crypto::falcon_verify(
        &dormant.falcon_public,
        &delivered.signatures[0],
        &delivered.statement.context_bytes().unwrap(),
        &wallet.context
    ));
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// The paced run's submit: `token shield-all`'s batch is delivered, kept for
/// `--wait` and routed to its source's shard; the node manager's is delivered
/// and kept for nothing.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_paced_batch_is_kept_for_its_wait_with_its_route() {
    use super::super::shield_pacing::ShieldIo;
    use super::super::test_nodes;
    use quil_lattice_ct::confidential::shield::{BatchShield, ShieldSource};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let directory = tempfile::tempdir().unwrap();
    let (listener, listen) = bind_loopback().await;
    let node = test_nodes::write(&directory.path().join("node"), 61, &listen);
    let delivered = Arc::new(AtomicUsize::new(0));
    let sent = delivered.clone();
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_peer_id(node.peer_id.clone())
        .with_send_handler_fn(Arc::new(move |_, _, _| {
            sent.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }));
    let (stop, serving) = serve_node(listener, server);
    let tc = TokenCtx::from_context(
        &test_nodes::context(false),
        &test_nodes::common(&node.dir, None, false),
    )
    .unwrap();
    let network =
        quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = Arc::new(
        RecipientWallet::load(&tc, &network, &quil_execution::domains::QUIL_TOKEN).unwrap(),
    );
    let owner = legacy_owner_signer(&tc).unwrap();
    let sources = vec![ShieldSource {
        address: [0x80; 32],
        amount: 10,
    }];
    let (statement, signature, _) = wallet
        .prepare_batch_shield(
            sources.clone(),
            owner.as_ref(),
            &[(wallet.address().clone(), 8)],
            2,
            1,
        )
        .unwrap();
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    let bytes = BatchShield {
        statement,
        signature,
        proof,
    }
    .encode()
    .unwrap();
    let mut record = super::super::action_log::ShieldRecorder::new(None, "cli");
    let mut sink = |_: ShieldReport<'_>| {};
    let payee = Box::new(shield_recipient(&wallet, None).unwrap());
    let mut io = ShieldAllIo {
        tc: &tc,
        payee,
        wallet,
        owner,
        client: tc.connect().await.unwrap(),
        batches: vec![sources],
        shards: vec!["1".into()],
        filters: vec![None],
        paths: vec![vec![false], vec![true]],
        announce: Some(true),
        submissions: Vec::new(),
        health: Err("not read by this test".into()),
        proved: Some((10, 2)),
        started: std::time::Instant::now(),
        record: &mut record,
        stop: None,
        sink: &mut sink,
    };
    io.submit(0, bytes.clone()).await.unwrap();
    assert_eq!(delivered.load(Ordering::SeqCst), 1);
    assert_eq!(io.submissions.len(), 1);
    assert!(matches!(
        &io.submissions[0].route,
        inclusion::Route::Shard(path) if path.as_slice() == [true]
    ));
    assert_eq!(
        io.submissions[0].operation,
        quil_execution::token_intrinsic::global_commit::tx_id(&bytes)
    );
    // As the node manager runs it: delivered, nothing printed or kept.
    io.announce = None;
    io.proved = Some((10, 2));
    io.submit(0, bytes).await.unwrap();
    assert_eq!(delivered.load(Ordering::SeqCst), 2);
    assert_eq!(io.submissions.len(), 1);
    drop(io);
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// Coins in their blocks and GLOBAL's accumulator over them, as a node holds
/// both: `early` coins staged at frame 1 in at least two blocks and, when
/// `report`, reported by the shard of each block (six bits deep, one block
/// each); then one coin at frame 2 in the block of each early coin `late`
/// names, which no report covers yet. `coins` is what a scan of that store
/// lists.
struct ReportedCoins {
    _directory: tempfile::TempDir,
    store: Arc<quil_store::RocksHypergraphStore>,
    /// `(address, output, position, frame)` in address order.
    coins: Vec<([u8; 32], Output, u64, u64)>,
    /// The root a scan of the store carries: canonical once reported.
    root: quil_lattice_ct::confidential::coin_tree::RootRecord,
    /// `(filter, report)` of each late coin's block as a shard reports it
    /// once the late coins are in, not yet materialized (late coins of
    /// another wallet only).
    late_reports: Vec<(Vec<u8>, Vec<u8>)>,
}

impl ReportedCoins {
    /// Returns the fixture, the early coins' addresses in staging order and
    /// the late coins' addresses in `late`'s order.
    fn new(
        wallet: &RecipientWallet,
        early: usize,
        late: &[usize],
        report: bool,
    ) -> (Self, Vec<[u8; 32]>, Vec<[u8; 32]>) {
        Self::with_other(wallet, None, early, late, report)
    }

    /// [`Self::new`] without late coins, plus one early coin after the
    /// wallet's in the first early coin's block, whose owner is not a
    /// canonical identity: GLOBAL committed it, and every tree over the
    /// committed coins burns it (its position holds the empty leaf). Its
    /// memo opens for another wallet.
    fn with_burned(
        wallet: &RecipientWallet,
        early: usize,
        report: bool,
    ) -> (Self, Vec<[u8; 32]>, Vec<[u8; 32]>) {
        Self::build(wallet, None, true, early, &[], report, false)
    }

    /// [`Self::new`], plus four early coins of `other` after the wallet's
    /// in staging order: one in the first early coin's block, two in a block
    /// no coin of the wallet is in and one alone in a third block.
    fn with_other(
        wallet: &RecipientWallet,
        other: Option<&RecipientWallet>,
        early: usize,
        late: &[usize],
        report: bool,
    ) -> (Self, Vec<[u8; 32]>, Vec<[u8; 32]>) {
        Self::build(wallet, other, false, early, late, report, false)
    }

    /// [`Self::new`] with reported early coins and the late coins owned by
    /// another wallet, so they are not this wallet's to merge, with the
    /// reports that would cover them.
    #[cfg(feature = "native-proof")]
    fn with_late_other(
        wallet: &RecipientWallet,
        early: usize,
        late: &[usize],
    ) -> (Self, Vec<[u8; 32]>, Vec<[u8; 32]>) {
        Self::build(wallet, None, false, early, late, true, true)
    }

    fn build(
        wallet: &RecipientWallet,
        other: Option<&RecipientWallet>,
        burned: bool,
        early: usize,
        late: &[usize],
        report: bool,
        late_other: bool,
    ) -> (Self, Vec<[u8; 32]>, Vec<[u8; 32]>) {
        use quil_execution::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
        use quil_execution::token_intrinsic::{
            coin_blocks, global_accumulator, roots, scan, shard_accumulator, state,
        };
        let directory = tempfile::tempdir().unwrap();
        let db = quil_store::RocksDb::open(directory.path()).unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        let hypergraph = HypergraphState::new(crdt.clone());
        let (network, application) = (wallet.network, wallet.application);
        let limits = state::SnapshotLimits {
            max_coins: 64,
            max_depth: 32,
            max_nodes: 1 << 14,
        };
        let disc = vertex_adds_discriminator().unwrap();
        let block_of = |address: &[u8; 32]| {
            coin_blocks::block_for_address(coin_blocks::INITIAL_BLOCK_BITS, address).unwrap()
        };
        // An output of `owner` whose coin lands in `block` (any block when
        // `None`).
        let draw = |owner: &RecipientWallet, frame: u64, block: Option<u64>| {
            for _ in 0..4096 {
                let output = quil_lattice_ct::confidential::memo::create_output(
                    &wallet.context,
                    owner.address(),
                    5,
                )
                .unwrap()
                .output;
                let (address, _) = state::coin_identity(&wallet.context, frame, &output).unwrap();
                if block.is_none_or(|block| block_of(&address) == block) {
                    return output;
                }
            }
            panic!("no output landed in the wanted block");
        };
        let stage = |frame: u64, outputs: Vec<Output>| -> Vec<[u8; 32]> {
            let mut staged = std::collections::BTreeMap::new();
            let mut addresses = Vec::new();
            for output in outputs {
                let (address, tree) = roots::stage_coin(
                    &hypergraph,
                    &network,
                    &application,
                    &wallet.context,
                    frame,
                    &output,
                    &mut staged,
                    limits,
                )
                .unwrap();
                hypergraph
                    .set(
                        &application,
                        &address,
                        &disc,
                        frame,
                        quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
                    )
                    .unwrap();
                addresses.push(address);
            }
            roots::refresh_root(&hypergraph, &network, &application, limits)
                .expect("the staged coins fold");
            addresses
        };
        // Early coins in at least two blocks, so inputs come from different
        // subtrees.
        let mut outputs: Vec<Output> = (0..early).map(|_| draw(wallet, 1, None)).collect();
        let first = state::coin_identity(&wallet.context, 1, &outputs[0])
            .unwrap()
            .0;
        if outputs[1..].iter().all(|output| {
            block_of(&state::coin_identity(&wallet.context, 1, output).unwrap().0)
                == block_of(&first)
        }) {
            let elsewhere = (0..4096)
                .map(|_| draw(wallet, 1, None))
                .find(|output| {
                    block_of(&state::coin_identity(&wallet.context, 1, output).unwrap().0)
                        != block_of(&first)
                })
                .expect("an output in another block");
            *outputs.last_mut().unwrap() = elsewhere;
        }
        if let Some(other) = other {
            let identity =
                |output: &Output| state::coin_identity(&wallet.context, 1, output).unwrap().0;
            let mut taken: std::collections::BTreeSet<u64> = outputs
                .iter()
                .map(|output| block_of(&identity(output)))
                .collect();
            outputs.push(draw(other, 1, Some(block_of(&first))));
            for count in [2, 1] {
                let block = (0..4096)
                    .map(|_| block_of(&identity(&draw(other, 1, None))))
                    .find(|block| !taken.contains(block))
                    .expect("a block no coin is in yet");
                taken.insert(block);
                for _ in 0..count {
                    outputs.push(draw(other, 1, Some(block)));
                }
            }
        }
        let stranger = || {
            let keys = sntrup761::Sntrup761KeyPair::generate();
            RecipientWallet::from_keys(
                &network,
                &application,
                &keys.public,
                Zeroizing::new(keys.secret),
            )
            .unwrap()
        };
        if burned {
            let stranger = stranger();
            let block = block_of(&first);
            let coin = (0..4096)
                .map(|_| Output {
                    owner: [0xff; IDENTITY_BYTES],
                    ..draw(&stranger, 1, None)
                })
                .find(|output| {
                    block_of(&state::coin_identity(&wallet.context, 1, output).unwrap().0) == block
                })
                .expect("a burned coin in the first early coin's block");
            outputs.push(coin);
        }
        let staged = outputs.len();
        let early_addresses = stage(1, outputs);
        if report {
            let blocks: std::collections::BTreeSet<u64> = early_addresses
                .iter()
                .map(|address| block_of(address))
                .collect();
            for block in blocks {
                let shard = coin_blocks::block_path(block);
                let report = shard_accumulator::shard_report(
                    &hypergraph,
                    &network,
                    &application,
                    &shard,
                    false,
                )
                .unwrap()
                .expect("the shard holds a coin");
                let filter = quil_forest::encode_shard_bit_path(&application, &shard);
                global_accumulator::materialize_report(
                    &hypergraph,
                    10,
                    &filter,
                    &report.encode().unwrap(),
                )
                .unwrap();
            }
        }
        hypergraph.commit().unwrap();
        hypergraph.abort();
        crdt.commit(1).unwrap();
        let mut late_addresses = Vec::new();
        let mut late_reports = Vec::new();
        if !late.is_empty() {
            let owner = late_other.then(stranger);
            let outputs = late
                .iter()
                .map(|&i| {
                    draw(
                        owner.as_ref().unwrap_or(wallet),
                        2,
                        Some(block_of(&early_addresses[i])),
                    )
                })
                .collect();
            late_addresses = stage(2, outputs);
            if late_other {
                let blocks: std::collections::BTreeSet<u64> =
                    late_addresses.iter().map(block_of).collect();
                for block in blocks {
                    let shard = coin_blocks::block_path(block);
                    let report = shard_accumulator::shard_report(
                        &hypergraph,
                        &network,
                        &application,
                        &shard,
                        false,
                    )
                    .unwrap()
                    .expect("the shard holds a coin");
                    late_reports.push((
                        quil_forest::encode_shard_bit_path(&application, &shard),
                        report.encode().unwrap(),
                    ));
                }
            }
            hypergraph.commit().unwrap();
            hypergraph.abort();
            crdt.commit(2).unwrap();
        }
        let snapshot = quil_types::store::HypergraphStore::capture_tree_snapshot(store.as_ref())
            .unwrap()
            .expect("tree snapshot");
        let page = scan::scan_page(
            snapshot.as_ref(),
            &network,
            &application,
            None,
            quil_types::store::VertexPageLimits {
                max_entries: 1024,
                max_bytes: 64 << 20,
            },
        )
        .unwrap();
        assert!(!page.has_more);
        assert_eq!(page.coins.len(), staged + late.len());
        let coins = page
            .coins
            .into_iter()
            .map(|(address, coin)| (address, coin.output, coin.position, coin.frame_number))
            .collect();
        (
            Self {
                _directory: directory,
                store,
                coins,
                root: page.root,
                late_reports,
            },
            early_addresses,
            late_addresses,
        )
    }

    fn block(address: &[u8; 32]) -> u64 {
        use quil_execution::token_intrinsic::coin_blocks;
        coin_blocks::block_for_address(coin_blocks::INITIAL_BLOCK_BITS, address).unwrap()
    }
    fn output(&self, address: &[u8; 32]) -> Output {
        self.coins
            .iter()
            .find(|(at, ..)| at == address)
            .map(|(_, output, ..)| output.clone())
            .unwrap()
    }

    /// Every listed coin's path in the whole tree, as a node holding them all
    /// would build it.
    fn whole_tree(&self) -> quil_lattice_ct::confidential::sharded_tree::ShardedCoinTree {
        use quil_execution::token_intrinsic::coin_blocks;
        let records: Vec<_> = self
            .coins
            .iter()
            .map(|(address, output, position, _)| {
                quil_lattice_ct::confidential::coin_tree::CoinRecord {
                    address: *address,
                    owner: output.owner,
                    commitment: output.commitment.clone(),
                    position: *position,
                }
            })
            .collect();
        quil_lattice_ct::confidential::sharded_tree::ShardedCoinTree::build(
            &self.root.context,
            quil_lattice_ct::confidential::sharded_tree::Shape {
                shard_bits: coin_blocks::BLOCK_INDEX_BITS,
                subtree_bits: coin_blocks::SUBTREE_BITS,
            },
            &records,
        )
        .unwrap()
    }
}

/// Serves a store's coin scan in pages of two, and records every coin a
/// `GetCoinWitnesses` request names, answering it from the whole tree.
struct RecordingCoins {
    network: [u8; 32],
    application: [u8; 32],
    root: Vec<u8>,
    coins: Vec<([u8; 32], Output, u64, u64)>,
    tree: quil_lattice_ct::confidential::sharded_tree::ShardedCoinTree,
    named: Mutex<Vec<[u8; 32]>>,
    /// Scan pages served.
    pages: std::sync::atomic::AtomicUsize,
}

impl RecordingCoins {
    fn new(wallet: &RecipientWallet, fixture: &ReportedCoins) -> Self {
        Self {
            network: wallet.network,
            application: wallet.application,
            root: fixture.root.encode().unwrap().to_vec(),
            coins: fixture.coins.clone(),
            tree: fixture.whole_tree(),
            named: Mutex::new(Vec::new()),
            pages: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl quil_types::store::CoinWitnessProvider for RecordingCoins {
    fn coin_page(
        &self,
        domain: &[u8; 32],
        _snapshot: Option<&[u8; 32]>,
        after: Option<&[u8; 32]>,
    ) -> quil_types::error::Result<Option<quil_types::store::CoinPageData>> {
        assert_eq!(domain, &self.application);
        self.pages.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let start = self
            .coins
            .partition_point(|(address, ..)| after.is_some_and(|old| address <= old));
        let page = &self.coins[start..(start + 2).min(self.coins.len())];
        Ok(Some(quil_types::store::CoinPageData {
            network: self.network,
            snapshot_id: [44; 32],
            root_record: self.root.clone(),
            coins: page
                .iter()
                .map(
                    |(address, output, position, frame)| quil_types::store::CoinData {
                        address: *address,
                        frame_number: *frame,
                        position: *position,
                        owner: output.owner.to_vec(),
                        commitment: output.commitment.to_bytes().to_vec(),
                        memo: output.memo.to_vec(),
                    },
                )
                .collect(),
            cursor: page.last().map(|(address, ..)| *address).or(after.copied()),
            has_more: start + page.len() < self.coins.len(),
        }))
    }

    fn coin_witnesses(
        &self,
        domain: &[u8; 32],
        addresses: &[[u8; 32]],
    ) -> quil_types::error::Result<Option<quil_types::store::CoinWitnessBundle>> {
        assert_eq!(domain, &self.application);
        self.named.lock().unwrap().extend_from_slice(addresses);
        let depth = self.tree.current_depth();
        Ok(Some(quil_types::store::CoinWitnessBundle {
            network: self.network,
            depth: depth as u8,
            root_record: self
                .tree
                .root_at_depth(depth)
                .unwrap()
                .encode()
                .unwrap()
                .to_vec(),
            witnesses: addresses
                .iter()
                .map(|address| {
                    let path = self.tree.auth_path(address).unwrap();
                    quil_types::store::CoinWitnessData {
                        address: *address,
                        found: true,
                        siblings: path
                            .siblings
                            .iter()
                            .map(|n| n.to_bytes().to_vec())
                            .collect(),
                        right: path.right,
                    }
                })
                .collect(),
        }))
    }
}

fn witness_wallet() -> Arc<RecipientWallet> {
    let keys = sntrup761::Sntrup761KeyPair::generate();
    Arc::new(
        RecipientWallet::from_keys(
            &[31; 32],
            &quil_execution::domains::QUIL_TOKEN,
            &keys.public,
            Zeroizing::new(keys.secret),
        )
        .unwrap(),
    )
}

async fn witness_client(
    fixture: &ReportedCoins,
    provider: Arc<RecordingCoins>,
) -> (
    quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_hypergraph_store(fixture.store.clone())
        .with_coin_witness_provider(provider);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, serving) = serve_node(listener, server);
    let channel = tonic::transport::Endpoint::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    (
        quil_types::proto::node::node_service_client::NodeServiceClient::new(channel),
        stop,
        serving,
    )
}

/// A/B reproducer (wallet privacy): a spend's membership paths must not name
/// its input coins to the node. On the base the wallet asked
/// `GetCoinWitnesses` for the exact input addresses, which a regular node
/// (it never covers QUIL) forwards to a remote node over a connection
/// authenticated with its prover key, so the serving peer learns each spend's
/// real inputs tied to the spender. The paths must still prove both inputs,
/// from different shards, against the canonical root.
#[tokio::test]
async fn spend_witnesses_name_no_input_coin_to_the_node() {
    let wallet = witness_wallet();
    let (fixture, early, _) = ReportedCoins::new(&wallet, 4, &[], true);
    let provider = Arc::new(RecordingCoins::new(&wallet, &fixture));
    let (client, stop, serving) = witness_client(&fixture, provider.clone()).await;
    // Two inputs in different blocks, so in different reported subtrees.
    let other = *early
        .iter()
        .find(|address| ReportedCoins::block(address) != ReportedCoins::block(&early[0]))
        .unwrap();
    let (first, second) = (fixture.output(&early[0]), fixture.output(&other));
    let selected = [(early[0], &first), (other, &second)];
    let result = wallet.witnesses(&client, &selected).await;
    let named = provider.named.lock().unwrap().clone();
    assert!(
        named.is_empty(),
        "the node was told the spend's input coins: {}",
        named.iter().map(hex::encode).collect::<Vec<_>>().join(", ")
    );
    let (root, paths) = result.unwrap();
    assert!(
        root == fixture.root && root.root == provider.tree.root(),
        "the rebuilt root is not the canonical root"
    );
    for ((address, _), path) in selected.iter().zip(&paths) {
        let expected = provider.tree.auth_path(address).unwrap();
        assert!(
            path.siblings == expected.siblings && path.right == expected.right,
            "the rebuilt path of {} is not the whole tree's",
            hex::encode(address)
        );
    }
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// A report lags the coins it covers. The rebuild must prove a reported coin
/// against the canonical root, leaving out its shard's newer coin, and must
/// refuse a coin no report covers yet rather than guess a root for it.
#[tokio::test]
async fn spend_witnesses_follow_lagging_reports_and_refuse_unreported_coins() {
    let wallet = witness_wallet();
    let (fixture, early, late) = ReportedCoins::new(&wallet, 3, &[0], true);
    let provider = Arc::new(RecordingCoins::new(&wallet, &fixture));
    let (client, stop, serving) = witness_client(&fixture, provider.clone()).await;
    assert!(
        fixture.root.root != provider.tree.root(),
        "the late coin must be outside the canonical root"
    );
    let reported = fixture.output(&early[0]);
    let (root, paths) = wallet
        .witnesses(&client, &[(early[0], &reported)])
        .await
        .unwrap();
    assert!(root == fixture.root, "not the canonical root");
    assert_eq!(paths[0].siblings.len(), usize::from(root.depth));
    let newer = fixture.output(&late[0]);
    let Err(error) = wallet.witnesses(&client, &[(late[0], &newer)]).await else {
        panic!("a coin no report covers was given a path");
    };
    let error = error.to_string();
    assert!(error.contains("newer than its subtree's report"), "{error}");
    assert!(provider.named.lock().unwrap().is_empty());
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// An application no shard reports for (one executed in the global venue)
/// has no accumulator index: the wallet rebuilds the whole tree from its
/// scan against the root the scan carries.
#[tokio::test]
async fn spend_witnesses_rebuild_an_unreported_application_from_its_scan() {
    let wallet = witness_wallet();
    let (fixture, early, _) = ReportedCoins::new(&wallet, 3, &[], false);
    let provider = Arc::new(RecordingCoins::new(&wallet, &fixture));
    let (client, stop, serving) = witness_client(&fixture, provider.clone()).await;
    let coin = fixture.output(&early[2]);
    let (root, paths) = wallet
        .witnesses(&client, &[(early[2], &coin)])
        .await
        .unwrap();
    assert!(root == fixture.root, "not the scan's root");
    let expected = provider.tree.auth_path(&early[2]).unwrap();
    assert!(paths[0].siblings == expected.siblings && paths[0].right == expected.right);
    assert!(provider.named.lock().unwrap().is_empty());
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// A spend's witness notes reach the node manager's sink: it runs the same
/// spends, and a print would overwrite its screen.
#[tokio::test]
async fn spend_witness_notes_reach_the_managers_sink() {
    use crate::commands::token::output::capture;
    let wallet = witness_wallet();
    let (fixture, early, _) = ReportedCoins::with_other(&wallet, None, 2, &[], true);
    let provider = Arc::new(RecordingCoins::new(&wallet, &fixture));
    let (client, stop, serving) = witness_client(&fixture, provider).await;
    let owned = wallet
        .clone()
        .scan_spendable(&client, 64, 16)
        .await
        .unwrap();
    let coin = owned.iter().find(|coin| coin.address == early[0]).unwrap();
    let selected = [(coin.address, &coin.output)];
    let (notes, mut lines) = tokio::sync::mpsc::unbounded_channel();
    capture(notes.clone(), wallet.witnesses(&client, &selected))
        .await
        .unwrap();
    let line = lines.try_recv().unwrap();
    assert!(
        line.starts_with("Spend witnesses rebuilt from the selection scan"),
        "{line}"
    );
    // The selection scan serves one spend; another rebuilds from its own.
    capture(notes, wallet.witnesses(&client, &selected))
        .await
        .unwrap();
    let line = lines.try_recv().unwrap();
    assert!(
        line.starts_with("Rebuilding spend witnesses from a full coin scan"),
        "{line}"
    );
    let line = lines.try_recv().unwrap();
    assert!(line.starts_with("spend witnesses: "), "{line}");
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// A spend lists the coins once: the scan that selects its inputs keeps the
/// coins under the subtrees holding the wallet's coins, another wallet's
/// beside them included, and drops the rest, so the witnesses take no second
/// scan, still name no input to the node and still match the whole tree.
#[tokio::test]
async fn spend_witnesses_come_from_the_selection_scan() {
    use std::sync::atomic::Ordering::SeqCst;
    let (wallet, other) = (witness_wallet(), witness_wallet());
    let (fixture, early, _) = ReportedCoins::with_other(&wallet, Some(&other), 3, &[], true);
    let provider = Arc::new(RecordingCoins::new(&wallet, &fixture));
    let (client, stop, serving) = witness_client(&fixture, provider.clone()).await;
    let owned = wallet
        .clone()
        .scan_spendable(&client, 64, 16)
        .await
        .unwrap();
    assert_eq!(owned.len(), 3);
    let scanned = provider.pages.load(SeqCst);
    assert_eq!(scanned, fixture.coins.len().div_ceil(2));
    {
        let ours: std::collections::BTreeSet<u64> =
            early[..3].iter().map(ReportedCoins::block).collect();
        let expected = fixture
            .coins
            .iter()
            .filter(|(address, ..)| ours.contains(&ReportedCoins::block(address)))
            .count();
        assert!(expected > 3, "the other wallet has a coin beside ours");
        let prepared = wallet.prepared.lock().unwrap();
        let kept = prepared
            .as_ref()
            .expect("the selection scan kept the spend's witnesses")
            .kept
            .len();
        assert_eq!(
            kept, expected,
            "the scan must keep exactly the coins in blocks holding ours"
        );
    }
    let first = owned.iter().find(|coin| coin.address == early[0]).unwrap();
    let second = owned
        .iter()
        .find(|coin| ReportedCoins::block(&coin.address) != ReportedCoins::block(&early[0]))
        .unwrap();
    let selected = [
        (first.address, &first.output),
        (second.address, &second.output),
    ];
    let (root, paths) = wallet.witnesses(&client, &selected).await.unwrap();
    assert_eq!(
        provider.pages.load(SeqCst) - scanned,
        0,
        "the spend scanned the coins again for its witnesses"
    );
    assert!(provider.named.lock().unwrap().is_empty());
    assert!(root == fixture.root, "not the canonical root");
    for ((address, _), path) in selected.iter().zip(&paths) {
        let expected = provider.tree.auth_path(address).unwrap();
        assert!(
            path.siblings == expected.siblings && path.right == expected.right,
            "the path of {} is not the whole tree's",
            hex::encode(address)
        );
    }
    assert!(
        wallet.prepared.lock().unwrap().is_none(),
        "a selection scan's witnesses serve one spend"
    );
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// A coin GLOBAL committed with an owner that is not a canonical identity is
/// burned: every tree over the committed coins takes its position as the
/// empty leaf. Anyone can place one beside a wallet's coin, so the wallet
/// must place it as the chain does and still prove its own coin under the
/// same subtree against the canonical root, from a full rescan and from the
/// selection scan, with the shards' reports and without them.
#[tokio::test]
async fn spend_witnesses_place_a_burned_coin_as_the_chain_does() {
    use quil_lattice_ct::confidential::relation::membership::Node;
    use std::sync::atomic::Ordering::SeqCst;
    for report in [true, false] {
        let wallet = witness_wallet();
        let (fixture, early, _) = ReportedCoins::with_burned(&wallet, 3, report);
        let burned: Vec<[u8; 32]> = fixture
            .coins
            .iter()
            .filter(|(_, output, ..)| Node::from_identity_bytes(&output.owner).is_err())
            .map(|(address, ..)| *address)
            .collect();
        assert_eq!(burned.len(), 1, "one coin with a non-canonical owner");
        assert_eq!(
            ReportedCoins::block(&burned[0]),
            ReportedCoins::block(&early[0]),
            "the burned coin shares a block with the wallet's coin"
        );
        let provider = Arc::new(RecordingCoins::new(&wallet, &fixture));
        let (client, stop, serving) = witness_client(&fixture, provider.clone()).await;
        let expected = provider.tree.auth_path(&early[0]).unwrap();
        let coin = fixture.output(&early[0]);
        let selected = [(early[0], &coin)];
        let (root, paths) = wallet
            .witnesses(&client, &selected)
            .await
            .unwrap_or_else(|error| {
                panic!("a full rescan refused the spend (reported: {report}): {error:#}")
            });
        assert!(
            root == fixture.root,
            "the rescan's root is not the canonical root"
        );
        assert!(
            paths[0].siblings == expected.siblings && paths[0].right == expected.right,
            "the rescan's path is not the whole tree's (reported: {report})"
        );
        let owned = wallet
            .clone()
            .scan_spendable(&client, 64, 16)
            .await
            .unwrap_or_else(|error| {
                panic!("the selection scan refused the spend (reported: {report}): {error:#}")
            });
        assert_eq!(owned.len(), 3, "the burned coin is not the wallet's");
        assert!(
            wallet.prepared.lock().unwrap().is_some(),
            "the selection scan kept no witnesses (reported: {report})"
        );
        let scanned = provider.pages.load(SeqCst);
        let (root, paths) = wallet.witnesses(&client, &selected).await.unwrap();
        assert_eq!(
            provider.pages.load(SeqCst),
            scanned,
            "the spend scanned the coins again for its witnesses"
        );
        assert!(
            root == fixture.root,
            "the selection scan's root is not the canonical root"
        );
        assert!(
            paths[0].siblings == expected.siblings && paths[0].right == expected.right,
            "the selection scan's path is not the whole tree's (reported: {report})"
        );
        assert!(provider.named.lock().unwrap().is_empty());
        stop.send(()).unwrap();
        serving.await.unwrap();
    }
}

// ---- Retries after proving: the call sites, against a node that fails ----

/// A loopback node that refuses its first `failures` calls of any kind with
/// `status` before they reach the service. Returns its gRPC multiaddr, the
/// number of calls it received, and its shutdown.
#[cfg(feature = "native-proof")]
async fn flaky_node(
    server: quil_rpc::node_service::NodeRpcServer,
    status: tonic::Status,
    failures: usize,
) -> (
    String,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let service = quil_types::proto::node::node_service_server::NodeServiceServer::with_interceptor(
        server,
        move |request: tonic::Request<()>| {
            if seen.fetch_add(1, Ordering::SeqCst) < failures {
                Err(status.clone())
            } else {
                Ok(request)
            }
        },
    );
    let (listener, multiaddr) = bind_loopback().await;
    let incoming = futures::stream::unfold(listener, |listener| async {
        let result = listener.accept().await.map(|(socket, _)| socket);
        Some((result, listener))
    });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    (multiaddr, calls, stop, serving)
}

#[cfg(feature = "native-proof")]
async fn client_at(
    multiaddr: &str,
) -> quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel> {
    let address = crate::rpc::grpc_multiaddr_to_host_port(multiaddr).unwrap();
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    quil_types::proto::node::node_service_client::NodeServiceClient::new(channel)
}

#[cfg(feature = "native-proof")]
fn quote_network() -> [u8; 32] {
    quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(
        quil_config::Config::default().p2p.network,
    )
    .network
}

/// A node quoting one unit per byte of state growth at 4,096 bytes.
#[cfg(feature = "native-proof")]
fn quoting_node() -> quil_rpc::node_service::NodeRpcServer {
    let network = quote_network();
    quil_rpc::node_service::NodeRpcServer::new().with_token_fee_provider(Arc::new(
        move |_application, _global_venue| {
            Ok(quil_rpc::node_service::TokenFeeSnapshot {
                network,
                observed_frame: 42,
                global_execution: true,
                difficulty: 50_000,
                world_state_bytes: 1 << 40,
                fee_multiplier_vote: 1,
            })
        },
    ))
}

/// The post-proving refresh of a 4,096-byte operation paying `paid`, against
/// a quoting node that refuses its first `failures` calls with `status`.
/// Returns the outcome and the number of calls the node received.
#[cfg(feature = "native-proof")]
async fn refresh_case(
    status: tonic::Status,
    failures: usize,
    paid: u128,
) -> (anyhow::Result<()>, usize) {
    crate::retry::NO_WAIT.store(true, std::sync::atomic::Ordering::SeqCst);
    let (multiaddr, calls, stop, serving) = flaky_node(quoting_node(), status, failures).await;
    let mut client = client_at(&multiaddr).await;
    let result = refresh_fee_quote(
        &mut client,
        &quote_network(),
        quil_execution::domains::QUIL_TOKEN,
        4096,
        false,
        paid,
    )
    .await;
    stop.send(()).unwrap();
    serving.await.unwrap();
    (result, calls.load(std::sync::atomic::Ordering::SeqCst))
}

#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_busy_quote_is_retried_by_the_post_proving_refresh() {
    let busy = tonic::Status::resource_exhausted("fee quote workers busy");
    let (result, calls) = refresh_case(busy, 2, 5000).await;
    result.expect("the refresh must pass once a quote worker is free");
    assert_eq!(calls, 3, "two refusals, then the quote");
}

#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_post_proving_refresh_keeps_the_proof_on_a_transient_quote_failure() {
    use tonic::{Code, Status};
    // A node still busy after the whole retry budget, and every other
    // transient or unsupported answer: the finished proof is submitted with
    // its supplied fee for the node to validate.
    let (result, calls) = refresh_case(Status::resource_exhausted("busy"), usize::MAX, 5000).await;
    result.expect("a node busy past the budget must not lose the proof");
    assert!((3..30).contains(&calls), "bounded retries, got {calls}");
    for code in [
        Code::Unavailable,
        Code::Unimplemented,
        Code::DeadlineExceeded,
        Code::Aborted,
        Code::Cancelled,
        Code::Unknown,
    ] {
        let (result, calls) = refresh_case(Status::new(code, "injected"), usize::MAX, 5000).await;
        result.unwrap_or_else(|e| panic!("{code:?} lost the proof: {e}"));
        assert_eq!(calls, 1, "{code:?} is kept without retrying");
    }
    // The node's real refusals still fail, once.
    for code in [
        Code::InvalidArgument,
        Code::FailedPrecondition,
        Code::Internal,
        Code::PermissionDenied,
        Code::Unauthenticated,
    ] {
        let (result, calls) = refresh_case(Status::new(code, "injected"), usize::MAX, 5000).await;
        let error = result.expect_err("a refusal must fail the refresh");
        assert!(!error.is::<FeeMoved>(), "{code:?} is not a fee move");
        assert_eq!(calls, 1, "{code:?} is not retried");
    }
    // A quote that shows the fee moved is the one failure a rebuild answers.
    let (result, calls) = refresh_case(Status::ok(""), 0, 1).await;
    let error = result.expect_err("an underpaying fee must fail the refresh");
    assert!(error.is::<FeeMoved>(), "{error}");
    assert_eq!(calls, 1);
}

#[cfg(feature = "native-proof")]
#[test]
fn only_a_moved_fee_rebuilds_the_proof() {
    let moved = anyhow::Error::new(FeeMoved("supplied 1, snapshot requires 2".into()));
    assert!(fee_moved_rebuild(None, 1, &moved));
    assert!(fee_moved_rebuild(None, FEE_REBUILDS - 1, &moved));
    assert!(
        !fee_moved_rebuild(None, FEE_REBUILDS, &moved),
        "the rebuilds are bounded"
    );
    assert!(
        !fee_moved_rebuild(Some(5), 1, &moved),
        "an explicit fee is exact and never re-quoted"
    );
    // No refresh failure other than a moved fee re-proves.
    let rpc: anyhow::Error = tonic::Status::deadline_exceeded("slow").into();
    let mismatch = anyhow::anyhow!("fee quote context does not match request");
    assert!(!fee_moved_rebuild(None, 1, &rpc));
    assert!(!fee_moved_rebuild(None, 1, &mismatch));
}

/// A key manager holding the peer key a send is signed with.
#[cfg(feature = "native-proof")]
fn peer_key_manager(directory: &std::path::Path) -> (quil_keys::FileKeyManager, Vec<u8>) {
    let km = quil_keys::FileKeyManager::new(
        directory.join("keys.yml"),
        &hex::encode([7; 32]),
        "q-prover-key".into(),
        Box::new(quil_crypto::FalconKeyConstructor),
    )
    .unwrap();
    let seed = [8; 57];
    let public = quil_crypto::Ed448Signer::derive_public(&seed).unwrap();
    let mut peer = seed.to_vec();
    peer.extend_from_slice(&public);
    km.set_peer_priv_key_hex(&hex::encode(peer));
    (km, public)
}

/// A structurally valid token operation request (not a proof): the node's
/// canonicalization needs only its carrier header.
#[cfg(feature = "native-proof")]
fn token_operation_request() -> quil_types::proto::global::MessageRequest {
    let mut bytes = vec![0, 0, 5, 0x12];
    bytes.extend_from_slice(b"QCT3TX\x00\x02");
    bytes.extend_from_slice(&[1; 32]);
    bytes.extend_from_slice(&[2; 32]);
    quil_types::proto::global::MessageRequest {
        request: Some(
            quil_types::proto::global::message_request::Request::TokenOperation(
                quil_types::proto::token::TokenOperation {
                    canonical_bytes: bytes,
                },
            ),
        ),
        ..Default::default()
    }
}

/// A node whose send handler records each payload and answers `outcome`.
#[cfg(feature = "native-proof")]
fn recording_node(
    outcome: Result<(), String>,
) -> (
    quil_rpc::node_service::NodeRpcServer,
    Arc<Mutex<Vec<Vec<u8>>>>,
) {
    let received = Arc::new(Mutex::new(Vec::new()));
    let captured = received.clone();
    let server = quil_rpc::node_service::NodeRpcServer::new().with_send_handler_fn(Arc::new(
        move |_domain, payload, _authentication| {
            captured.lock().unwrap().push(payload);
            let outcome = outcome.clone();
            Box::pin(async move { outcome.map_err(Into::into) })
        },
    ));
    (server, received)
}

/// The one-request bundle a submission hands to `send_message_bundle`.
#[cfg(feature = "native-proof")]
fn submission_bundle() -> quil_types::proto::global::MessageBundle {
    quil_types::proto::global::MessageBundle {
        requests: vec![token_operation_request()],
        timestamp: crate::send::now_millis(),
    }
}

#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_delivery_that_fails_transiently_is_resent() {
    crate::retry::NO_WAIT.store(true, std::sync::atomic::Ordering::SeqCst);
    let directory = tempfile::tempdir().unwrap();
    let (km, _) = peer_key_manager(directory.path());
    let (server, received) = recording_node(Ok(()));
    let (multiaddr, calls, stop, serving) =
        flaky_node(server, tonic::Status::unavailable("node restarting"), 2).await;
    let mut client = client_at(&multiaddr).await;
    crate::send::send_message_bundle(&mut client, &km, vec![2; 32], submission_bundle())
        .await
        .expect("a node that comes back within the budget must take the submission");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(
        received.lock().unwrap().len(),
        1,
        "the node was reached once, after two refusals"
    );
    stop.send(()).unwrap();
    serving.await.unwrap();
}

#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_rejected_delivery_is_not_resent() {
    crate::retry::NO_WAIT.store(true, std::sync::atomic::Ordering::SeqCst);
    let directory = tempfile::tempdir().unwrap();
    let (km, _) = peer_key_manager(directory.path());
    let (server, received) = recording_node(Err("test rejection".into()));
    let (multiaddr, calls, stop, serving) =
        flaky_node(server, tonic::Status::unavailable("unused"), 0).await;
    let mut client = client_at(&multiaddr).await;
    let error =
        crate::send::send_message_bundle(&mut client, &km, vec![2; 32], submission_bundle())
            .await
            .expect_err("a rejected submission must fail");
    assert!(error.to_string().contains("send rpc"), "{error}");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        received.lock().unwrap().len(),
        1,
        "delivered once, not resent"
    );
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// A node that reached no prover of the application refuses with `retry`: over
/// the real service a sender resends the same signed bytes until one takes them.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_send_the_node_could_not_deliver_is_resent() {
    crate::retry::NO_WAIT.store(true, std::sync::atomic::Ordering::SeqCst);
    let directory = tempfile::tempdir().unwrap();
    let (km, _) = peer_key_manager(directory.path());
    let received = Arc::new(Mutex::new(Vec::new()));
    let captured = received.clone();
    let server = quil_rpc::node_service::NodeRpcServer::new().with_send_handler_fn(Arc::new(
        move |_domain, payload, _authentication| {
            let mut sends = captured.lock().unwrap();
            sends.push(payload);
            let attempt = sends.len();
            Box::pin(async move {
                if attempt < 3 {
                    Err(quil_rpc::SubmitRefusal::retry_later("no prover reachable"))
                } else {
                    Ok(())
                }
            })
        },
    ));
    let (multiaddr, _, stop, serving) =
        flaky_node(server, tonic::Status::unavailable("unused"), 0).await;
    let mut client = client_at(&multiaddr).await;
    crate::send::send_message_bundle(&mut client, &km, vec![2; 32], submission_bundle())
        .await
        .expect("a sender resends what the node could not deliver");
    {
        let sends = received.lock().unwrap();
        assert_eq!(sends.len(), 3, "resent until a prover took it");
        assert!(
            sends.iter().all(|bytes| bytes == &sends[0]),
            "a resend carries the same bytes"
        );
    }
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// A bundle for an application whose shard topic stays out of reach is resent
/// there for the delivery budget, and only then tried in the global venue: a
/// covered application's bundle occupies a global frame and executes nowhere.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_venue_send_tries_global_only_after_the_shard_topic_stays_out_of_reach() {
    crate::retry::NO_WAIT.store(true, std::sync::atomic::Ordering::SeqCst);
    let directory = tempfile::tempdir().unwrap();
    let (km, _) = peer_key_manager(directory.path());
    let (shard, global) = (vec![2u8; 32], vec![0xffu8; 32]);
    let domains = Arc::new(Mutex::new(Vec::new()));
    let captured = domains.clone();
    let shard_topic = shard.clone();
    let server = quil_rpc::node_service::NodeRpcServer::new().with_send_handler_fn(Arc::new(
        move |domain, _payload, _authentication| {
            let to_shard = domain == shard_topic;
            captured.lock().unwrap().push(domain);
            Box::pin(async move {
                if to_shard {
                    Err(quil_rpc::SubmitRefusal::retry_later("no prover reachable"))
                } else {
                    Ok(())
                }
            })
        },
    ));
    let (multiaddr, _, stop, serving) =
        flaky_node(server, tonic::Status::unavailable("unused"), 0).await;
    let mut client = client_at(&multiaddr).await;
    crate::send::send_to_venue(&mut client, &km, shard.clone(), false, submission_bundle())
        .await
        .expect("the global venue takes it");
    {
        let domains = domains.lock().unwrap();
        let (last, first) = domains.split_last().unwrap();
        assert_eq!(last, &global);
        assert!(
            first.len() > 1,
            "resent to the shard topic first: {domains:?}"
        );
        assert!(first.iter().all(|domain| domain == &shard), "{domains:?}");
    }
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// `RecipientWallet::submit` prints the id of the bundle it hands to
/// `send_message_bundle`: a resend carries those same bytes, so the id stays true.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_resent_bundle_keeps_the_id_a_submit_prints() {
    use sha3::Digest;
    crate::retry::NO_WAIT.store(true, std::sync::atomic::Ordering::SeqCst);
    let directory = tempfile::tempdir().unwrap();
    let (km, _) = peer_key_manager(directory.path());
    let (server, received) = recording_node(Ok(()));
    let (multiaddr, calls, stop, serving) =
        flaky_node(server, tonic::Status::unavailable("node restarting"), 2).await;
    let mut client = client_at(&multiaddr).await;
    let bundle = submission_bundle();
    let id = bundle_id(&bundle).unwrap();
    crate::send::send_message_bundle(&mut client, &km, vec![2; 32], bundle)
        .await
        .expect("a node that comes back within the budget must take the bundle");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    let received = received.lock().unwrap().clone();
    assert_eq!(received.len(), 1, "the node was reached once");
    let delivered: [u8; 32] = sha3::Sha3_256::digest(&received[0]).into();
    assert_eq!(delivered, id, "the id names the bytes the node got");
    stop.send(()).unwrap();
    serving.await.unwrap();
}

#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_transient_witness_failure_keeps_waiting_for_the_settlement() {
    let directory = tempfile::tempdir().unwrap();
    let key_manager = Arc::new(
        quil_keys::FileKeyManager::new(
            directory.path().join("keys.yml"),
            &hex::encode([9; 32]),
            "q-prover-key".into(),
            Box::new(quil_crypto::FalconKeyConstructor),
        )
        .unwrap(),
    );
    let (multiaddr, calls, stop, serving) = flaky_node(
        quil_rpc::node_service::NodeRpcServer::new(),
        tonic::Status::deadline_exceeded("slow"),
        usize::MAX,
    )
    .await;
    let opts = crate::rpc::ConnectOpts {
        listen_grpc_multiaddr: multiaddr,
        ..Default::default()
    };
    let tc = TokenCtx {
        node_config: quil_config::Config::default(),
        config_dir: directory.path().to_path_buf(),
        key_manager: key_manager.clone(),
        connect_opts: opts.clone(),
        submit_opts: opts,
        submit_key_manager: key_manager,
        submit_config_dir: directory.path().to_path_buf(),
        submit_identity: Default::default(),
        peer_id_bytes: Vec::new(),
        max_fee: crate::commands::token::DEFAULT_MAX_AUTOMATIC_FEE,
        read_flags: Vec::new(),
    };
    // A zero wait ends the loop after the first answer: a slow witness read
    // is a wait for the settlement, not a failure of the operation.
    let error = settlement_claim(
        &tc,
        [3; 32],
        [4; 32],
        1,
        &ClaimBinding::Bundle([0; 32]),
        None,
        std::time::Duration::ZERO,
    )
    .await
    .expect_err("nothing certified the settlement");
    assert!(error.to_string().contains("not yet certified"), "{error}");
    assert!(calls.load(std::sync::atomic::Ordering::SeqCst) >= 1);
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// A token context on `multiaddr` whose keystore holds the wallet key and the
/// peer key a send is signed with.
#[cfg(feature = "native-proof")]
fn paid_mint_ctx(directory: &std::path::Path, multiaddr: String) -> TokenCtx {
    let (key_manager, _) = peer_key_manager(directory);
    key_manager.create_agreement_key("q-onion-key", 9).unwrap();
    let key_manager = Arc::new(key_manager);
    let opts = crate::rpc::ConnectOpts {
        listen_grpc_multiaddr: multiaddr,
        ..Default::default()
    };
    TokenCtx {
        node_config: quil_config::Config::default(),
        config_dir: directory.to_path_buf(),
        key_manager: key_manager.clone(),
        connect_opts: opts.clone(),
        submit_opts: opts,
        submit_key_manager: key_manager,
        submit_config_dir: directory.to_path_buf(),
        submit_identity: Default::default(),
        peer_id_bytes: Vec::new(),
        read_flags: Vec::new(),
        max_fee: u128::MAX,
    }
}

/// An unsigned custom mint of 3 to `wallet`, framed as the node decodes it
/// (its proof is not a valid proof).
#[cfg(feature = "native-proof")]
fn custom_mint_bytes(wallet: &RecipientWallet) -> Vec<u8> {
    use quil_lattice_ct::confidential::custom_mint::{CustomMint, CustomMintStatement};
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    CustomMint {
        statement: CustomMintStatement {
            network: wallet.network,
            application: wallet.application,
            authority_key_type: 0,
            authority_public_key: Vec::new(),
            nonce: [8; 32],
            amount: 3,
            outputs: vec![
                quil_lattice_ct::confidential::memo::create_output(
                    &wallet.context,
                    wallet.address(),
                    3,
                )
                .unwrap()
                .output,
            ],
            entitlement_proof: Vec::new(),
        },
        signature: Vec::new(),
        proof,
    }
    .encode()
    .unwrap()
}

/// A real GLOBAL membership proof of the settlement record `entry`.
#[cfg(feature = "native-proof")]
fn settlement_witness(
    entry: &quil_execution::token_intrinsic::settlement_record::SettlementEntry,
) -> quil_types::store::MintAuthorizationWitnessData {
    use quil_execution::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
    use quil_hypergraph::addressing::{shard_key_for_location, Location};
    let directory = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(directory.path()).unwrap();
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
        Arc::new(quil_types::crypto::NoopInclusionProver),
    ));
    crdt.set_forest(quil_forest::Forest::new(db.inner()));
    let state = HypergraphState::new(crdt.clone());
    let global = quil_execution::domains::GLOBAL;
    state
        .set(
            &global,
            &entry.receipt,
            &vertex_adds_discriminator().unwrap(),
            1,
            quil_execution::token_intrinsic::settlement_record::create_record(entry).unwrap(),
        )
        .unwrap();
    state.commit().unwrap();
    crdt.commit(1).unwrap();
    let root: [u8; 32] = crdt
        .compute_shard_root(
            "vertex",
            "adds",
            &shard_key_for_location(&Location {
                app_address: global,
                data_address: entry.receipt,
            }),
        )
        .try_into()
        .unwrap();
    let membership = crdt
        .global_vertex_membership_at_root(&root, &entry.receipt)
        .unwrap()
        .unwrap();
    quil_types::store::MintAuthorizationWitnessData {
        found: true,
        cited_frame: 1,
        global_root: root.to_vec(),
        forest_proof: quil_forest::MembershipProof {
            inputs: vec![membership],
        }
        .to_bytes(),
    }
}

/// A node holding one certified settlement record.
#[cfg(feature = "native-proof")]
struct CertifiedSettlement(quil_types::store::MintAuthorizationWitnessData);

#[cfg(feature = "native-proof")]
impl quil_types::store::CoinWitnessProvider for CertifiedSettlement {
    fn mint_authorization_witness(
        &self,
        _receipt: &[u8; 32],
    ) -> quil_types::error::Result<quil_types::store::MintAuthorizationWitnessData> {
        Ok(self.0.clone())
    }
}

/// A/B reproducer: a custom mint's settlement pays for one exact bundle. The
/// base paid first and saved nothing, so a settlement not certified within
/// `--pay-wait` left a payment nothing could spend, and its "retry later" paid
/// again. The bundle must be saved with the receipt before the settlement is
/// sent, and the timeout must point at `--resume`.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_timed_out_paid_mint_leaves_its_bundle_to_resume() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let directory = tempfile::tempdir().unwrap();
    let (listener, multiaddr) = bind_loopback().await;
    let tc = paid_mint_ctx(directory.path(), multiaddr);
    let network = quote_network();
    let wallet = RecipientWallet::load(&tc, &network, &[0x42; 32]).unwrap();
    let payee = RecipientWallet::load(&tc, &network, &quil_execution::domains::QUIL_TOKEN)
        .unwrap()
        .address()
        .clone();
    let mint = custom_mint_bytes(&wallet);
    // A node that quotes but certifies nothing: the wait runs out.
    let (stop, serving) = serve_node(listener, quoting_node());
    let payments = AtomicUsize::new(0);
    let bound = Mutex::new(None);
    let submitted = paid_bundle::submit_paid_with(
        &tc,
        &wallet,
        RootChecked::citing_none(&wallet, mint.clone()).unwrap(),
        Some((payee.clone(), 21)),
        std::time::Duration::ZERO,
        true,
        async |amount, binding: SettlementBinding, _payment, before_submit| {
            // As the wallet's payment does: the call, then the send.
            if let Some(before_submit) = before_submit {
                before_submit(&[5; 32])?;
            }
            payments.fetch_add(1, Ordering::SeqCst);
            *bound.lock().unwrap() = Some((amount, binding.context()));
            Ok([5; 32])
        },
    )
    .await;
    stop.send(()).unwrap();
    serving.await.unwrap();
    let Err(error) = submitted else {
        panic!("nothing certified the settlement, yet the mint was submitted");
    };
    let error = format!("{error:#}");
    assert_eq!(payments.load(Ordering::SeqCst), 1, "the mint pays once");
    let saved: Vec<_> = std::fs::read_dir(directory.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("custom-mint-"))
        })
        .collect();
    assert_eq!(
        saved.len(),
        1,
        "NOTHING-TO-RESUME: a paid mint whose wait ran out saved no bundle: {error}"
    );
    let paid = paid_bundle::PaidBundle::load(&saved[0]).unwrap();
    let (amount, context) = bound.lock().unwrap().take().unwrap();
    assert_eq!(
        paid.context().unwrap(),
        context,
        "the saved bundle is not the one the settlement binds"
    );
    assert_eq!(
        (paid.receipt, paid.settlement, paid.application),
        ([5; 32], amount, [0x42; 32])
    );
    assert_eq!(paid.operation, mint);
    assert_eq!(
        paid.payment,
        Some((
            quil_execution::token_intrinsic::settlement_record::payment_address(&payee.encode())
                .unwrap(),
            21
        ))
    );
    assert!(error.contains("not yet certified"), "{error}");
    assert!(
        error.contains(&format!("custom-mint --resume {}", saved[0].display())),
        "{error}"
    );
    assert!(error.contains("do not run custom-mint again"), "{error}");
    assert!(error.contains("GetMintAuthorizationStatus"), "{error}");
}

/// The saved file rebuilds exactly the bundle the settlement binds, and a
/// file whose bundle no longer hashes to that context is refused rather
/// than submitted as a bundle the settlement does not pay for.
#[cfg(feature = "native-proof")]
#[test]
fn a_saved_paid_bundle_round_trips_to_its_bundle_context() {
    use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
    let directory = tempfile::tempdir().unwrap();
    let operation = vec![0, 0, 5, 0x13, 9, 9, 9];
    let paid = paid_bundle::PaidBundle {
        network: quote_network(),
        application: [0x42; 32],
        timestamp: 1_700_000_000_123,
        operation: operation.clone(),
        receipt: [5; 32],
        settlement: 77,
        payment: Some(([6; 32], 21)),
        global_execution: true,
    };
    let unpaid = paid_bundle::PaidBundle {
        payment: None,
        global_execution: false,
        ..paid.clone()
    };
    // The context the settlement was paid for, as a submission hashes it.
    let bound = quil_execution::token_intrinsic::settlement_claim::bundle_context(
        &CanonicalMessageBundle {
            requests: vec![
                None,
                Some(CanonicalMessageRequest::wrap(operation).unwrap()),
            ],
            timestamp: 1_700_000_000_123,
        },
    )
    .unwrap();
    for bundle in [&paid, &unpaid] {
        let path = bundle.save(directory.path()).unwrap();
        assert_eq!(
            path.file_name().unwrap(),
            "custom-mint-0505050505050505.txt"
        );
        let loaded =
            paid_bundle::PaidBundle::load(&path).expect("ROUNDTRIP: a saved bundle must load");
        assert_eq!(&loaded, bundle, "ROUNDTRIP: the saved bundle changed");
        assert_eq!(
            loaded.context().unwrap(),
            bound,
            "ROUNDTRIP: the saved bundle is not the one the settlement binds"
        );
    }
    let text = paid.encode().unwrap();
    for (from, to) in [
        ("timestamp 1700000000123", "timestamp 1700000000124"),
        ("operation 00000513090909", "operation 00000513090908"),
    ] {
        let changed = text.replace(from, to);
        assert_ne!(changed, text, "{from}");
        let error = paid_bundle::PaidBundle::decode(&changed)
            .expect_err("TAMPER: a changed bundle was accepted");
        assert!(
            error.to_string().contains("does not hash to the context"),
            "{error}"
        );
    }
    assert!(paid_bundle::PaidBundle::decode(&text.replace("receipt ", "receipts ")).is_err());
    assert!(paid_bundle::PaidBundle::decode(&text.replacen("qclient", "other", 1)).is_err());
}

/// `custom-mint --resume` submits the saved bundle, its claim first, once the
/// settlement is certified, and pays nothing: no fee quote, no settlement,
/// one send.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_resumed_mint_submits_its_saved_bundle_without_paying() {
    use quil_execution::message_envelope::CanonicalMessageBundle;
    use quil_execution::token_intrinsic::settlement_claim::{bundle_context, SettlementClaim};
    use std::sync::atomic::{AtomicUsize, Ordering};
    crate::retry::NO_WAIT.store(true, Ordering::SeqCst);
    let directory = tempfile::tempdir().unwrap();
    let (listener, multiaddr) = bind_loopback().await;
    let tc = paid_mint_ctx(directory.path(), multiaddr);
    let network = quote_network();
    let application = [0x42; 32];
    let wallet = RecipientWallet::load(&tc, &network, &application).unwrap();
    let paid = paid_bundle::PaidBundle {
        network,
        application,
        timestamp: crate::send::now_millis(),
        operation: custom_mint_bytes(&wallet),
        receipt: [5; 32],
        settlement: 77,
        payment: Some(([6; 32], 21)),
        global_execution: true,
    };
    let saved = paid.save(directory.path()).unwrap();
    let context = paid.context().unwrap();
    let record = SettlementClaim {
        network,
        application,
        cited_global_frame: 0,
        global_root: [0; 32],
        receipt: [5; 32],
        settlement: 77,
        context,
        payment_address: [6; 32],
        payment: 21,
        claimant_key_type: 0,
        claimant_public_key: Vec::new(),
        claimant_signature: Vec::new(),
        forest_proof: Vec::new(),
    }
    .entry()
    .unwrap();
    let quotes = Arc::new(AtomicUsize::new(0));
    let counted = quotes.clone();
    let (server, received) = recording_node(Ok(()));
    let server = server
        .with_coin_witness_provider(Arc::new(CertifiedSettlement(settlement_witness(&record))))
        .with_token_fee_provider(Arc::new(move |_, _| {
            counted.fetch_add(1, Ordering::SeqCst);
            Err(quil_types::error::QuilError::ExecutionUnavailable(
                "a resume pays nothing".into(),
            ))
        }));
    let (stop, serving) = serve_node(listener, server);
    let resumed =
        paid_bundle::resume(&tc, Some(application), &saved, std::time::Duration::ZERO).await;
    stop.send(()).unwrap();
    serving.await.unwrap();
    let (_, _, priced) = match resumed {
        Ok(resumed) => resumed,
        Err(error) if format!("{error:#}").contains("does not match the requested claim") => {
            panic!("UNPAID-CLAIM: the resume's claim lacks the saved payment: {error:#}")
        }
        Err(error) => {
            panic!("PAID-AGAIN: a resume must submit the saved bundle without paying: {error:#}")
        }
    };
    assert!(priced);
    assert_eq!(
        quotes.load(Ordering::SeqCst),
        0,
        "PAID-AGAIN: a resume quoted a new settlement"
    );
    let received = received.lock().unwrap().clone();
    assert_eq!(received.len(), 1, "one bundle, sent once");
    let bundle = CanonicalMessageBundle::from_canonical_bytes(&received[0]).unwrap();
    assert_eq!(
        bundle_context(&bundle).unwrap(),
        context,
        "the resumed bundle is not the one the settlement binds"
    );
    let claim = SettlementClaim::decode(&bundle.requests[0].as_ref().unwrap().inner_bytes).unwrap();
    assert_eq!(
        (
            claim.receipt,
            claim.settlement,
            claim.context,
            claim.payment
        ),
        ([5; 32], 77, context, 21)
    );
    // The record of a paid settlement carries its payment: the claim the resume
    // sent proves it at the cited root, and the same claim without the payment
    // (what `token settlement-claim` builds) does not.
    let verify = |entry| {
        quil_execution::token_intrinsic::settlement_record::verify_membership(
            &network,
            &entry,
            &claim.global_root,
            &claim.forest_proof,
        )
    };
    verify(claim.entry().unwrap()).expect("UNPAID-CLAIM: the resumed claim is not proven");
    let mut unpaid = claim.entry().unwrap();
    (unpaid.payment_address, unpaid.payment) = ([0; 32], 0);
    assert!(
        verify(unpaid).is_err(),
        "a claim without the payment proved a paid settlement"
    );
    // A file for another application is refused before the node is asked.
    let other = paid_bundle::resume(&tc, Some([0x43; 32]), &saved, std::time::Duration::ZERO).await;
    let Err(error) = other else {
        panic!("a resume under another --application was accepted");
    };
    assert!(error.to_string().contains("not --application"), "{error}");
}

/// `token settlement-claim` on a paid settlement: the record carries the
/// payment, which the node's witness does not, so the claim takes it from
/// `--payment-address` and `--payment` and then proves at the cited root.
/// Without them the claim cannot match, and the error names the options.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_paid_settlement_is_claimed_by_hand_with_its_payment() {
    use quil_execution::token_intrinsic::settlement_claim::SettlementClaim;
    let directory = tempfile::tempdir().unwrap();
    let (listener, multiaddr) = bind_loopback().await;
    let tc = paid_mint_ctx(directory.path(), multiaddr);
    let network = quote_network();
    let (application, receipt, context) = ([0x42; 32], [5; 32], [7; 32]);
    let record = SettlementClaim {
        network,
        application,
        cited_global_frame: 0,
        global_root: [0; 32],
        receipt,
        settlement: 77,
        context,
        payment_address: [6; 32],
        payment: 21,
        claimant_key_type: 0,
        claimant_public_key: Vec::new(),
        claimant_signature: Vec::new(),
        forest_proof: Vec::new(),
    }
    .entry()
    .unwrap();
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_coin_witness_provider(Arc::new(CertifiedSettlement(settlement_witness(&record))));
    let (stop, serving) = serve_node(listener, server);
    let (application, receipt, context) = (
        hex::encode(application),
        hex::encode(receipt),
        hex::encode(context),
    );
    let claim = |payment: &[&str]| {
        let mut arguments = vec![
            "token",
            "settlement-claim",
            &application,
            &receipt,
            "77",
            &context,
        ];
        arguments.extend_from_slice(payment);
        arguments.into_iter().map(String::from).collect::<Vec<_>>()
    };
    let address = hex::encode([6; 32]);
    let paid = claim(&["--payment-address", &address, "--payment", "21"]);
    let unpaid = claim(&[]);
    let paid = run_token_command(&tc, &paid.iter().map(String::as_str).collect::<Vec<_>>()).await;
    let unpaid =
        run_token_command(&tc, &unpaid.iter().map(String::as_str).collect::<Vec<_>>()).await;
    stop.send(()).unwrap();
    serving.await.unwrap();
    if let Err(error) = paid {
        panic!("PAID-HAND-CLAIM: a claim with the settlement's payment was refused: {error:#}");
    }
    let Err(error) = unpaid else {
        panic!("a claim without the payment matched a paid settlement");
    };
    let error = format!("{error:#}");
    assert!(
        error.contains("does not match the requested claim")
            && error.ends_with("; a paid settlement needs --payment-address and --payment"),
        "NO-PAYMENT-HINT: the refusal does not name the payment options: {error}"
    );
}

/// `--payment-address` and `--payment` are one value: either alone is refused
/// before anything is asked of the node.
#[cfg(feature = "native-proof")]
#[test]
fn settlement_claim_takes_both_payment_options_or_neither() {
    use clap::Parser;
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        token: super::super::TokenArgs,
    }
    let id = hex::encode([1; 32]);
    let parse = |payment: &[&str]| {
        let mut arguments = vec!["token", "settlement-claim", &id, &id, "77", &id];
        arguments.extend_from_slice(payment);
        Cli::try_parse_from(arguments).is_ok()
    };
    assert!(parse(&[]));
    assert!(parse(&["--payment-address", &id, "--payment", "21"]));
    for alone in [["--payment-address", id.as_str()], ["--payment", "21"]] {
        assert!(
            !parse(&alone),
            "ONE-PAYMENT-OPTION: {} alone was accepted",
            alone[0]
        );
    }
}

/// An unspent coin of `wallet` worth `amount` at address `[address; 32]`,
/// as a scan lists it.
#[cfg(feature = "native-proof")]
fn owned_coin(wallet: &RecipientWallet, address: u8, amount: u128) -> OwnedCoin {
    OwnedCoin {
        address: [address; 32],
        output: quil_lattice_ct::confidential::memo::create_output(
            &wallet.context,
            wallet.address(),
            amount,
        )
        .unwrap()
        .output,
        amount: Zeroizing::new(amount),
        image: [address; IDENTITY_BYTES],
    }
}

/// The planned merges' coins, by the first address byte, group by group.
#[cfg(feature = "native-proof")]
fn planned(plan: &MergePlan) -> Vec<Vec<u8>> {
    plan.groups
        .iter()
        .map(|(group, _)| {
            plan.coins[group.clone()]
                .iter()
                .map(|coin| coin.address[0])
                .collect()
        })
        .collect()
}

/// A batch merge's plan: disjoint groups of at most the circuit's inputs,
/// largest coins first, each total the sum of its coins; a last coin with
/// no partner is left, as are a group not worth its fee and empty coins.
#[cfg(feature = "native-proof")]
#[test]
fn merge_plan_groups_are_disjoint_bounded_and_largest_first() {
    let wallet = witness_wallet();
    let none = std::collections::BTreeSet::new();
    let max_inputs = compile_limits().max_inputs;
    assert_eq!(max_inputs, 4, "the network's input limit");
    // Coin i worth i for i in 1..=11, and an empty coin.
    let mut coins: Vec<_> = (1..=11)
        .map(|i| owned_coin(&wallet, i, u128::from(i)))
        .collect();
    coins.push(owned_coin(&wallet, 12, 0));
    let plan = merge_plan(coins, &none, max_inputs, 0).unwrap();
    let groups = planned(&plan);
    let mut seen = std::collections::BTreeSet::new();
    for group in &groups {
        assert!(group.len() >= 2 && group.len() <= max_inputs);
        for address in group {
            assert!(
                seen.insert(*address),
                "MERGE-GROUPS-OVERLAP: coin {address} planned twice"
            );
        }
    }
    assert_eq!(
        groups,
        vec![vec![11, 10, 9, 8], vec![7, 6, 5, 4], vec![3, 2, 1]],
        "largest first, at most four each"
    );
    let totals: Vec<u128> = plan.groups.iter().map(|(_, total)| *total).collect();
    assert_eq!(totals, vec![38, 22, 6]);
    assert_eq!((plan.excluded, plan.below_fee, plan.lone), (0, 0, 0));

    // Nine coins: two merges (30 and 14) and a lone coin; a fee of 14
    // leaves the second merge out.
    let nine = || {
        (1..=9)
            .map(|i| owned_coin(&wallet, i, u128::from(i)))
            .collect::<Vec<_>>()
    };
    let plan = merge_plan(nine(), &none, max_inputs, 6).unwrap();
    assert_eq!(planned(&plan), vec![vec![9, 8, 7, 6], vec![5, 4, 3, 2]]);
    assert_eq!((plan.below_fee, plan.lone), (0, 1));
    let plan = merge_plan(nine(), &none, max_inputs, 14).unwrap();
    assert_eq!(planned(&plan), vec![vec![9, 8, 7, 6]]);
    assert_eq!((plan.below_fee, plan.lone), (1, 1));
    // Equal amounts: the address breaks the tie, so the plan does not
    // depend on the order a node lists coins in.
    let equal = [3u8, 1, 2].map(|i| owned_coin(&wallet, i, 5)).into();
    let plan = merge_plan(equal, &none, max_inputs, 0).unwrap();
    assert_eq!(planned(&plan), vec![vec![1, 2, 3]]);
    assert!(merge_plan(nine(), &none, 1, 0).is_err());
}

/// A batch merge's segment takes its plan's merges in order while their
/// coins' candidate subtrees report at most the cap together, each subtree
/// once; a first merge over the cap fails as its own spend does, and with
/// no index every merge shares the one tree.
#[cfg(feature = "native-proof")]
#[test]
fn a_merge_segment_takes_the_merges_one_witness_pass_serves() {
    use quil_lattice_ct::confidential::relation::membership::{Node, NODE_BYTES};
    let wallet = witness_wallet();
    // Coin i worth i at address [i; 32]: merges 9-6 and 5-2, coin 1 lone.
    let coins = (1..=9)
        .map(|i| owned_coin(&wallet, i, u128::from(i)))
        .collect();
    let plan = merge_plan(coins, &Default::default(), 4, 0).unwrap();
    assert_eq!(planned(&plan), vec![vec![9, 8, 7, 6], vec![5, 4, 3, 2]]);
    let subtree = |index: u64, coins: u64| ReportedSubtree {
        level: 0,
        index,
        coins,
        root: Node::from_bytes(&[0xee; NODE_BYTES]).unwrap(),
    };
    let plan = &plan;
    let groups = move || {
        plan.groups
            .iter()
            .map(move |(group, _)| plan.coins[group.clone()].iter().map(|coin| &coin.address))
    };
    let sized = |subtrees: &[ReportedSubtree], cap| {
        segment_groups(Some(subtrees), groups(), cap).map_err(|error| error.to_string())
    };
    // An eight-bit subtree of ten coins under each coin: 40 under the first
    // merge's coins, 80 under both merges'.
    let mut subtrees: Vec<_> = (1..=9u64).map(|path| subtree(256 | path, 10)).collect();
    assert_eq!(sized(&subtrees, 79), Ok(1), "both merges past the cap");
    assert_eq!(sized(&subtrees, 80), Ok(2));
    assert_eq!(sized(&subtrees, 81), Ok(2));
    let over = |cap| witness_cap_exceeded(cap).to_string();
    assert_eq!(
        over(39),
        "the selected coins' subtrees hold more than 39 coins"
    );
    assert_eq!(sized(&subtrees, 39), Err(over(39)), "a lone merge over");
    assert_eq!(sized(&subtrees, 40), Ok(1));
    // A subtree any coin can sit in counts once, from the first merge.
    subtrees.push(subtree(0, 5));
    assert_eq!(sized(&subtrees, 44), Err(over(44)));
    assert_eq!(sized(&subtrees, 84), Ok(1));
    assert_eq!(sized(&subtrees, 85), Ok(2));
    // No index: one tree holds every coin, whichever merge spends them.
    assert_eq!(segment_groups(None, groups(), 0).unwrap(), 2);
}

/// Coins a batch merge submitted in the last two hours are journaled and
/// left out of the next plan; older and malformed lines are not.
#[cfg(feature = "native-proof")]
#[test]
fn merge_journal_leaves_recently_submitted_coins_out() {
    use super::super::legacy::{
        recently_journaled, recently_shielded, record_journaled, SUBMITTED_EXCLUSION_SECS,
    };
    let wallet = witness_wallet();
    let dir = tempfile::tempdir().unwrap();
    let now = RecipientWallet::unix_now();
    let stale = now - SUBMITTED_EXCLUSION_SECS;
    record_journaled(dir.path(), MERGE_JOURNAL, stale, [[1u8; 32]]).unwrap();
    record_journaled(dir.path(), MERGE_JOURNAL, now, [[2u8; 32], [3; 32]]).unwrap();
    let path = dir.path().join(MERGE_JOURNAL);
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str("garbage\n");
    std::fs::write(&path, text).unwrap();
    let journaled = recently_journaled(dir.path(), MERGE_JOURNAL);
    assert_eq!(journaled, [[2u8; 32], [3; 32]].into_iter().collect());
    assert!(
        recently_shielded(dir.path()).is_empty(),
        "shield-all keeps its own journal"
    );
    let coins = (1..=6)
        .map(|i| owned_coin(&wallet, i, u128::from(i)))
        .collect();
    let plan = merge_plan(coins, &journaled, 4, 0).unwrap();
    assert!(
        planned(&plan)
            .iter()
            .flatten()
            .all(|address| ![2, 3].contains(address)),
        "MERGE-EXCLUSION-OFF: a journaled coin was planned again"
    );
    assert_eq!(plan.excluded, 2);
    assert_eq!(planned(&plan), vec![vec![6, 5, 4, 1]]);
}

/// A batch merge keeps citing its scan's root while GLOBAL has published at
/// most half the roots admission retains since; a single operation cites
/// any root still retained. Neither cites an evicted root, and a root whose
/// age the node cannot tell is left to admission.
#[cfg(feature = "native-proof")]
#[test]
fn merge_root_stays_usable_for_half_the_history() {
    assert_eq!(
        SUBMIT_ROOT_MAX_AGE * 2,
        quil_execution::token_intrinsic::roots::HISTORY_LIMIT
    );
    let half = SUBMIT_ROOT_MAX_AGE;
    for (age, batch, single) in [
        (RootAge::Retained(0), None, None),
        (RootAge::Retained(half), None, None),
        (RootAge::Retained(half + 1), Some(Some(half + 1)), None),
        (
            RootAge::Retained(half * 2 - 1),
            Some(Some(half * 2 - 1)),
            None,
        ),
        (RootAge::Evicted, Some(None), Some(None)),
        (RootAge::Unknown, None, None),
    ] {
        for (limit, refused) in [
            (RootLimit::HalfHistory, batch),
            (RootLimit::Retained, single),
        ] {
            assert_eq!(
                stale_root(age, limit).map(|stale| stale.0),
                refused,
                "MERGE-ROOT-AGE-IGNORED: a root of age {age:?} under {limit:?}"
            );
        }
    }
}

/// A batch merge lists the coins once: from the one scan that finds them it
/// plans disjoint merges and builds every planned coin's path against the
/// canonical root, naming no coin to the node and scanning nothing again.
/// Each merge then prepares through the client against that root: a
/// statement within the network's limits whose relation holds, sharing no
/// spend image with another merge, citing a root admission retains; and the
/// root's age, read from GLOBAL's history, counts the roots published since.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_batch_merge_builds_every_merge_from_one_scan() {
    use quil_execution::hypergraph_state::HypergraphState;
    use quil_execution::token_intrinsic::global_accumulator;
    use quil_lattice_ct::confidential::relation::membership::{Node, NODE_BYTES};
    use std::sync::atomic::Ordering::SeqCst;
    let (wallet, other) = (witness_wallet(), witness_wallet());
    let (fixture, early, _) = ReportedCoins::with_other(&wallet, Some(&other), 9, &[], true);
    let provider = Arc::new(RecordingCoins::new(&wallet, &fixture));
    let (client, stop, serving) = witness_client(&fixture, provider.clone()).await;
    let owned = wallet
        .clone()
        .scan_spendable(&client, 64, 16)
        .await
        .unwrap();
    assert_eq!(owned.len(), 9);
    let scanned = provider.pages.load(SeqCst);
    let limits = compile_limits();
    let fee = 1;
    let plan = merge_plan(owned, &Default::default(), limits.max_inputs, fee).unwrap();
    assert_eq!((plan.groups.len(), plan.lone), (2, 1));
    let (mut segment, left) = wallet
        .merge_segment(&client, plan, MAX_WITNESS_SUBTREE_COINS)
        .await
        .unwrap();
    assert_eq!(left, 0);
    assert_eq!(
        provider.pages.load(SeqCst) - scanned,
        0,
        "MERGE-RESCANNED: the batch scanned the coins again for its witnesses"
    );
    assert!(provider.named.lock().unwrap().is_empty());
    assert!(segment.root == fixture.root, "not the canonical root");
    let mut images = std::collections::BTreeSet::new();
    for index in 0..segment.plan.groups.len() {
        let (spend, total) = segment.take_spend(index).unwrap();
        assert_eq!(total, 5 * spend.coins.len() as u128);
        assert!(spend.root == fixture.root);
        for ((address, _), path) in spend.coins.iter().zip(&spend.paths) {
            assert!(early.contains(address));
            let expected = provider.tree.auth_path(address).unwrap();
            assert!(
                path.siblings == expected.siblings && path.right == expected.right,
                "the path of {} is not the whole tree's",
                hex::encode(address)
            );
        }
        let coins: Vec<_> = spend
            .coins
            .iter()
            .map(|(address, output)| (*address, output))
            .collect();
        let (statement, relation) = wallet
            .prepare_transfer(
                &coins,
                &spend.root,
                &spend.paths,
                &[(wallet.address(), total - fee)],
                fee,
                limits,
            )
            .unwrap();
        assert!(relation.validate_local_witness());
        // What admission compiles from the decoded statement.
        assert!(statement.public_relation(limits).is_ok());
        assert_eq!(
            wallet.open(&statement.outputs[0]).unwrap().amount,
            total - fee
        );
        for image in &statement.images {
            assert!(images.insert(*image), "two merges spend one coin");
        }
    }
    assert_eq!(images.len(), 8);
    assert!(segment.take_spend(0).is_err(), "a path serves one spend");

    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        fixture.store.clone(),
        Arc::new(quil_types::crypto::NoopInclusionProver),
    ));
    let state = HypergraphState::new(crdt.clone());
    assert!(global_accumulator::accepts_root(
        &state,
        &wallet.application,
        &wallet.context,
        segment.root.depth,
        &segment.root.root
    )
    .unwrap());
    let RootAge::Retained(age) = wallet.root_age(&client, &segment.root).await.unwrap() else {
        panic!("the scan's root is not in GLOBAL's history");
    };
    assert!(stale_root(RootAge::Retained(age), RootLimit::HalfHistory).is_none());
    let later = SUBMIT_ROOT_MAX_AGE + 1 - age;
    for i in 0..later {
        let next = quil_lattice_ct::confidential::coin_tree::RootRecord {
            root: Node::from_bytes(&[i as u8 + 1; NODE_BYTES]).unwrap(),
            ..fixture.root.clone()
        };
        global_accumulator::publish_root_for_tests(&state, 3, &wallet.application, next).unwrap();
    }
    state.commit().unwrap();
    state.abort();
    crdt.commit(3).unwrap();
    let aged = wallet.root_age(&client, &segment.root).await.unwrap();
    assert_eq!(aged, RootAge::Retained(SUBMIT_ROOT_MAX_AGE + 1));
    assert!(stale_root(aged, RootLimit::HalfHistory).is_some());
    assert!(stale_root(aged, RootLimit::Retained).is_none());
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// A proof framed as the node decodes one; not a valid proof.
#[cfg(feature = "native-proof")]
fn placeholder_proof() -> Vec<u8> {
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    proof
}

/// The statement of a transfer of `spend` to `recipients` at `fee`.
#[cfg(feature = "native-proof")]
fn spend_statement(
    wallet: &RecipientWallet,
    spend: &Spend,
    recipients: &[(RecipientAddress, u128)],
    fee: u128,
) -> quil_lattice_ct::confidential::transfer::TransferStatement {
    let coins: Vec<_> = spend
        .coins
        .iter()
        .map(|(address, output)| (*address, output))
        .collect();
    let destinations: Vec<_> = recipients
        .iter()
        .map(|(address, amount)| (address, *amount))
        .collect();
    wallet
        .prepare_transfer(
            &coins,
            &spend.root,
            &spend.paths,
            &destinations,
            fee,
            compile_limits(),
        )
        .unwrap()
        .0
}

/// A node serving nine reported coins of `wallet` whose root is current in
/// GLOBAL's history.
#[cfg(feature = "native-proof")]
struct ServedCoins {
    fixture: ReportedCoins,
    multiaddr: String,
    client:
        quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
    stop: tokio::sync::oneshot::Sender<()>,
    serving: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "native-proof")]
impl ServedCoins {
    /// `server` with the coins' store and witnesses, listening.
    async fn start(
        wallet: &RecipientWallet,
        server: quil_rpc::node_service::NodeRpcServer,
    ) -> Self {
        let (fixture, _, _) = ReportedCoins::new(wallet, 9, &[], true);
        Self::serve(wallet, fixture, server).await
    }

    /// `server` with `fixture`'s store and witnesses, listening.
    async fn serve(
        wallet: &RecipientWallet,
        fixture: ReportedCoins,
        server: quil_rpc::node_service::NodeRpcServer,
    ) -> Self {
        let provider = Arc::new(RecordingCoins::new(wallet, &fixture));
        let server = server
            .with_hypergraph_store(fixture.store.clone())
            .with_coin_witness_provider(provider);
        let (multiaddr, stop, serving) = serve_at(server).await;
        let client = client_at(&multiaddr).await;
        Self {
            fixture,
            multiaddr,
            client,
            stop,
            serving,
        }
    }

    /// GLOBAL publishes `count` other roots after the coins' root: the
    /// i-th (from 0) is `[i + 1; NODE_BYTES]`.
    fn age(&self, wallet: &RecipientWallet, count: usize) {
        use quil_lattice_ct::confidential::relation::membership::{Node, NODE_BYTES};
        self.publish(
            wallet,
            (0..count).map(|i| quil_lattice_ct::confidential::coin_tree::RootRecord {
                root: Node::from_bytes(&[i as u8 + 1; NODE_BYTES]).unwrap(),
                ..self.fixture.root.clone()
            }),
        );
    }

    /// GLOBAL publishes `roots` in order.
    fn publish(
        &self,
        wallet: &RecipientWallet,
        roots: impl IntoIterator<Item = quil_lattice_ct::confidential::coin_tree::RootRecord>,
    ) {
        publish_roots(&self.fixture.store, &wallet.application, roots);
    }

    async fn stop(self) {
        self.stop.send(()).unwrap();
        self.serving.await.unwrap();
    }
}

/// GLOBAL publishes `roots` of `application` in `store`, in order.
#[cfg(feature = "native-proof")]
fn publish_roots(
    store: &Arc<quil_store::RocksHypergraphStore>,
    application: &[u8; 32],
    roots: impl IntoIterator<Item = quil_lattice_ct::confidential::coin_tree::RootRecord>,
) {
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        store.clone(),
        Arc::new(quil_types::crypto::NoopInclusionProver),
    ));
    let state = quil_execution::hypergraph_state::HypergraphState::new(crdt.clone());
    for next in roots {
        quil_execution::token_intrinsic::global_accumulator::publish_root_for_tests(
            &state,
            3,
            application,
            next,
        )
        .unwrap();
    }
    state.commit().unwrap();
    state.abort();
    crdt.commit(3).unwrap();
}

/// GLOBAL's records as a node that does not hold GLOBAL reads them, from a
/// node that does: the coins' store. The accumulator reads stale (GLOBAL
/// published another root) from the first index read until index read
/// `good_from`, which republishes the coins' root; with `land_after`, the
/// late coins' reports land once that index read's root-history read is
/// answered, publishing a newer root.
#[cfg(feature = "native-proof")]
struct GlobalReads {
    store: Arc<quil_store::RocksHypergraphStore>,
    application: [u8; 32],
    root: quil_lattice_ct::confidential::coin_tree::RootRecord,
    reports: Vec<(Vec<u8>, Vec<u8>)>,
    good_from: usize,
    land_after: Option<usize>,
    index_reads: std::sync::atomic::AtomicUsize,
    landed: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "native-proof")]
impl GlobalReads {
    fn remote(self: &Arc<Self>) -> quil_rpc::node_service::RemoteVertex {
        let reads = self.clone();
        Arc::new(move |app, data| {
            let reads = reads.clone();
            Box::pin(async move { Some(reads.read(app, &data)) })
        })
    }

    fn read(&self, app: [u8; 32], data: &[u8]) -> (bool, Vec<u8>) {
        use quil_execution::token_intrinsic::global_accumulator as records;
        use quil_lattice_ct::confidential::relation::membership::{Node, NODE_BYTES};
        use std::sync::atomic::Ordering::SeqCst;
        assert_eq!(app, quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS);
        if data == records::index_address(&self.application).unwrap() {
            let read = self.index_reads.fetch_add(1, SeqCst) + 1;
            if read == 1 {
                let other = quil_lattice_ct::confidential::coin_tree::RootRecord {
                    root: Node::from_bytes(&[1; NODE_BYTES]).unwrap(),
                    ..self.root.clone()
                };
                publish_roots(&self.store, &self.application, [other]);
            }
            if read == self.good_from {
                publish_roots(&self.store, &self.application, [self.root.clone()]);
            }
        }
        let shard = quil_types::store::ShardKey {
            l1: quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3),
            l2: app,
        };
        let address = [app.as_slice(), data].concat();
        let raw = quil_types::store::HypergraphStore::load_vertex_underlying_raw(
            self.store.as_ref(),
            "vertex",
            "adds",
            &shard,
            &address,
        )
        .unwrap();
        if data == records::root_history_address(&self.application).unwrap()
            && self.land_after == Some(self.index_reads.load(SeqCst))
            && !self.landed.swap(true, SeqCst)
        {
            self.land();
        }
        (raw.is_some(), raw.unwrap_or_default())
    }

    /// The late coins' shards report them: GLOBAL materializes each report
    /// and publishes the root they fold to.
    fn land(&self) {
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            self.store.clone(),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        let state = quil_execution::hypergraph_state::HypergraphState::new(crdt.clone());
        for (filter, report) in &self.reports {
            assert!(
                quil_execution::token_intrinsic::global_accumulator::materialize_report(
                    &state, 11, filter, report,
                )
                .unwrap(),
                "a late report changes the accumulator"
            );
        }
        state.commit().unwrap();
        state.abort();
        crdt.commit(4).unwrap();
    }
}

/// What [`merge_through_stale_reads`] saw.
#[cfg(feature = "native-proof")]
struct StaleReadsRun {
    result: anyhow::Result<()>,
    lines: Vec<String>,
    /// The root each proved merge cites, in order.
    cited: Vec<quil_lattice_ct::confidential::coin_tree::RootRecord>,
    submitted: usize,
    /// The coins' root: the one the reports of the early coins fold to.
    root: quil_lattice_ct::confidential::coin_tree::RootRecord,
    landed: bool,
}

/// A batch merge of nine reported coins of five, with a coin of another
/// wallet, newer than any report, in each of their blocks; GLOBAL's records
/// read through [`GlobalReads`] with `good_from` and `land_after`. The cap
/// is what the subtrees of the plan's two merges report together, so one
/// witness pass takes both. Placeholder proofs at fee 1.
#[cfg(feature = "native-proof")]
async fn merge_through_stale_reads(good_from: usize, land_after: Option<usize>) -> StaleReadsRun {
    use quil_lattice_ct::confidential::transfer::Transfer;
    use std::sync::atomic::Ordering::SeqCst;
    crate::retry::NO_WAIT.store(true, SeqCst);
    let directory = tempfile::tempdir().unwrap();
    let mut tc = paid_mint_ctx(directory.path(), String::new());
    let network =
        quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = Arc::new(
        RecipientWallet::load(&tc, &network, &quil_execution::domains::QUIL_TOKEN).unwrap(),
    );
    let late: Vec<usize> = (0..9).collect();
    let (fixture, mut ours, _) = ReportedCoins::with_late_other(&wallet, 9, &late);
    // By address, merges of the first four and the next four.
    ours.sort();
    let merged: std::collections::BTreeSet<u64> =
        ours[..8].iter().map(ReportedCoins::block).collect();
    let under = |frame: u64| {
        fixture
            .coins
            .iter()
            .filter(|(address, _, _, at)| {
                *at == frame && merged.contains(&ReportedCoins::block(address))
            })
            .count()
    };
    let cap = under(1);
    assert!(
        under(2) > 0,
        "coins newer than the reports sit under the merges' subtrees"
    );
    let reads = Arc::new(GlobalReads {
        store: fixture.store.clone(),
        application: wallet.application,
        root: fixture.root.clone(),
        reports: fixture.late_reports.clone(),
        good_from,
        land_after,
        index_reads: Default::default(),
        landed: Default::default(),
    });
    let received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let delivered = received.clone();
    let global = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS;
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_send_handler_fn(Arc::new(move |_, _, _| {
            delivered.fetch_add(1, SeqCst);
            Box::pin(async { Ok(()) })
        }))
        .with_application_coverage(Arc::new(move |app: &[u8]| app != global.as_slice()))
        .with_remote_vertex(reads.remote());
    let node = ServedCoins::serve(&wallet, fixture, server).await;
    tc.connect_opts.listen_grpc_multiaddr = node.multiaddr.clone();
    tc.submit_opts = tc.connect_opts.clone();
    let cited = Arc::new(Mutex::new(Vec::new()));
    let record = cited.clone();
    let prove =
        move |wallet: Arc<RecipientWallet>,
              spend: Spend,
              recipients: Vec<(RecipientAddress, u128)>,
              _limits: quil_lattice_ct::confidential::transfer::CompileLimits| {
            record.lock().unwrap().push(spend.root.clone());
            async move {
                anyhow::Ok(
                    Transfer {
                        statement: spend_statement(&wallet, &spend, &recipients, 1),
                        proof: placeholder_proof(),
                    }
                    .encode()
                    .unwrap(),
                )
            }
        };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let result = super::super::output::capture(
        tx,
        run_merge_batch_proving(
            &tc,
            &hex::encode(quil_execution::domains::QUIL_TOKEN),
            1,
            (64, 16),
            std::time::Duration::ZERO,
            cap,
            prove,
        ),
    )
    .await;
    let lines = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    let root = node.fixture.root.clone();
    node.stop().await;
    let cited = cited.lock().unwrap().clone();
    StaleReadsRun {
        result,
        lines,
        cited,
        submitted: received.load(SeqCst),
        root,
        landed: reads.landed.load(SeqCst),
    }
}

/// `server` on a local port: its multiaddr, stop sender and task.
#[cfg(feature = "native-proof")]
async fn serve_at(
    server: quil_rpc::node_service::NodeRpcServer,
) -> (
    String,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let multiaddr = format!(
        "/ip4/127.0.0.1/tcp/{}",
        listener.local_addr().unwrap().port()
    );
    let (stop, serving) = serve_node(listener, server);
    (multiaddr, stop, serving)
}

/// One operation of each class that cites a coin root (a transfer, an
/// escrow funding, a settlement), all spending the served coins' first
/// planned merge against their root at fee 1, with placeholder proofs; and
/// that merge's coins.
#[cfg(feature = "native-proof")]
async fn cited_root_operations(
    wallet: &Arc<RecipientWallet>,
    node: &ServedCoins,
) -> (Vec<(&'static str, Vec<u8>)>, Vec<[u8; 32]>) {
    use quil_lattice_ct::confidential::{
        memo::create_escrow_recovery,
        mint::FALCON_PUBLIC_BYTES,
        pending_claim::EscrowPolicy,
        pending_create::{PendingCreate, PendingCreateStatement},
        settlement::{Settlement, SettlementStatement},
        transfer::Transfer,
    };
    let owned = wallet
        .clone()
        .scan_spendable(&node.client, 64, 16)
        .await
        .unwrap();
    let plan = merge_plan(owned, &Default::default(), compile_limits().max_inputs, 1).unwrap();
    let (mut segment, _) = wallet
        .merge_segment(&node.client, plan, MAX_WITNESS_SUBTREE_COINS)
        .await
        .unwrap();
    assert!(segment.root == node.fixture.root, "not the served root");
    let (spend, total) = segment.take_spend(0).unwrap();
    let statement = spend_statement(wallet, &spend, &[(wallet.address().clone(), total - 1)], 1);
    let recovery =
        create_escrow_recovery(&wallet.context, wallet.address(), wallet.address(), 3).unwrap();
    let pending = PendingCreate {
        statement: PendingCreateStatement {
            funding: statement.clone(),
            policy: EscrowPolicy {
                recipient: [1; FALCON_PUBLIC_BYTES],
                refund: [2; FALCON_PUBLIC_BYTES],
                refund_after_global_frame: 0,
            },
            refund_recovery: recovery.refund,
        },
        proof: placeholder_proof(),
    }
    .encode()
    .unwrap();
    let settlement = Settlement {
        statement: SettlementStatement {
            funding: statement.clone(),
            fee: 0,
            settlement: 1,
            destination: [9; 32],
            context: [7; 32],
            claimant: None,
            payment: None,
        },
        proof: placeholder_proof(),
    }
    .encode()
    .unwrap();
    let transfer = Transfer {
        statement,
        proof: placeholder_proof(),
    }
    .encode()
    .unwrap();
    let addresses = spend.coins.iter().map(|(address, _)| *address).collect();
    (
        vec![
            ("transfer", transfer),
            ("escrow funding", pending),
            ("settlement", settlement),
        ],
        addresses,
    )
}

/// Every operation class that cites a coin root is refused, after proving,
/// once that root is evicted from GLOBAL's history, through the shared
/// submission path (transfers, merges, escrow funding); a batch merge is
/// refused, journaling none of its coins, once GLOBAL has published more
/// than half its history since that root, while a single operation still
/// passes. An operation citing no root passes, as does each class while its
/// root is fresh.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn every_operation_citing_a_stale_root_is_refused_unjournaled() {
    crate::retry::NO_WAIT.store(true, std::sync::atomic::Ordering::SeqCst);
    let wallet = witness_wallet();
    let node = ServedCoins::start(&wallet, quil_rpc::node_service::NodeRpcServer::new()).await;
    let directory = tempfile::tempdir().unwrap();
    let tc = paid_mint_ctx(directory.path(), node.multiaddr.clone());
    let (operations, addresses) = cited_root_operations(&wallet, &node).await;
    let mut uncited = operations[0].1.clone();
    uncited[..4].copy_from_slice(&0x0513u32.to_be_bytes());
    for limit in [RootLimit::Retained, RootLimit::HalfHistory] {
        for (name, bytes) in &operations {
            wallet
                .check_cited_root(&node.client, bytes, limit)
                .await
                .unwrap_or_else(|e| panic!("a fresh {name} was refused under {limit:?}: {e}"));
        }
    }
    node.age(&wallet, SUBMIT_ROOT_MAX_AGE + 1);
    for (name, bytes) in &operations {
        wallet
            .check_cited_root(&node.client, bytes, RootLimit::Retained)
            .await
            .unwrap_or_else(|e| panic!("a retained root refused a single {name}: {e}"));
        let error = wallet
            .check_cited_root(&node.client, bytes, RootLimit::HalfHistory)
            .await
            .expect_err("a root past half the history was let through a batch's limit");
        assert_eq!(
            error.downcast_ref::<StaleRoot>().map(|stale| stale.0),
            Some(Some(SUBMIT_ROOT_MAX_AGE + 1)),
            "{name}: {error}"
        );
    }
    let transfer = operations[0].1.clone();
    let mut client = node.client.clone();
    let error = submit_batch_merge(
        &tc,
        &wallet,
        &mut client,
        &addresses,
        transfer.clone(),
        RootLimit::HalfHistory,
    )
    .await
    .err()
    .expect("BATCH-ROOT-UNCHECKED: a batch merge submitted a stale root");
    assert!(error.is::<StaleRoot>(), "BATCH-ROOT-UNCHECKED: {error}");
    assert!(
        super::super::legacy::recently_journaled(directory.path(), MERGE_JOURNAL).is_empty(),
        "a refused merge's coins were journaled"
    );
    node.age(
        &wallet,
        quil_execution::token_intrinsic::roots::HISTORY_LIMIT,
    );
    for limit in [RootLimit::Retained, RootLimit::HalfHistory] {
        for (name, bytes) in &operations {
            let error = wallet
                .check_cited_root(&node.client, bytes, limit)
                .await
                .expect_err("SUBMIT-ROOT-UNCHECKED: an evicted root was let through");
            assert_eq!(
                error.downcast_ref::<StaleRoot>().map(|stale| stale.0),
                Some(None),
                "{name} under {limit:?}: {error}"
            );
        }
        wallet
            .check_cited_root(&node.client, &uncited, limit)
            .await
            .expect("an operation citing no root is not refused");
    }
    let error = submit_refreshed_operation(&tc, &wallet, &node.client, transfer)
        .await
        .err()
        .expect("SUBMIT-ROOT-UNCHECKED: the shared path submitted an evicted root");
    assert!(error.is::<StaleRoot>(), "SUBMIT-ROOT-UNCHECKED: {error}");
    node.stop().await;
}

/// A node that serves no root history cannot date a cited root: the wallet
/// submits and leaves the root to admission rather than refusing every
/// spend.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_root_of_unknown_age_is_left_to_admission() {
    let wallet = witness_wallet();
    let node = ServedCoins::start(&wallet, quil_rpc::node_service::NodeRpcServer::new()).await;
    let (operations, _) = cited_root_operations(&wallet, &node).await;
    let (multiaddr, stop, serving) = serve_at(
        quil_rpc::node_service::NodeRpcServer::new()
            .with_hypergraph_store(Arc::new(quil_hypergraph::testing::MemStore::new())),
    )
    .await;
    let bare = client_at(&multiaddr).await;
    assert_eq!(
        wallet.root_age(&bare, &node.fixture.root).await.unwrap(),
        RootAge::Unknown
    );
    let (sink, mut lines) = tokio::sync::mpsc::unbounded_channel();
    super::super::output::capture(sink, async {
        for limit in [RootLimit::Retained, RootLimit::HalfHistory] {
            for (name, bytes) in &operations {
                wallet
                    .check_cited_root(&bare, bytes, limit)
                    .await
                    .unwrap_or_else(|e| panic!("ROOT-AGE-UNKNOWN-REFUSED: {name}: {e}"));
            }
        }
    })
    .await;
    let mut said = Vec::new();
    while let Ok(line) = lines.try_recv() {
        said.push(line);
    }
    assert_eq!(said.len(), 1, "the run says the unknown age once: {said:?}");
    assert!(
        said[0].contains("root history") && said[0].contains(&hex::encode(wallet.application)),
        "{said:?}"
    );
    stop.send(()).unwrap();
    serving.await.unwrap();
    node.stop().await;
}

/// A batch merge whose fee moved while it proved is refused before its
/// coins are journaled, so a rerun may spend them.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_batch_merge_whose_fee_moved_journals_nothing() {
    crate::retry::NO_WAIT.store(true, std::sync::atomic::Ordering::SeqCst);
    let wallet = witness_wallet();
    let node = ServedCoins::start(&wallet, quoting_node()).await;
    let directory = tempfile::tempdir().unwrap();
    let tc = paid_mint_ctx(directory.path(), node.multiaddr.clone());
    let (operations, addresses) = cited_root_operations(&wallet, &node).await;
    let mut client = node.client.clone();
    let error = submit_batch_merge(
        &tc,
        &wallet,
        &mut client,
        &addresses,
        operations[0].1.clone(),
        RootLimit::HalfHistory,
    )
    .await
    .err()
    .expect("a fee of 1 is under the quote");
    assert!(error.is::<FeeMoved>(), "{error}");
    assert!(
        super::super::legacy::recently_journaled(directory.path(), MERGE_JOURNAL).is_empty(),
        "JOURNAL-BEFORE-FEE: a merge refused for its fee journaled its coins"
    );
    node.stop().await;
}

/// One `token merge --batch` runs at a time per wallet: a second is refused
/// before it reads anything while the first holds the lock, and runs once
/// the first has ended.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn one_batch_merge_runs_at_a_time_per_wallet() {
    let directory = tempfile::tempdir().unwrap();
    let held = lock_merge_batch(directory.path()).unwrap();
    let refused = lock_merge_batch(directory.path())
        .expect_err("BATCH-UNLOCKED: two batch runs held the lock");
    assert!(refused.to_string().contains("another"), "{refused}");
    // No node listens there: a run that got past the lock would fail
    // to connect instead.
    let tc = paid_mint_ctx(directory.path(), "/ip4/127.0.0.1/tcp/1".into());
    let error = run_merge_batch(
        &tc,
        &hex::encode(quil_execution::domains::QUIL_TOKEN),
        1,
        1,
        1,
        std::time::Duration::ZERO,
    )
    .await
    .expect_err("BATCH-UNLOCKED: a second run started");
    assert!(
        error.to_string().contains("another `token merge --batch`"),
        "{error}"
    );
    drop(held);
    drop(lock_merge_batch(directory.path()).expect("the lock ends with its run"));
}

/// A batch merge proved against a root GLOBAL no longer retains is dropped
/// unjournaled, and as a merge from this scan was already submitted, the
/// run rescans: the coins left (the journaled ones out) are replanned and
/// merged against the fresh scan's root. Placeholder proofs; the second
/// proof cites an evicted root.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_batch_merge_rescans_after_a_stale_root() {
    use quil_lattice_ct::confidential::{
        relation::membership::{Node, NODE_BYTES},
        transfer::Transfer,
    };
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    crate::retry::NO_WAIT.store(true, SeqCst);
    let directory = tempfile::tempdir().unwrap();
    let mut tc = paid_mint_ctx(directory.path(), String::new());
    let network =
        quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = Arc::new(
        RecipientWallet::load(&tc, &network, &quil_execution::domains::QUIL_TOKEN).unwrap(),
    );
    let received = Arc::new(Mutex::new(Vec::new()));
    let capture = received.clone();
    let server = quil_rpc::node_service::NodeRpcServer::new().with_send_handler_fn(Arc::new(
        move |_, payload, _| {
            let capture = capture.clone();
            Box::pin(async move {
                let bundle =
                    quil_execution::message_envelope::CanonicalMessageBundle::from_canonical_bytes(
                        &payload,
                    )
                    .map_err(|e| e.to_string())?;
                let request = bundle.requests[0].as_ref().ok_or("missing merge")?;
                capture.lock().unwrap().push(request.inner_bytes.clone());
                Ok(())
            })
        },
    ));
    let node = ServedCoins::start(&wallet, server).await;
    tc.connect_opts.listen_grpc_multiaddr = node.multiaddr.clone();
    tc.submit_opts = tc.connect_opts.clone();
    let proved = Arc::new(AtomicUsize::new(0));
    let calls = proved.clone();
    let prove =
        move |wallet: Arc<RecipientWallet>,
              spend: Spend,
              recipients: Vec<(RecipientAddress, u128)>,
              _limits: quil_lattice_ct::confidential::transfer::CompileLimits| {
            let call = calls.fetch_add(1, SeqCst);
            async move {
                let mut statement = spend_statement(&wallet, &spend, &recipients, 1);
                if call == 1 {
                    statement.root = Node::from_bytes(&[0xee; NODE_BYTES]).unwrap();
                }
                anyhow::Ok(
                    Transfer {
                        statement,
                        proof: placeholder_proof(),
                    }
                    .encode()
                    .unwrap(),
                )
            }
        };
    run_merge_batch_proving(
        &tc,
        &hex::encode(quil_execution::domains::QUIL_TOKEN),
        1,
        (64, 16),
        std::time::Duration::ZERO,
        MAX_WITNESS_SUBTREE_COINS,
        prove,
    )
    .await
    .unwrap();
    assert_eq!(
        proved.load(SeqCst),
        3,
        "BATCH-ROOT-UNCHECKED: the stale merge was not dropped for a rescan"
    );
    let captured = received.lock().unwrap().clone();
    assert_eq!(
        captured.len(),
        2,
        "a merge of four, then one after the rescan"
    );
    for bytes in &captured {
        let merge = Transfer::decode(bytes, &wallet.network, &wallet.application).unwrap();
        assert!(
            merge.statement.root == node.fixture.root.root,
            "a submitted merge cites a stale root"
        );
    }
    assert_eq!(
        super::super::legacy::recently_journaled(directory.path(), MERGE_JOURNAL).len(),
        8
    );
    node.stop().await;
}

/// A batch whose merges' subtrees report more coins than one witness pass
/// keeps merges in segments: the first scan's segment takes the merges that
/// fit, the next scan plans the rest. Here the cap fits either merge's
/// subtrees but not both: two plans, each merge proved and submitted once,
/// every coin journaled once. Placeholder proofs.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_batch_merge_wider_than_one_witness_pass_merges_in_segments() {
    use quil_execution::token_intrinsic::coin_blocks::{block_for_address, INITIAL_BLOCK_BITS};
    use quil_lattice_ct::confidential::transfer::Transfer;
    use std::sync::atomic::Ordering::SeqCst;
    crate::retry::NO_WAIT.store(true, SeqCst);
    let directory = tempfile::tempdir().unwrap();
    let mut tc = paid_mint_ctx(directory.path(), String::new());
    let network =
        quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = Arc::new(
        RecipientWallet::load(&tc, &network, &quil_execution::domains::QUIL_TOKEN).unwrap(),
    );
    let received = Arc::new(Mutex::new(Vec::new()));
    let server = || {
        let capture = received.clone();
        quil_rpc::node_service::NodeRpcServer::new().with_send_handler_fn(Arc::new(
            move |_, payload, _| {
                let capture = capture.clone();
                Box::pin(async move {
                    let bundle = quil_execution::message_envelope::CanonicalMessageBundle::from_canonical_bytes(
                        &payload,
                    )
                    .map_err(|e| e.to_string())?;
                    let request = bundle.requests[0].as_ref().ok_or("missing merge")?;
                    capture.lock().unwrap().push(request.inner_bytes.clone());
                    Ok(())
                })
            },
        ))
    };
    // Nine coins of five: by address, a merge of the first four, one of the
    // next four, and a lone coin. Each coin's subtree is its six-bit block,
    // reporting every coin in it. Redraw until each merge's subtrees hold a
    // coin the other's do not, so a cap fitting either alone splits them.
    let mut drawn = None;
    for _ in 0..16 {
        let node = ServedCoins::start(&wallet, server()).await;
        assert_eq!(node.fixture.coins.len(), 9);
        let blocks: Vec<u64> = node
            .fixture
            .coins
            .iter()
            .map(|(address, ..)| block_for_address(INITIAL_BLOCK_BITS, address).unwrap())
            .collect();
        let held = |merges: std::ops::Range<usize>| {
            let under: std::collections::BTreeSet<u64> = blocks[merges].iter().copied().collect();
            blocks.iter().filter(|block| under.contains(block)).count()
        };
        let cap = held(0..4).max(held(4..8));
        if held(0..8) > cap {
            drawn = Some((node, cap));
            break;
        }
        node.stop().await;
    }
    let (node, cap) = drawn.expect("a draw whose merges' subtrees differ");
    tc.connect_opts.listen_grpc_multiaddr = node.multiaddr.clone();
    tc.submit_opts = tc.connect_opts.clone();
    let proved = Arc::new(Mutex::new(Vec::new()));
    let record = proved.clone();
    let prove =
        move |wallet: Arc<RecipientWallet>,
              spend: Spend,
              recipients: Vec<(RecipientAddress, u128)>,
              _limits: quil_lattice_ct::confidential::transfer::CompileLimits| {
            record
                .lock()
                .unwrap()
                .extend(spend.coins.iter().map(|(address, _)| *address));
            async move {
                anyhow::Ok(
                    Transfer {
                        statement: spend_statement(&wallet, &spend, &recipients, 1),
                        proof: placeholder_proof(),
                    }
                    .encode()
                    .unwrap(),
                )
            }
        };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    super::super::output::capture(
        tx,
        run_merge_batch_proving(
            &tc,
            &hex::encode(quil_execution::domains::QUIL_TOKEN),
            1,
            (64, 16),
            std::time::Duration::ZERO,
            cap,
            prove,
        ),
    )
    .await
    .unwrap();
    let mut plans = Vec::new();
    while let Ok(line) = rx.try_recv() {
        if line.starts_with("Merge plan:") {
            plans.push(line);
        }
    }
    assert_eq!(
        plans.len(),
        2,
        "SEGMENT-UNSIZED: one witness pass took both merges: {plans:?}"
    );
    assert!(
        plans[0].starts_with(&format!(
            "Merge plan: 2 merges, 1 from this scan and 1 after a rescan (one witness pass keeps at most {cap} coins under their subtrees);"
        )),
        "{}",
        plans[0]
    );
    assert!(
        plans[1].starts_with("Merge plan: 1 merges;"),
        "{}",
        plans[1]
    );
    let addresses: Vec<[u8; 32]> = node
        .fixture
        .coins
        .iter()
        .map(|(address, ..)| *address)
        .collect();
    assert_eq!(
        *proved.lock().unwrap(),
        addresses[..8],
        "each merge proved once, in plan order"
    );
    assert_eq!(received.lock().unwrap().len(), 2, "two merges submitted");
    let journal = std::fs::read_to_string(directory.path().join(MERGE_JOURNAL)).unwrap();
    let journaled: Vec<&str> = journal
        .lines()
        .map(|line| line.split_once(' ').unwrap().1)
        .collect();
    let expected: Vec<String> = addresses[..8].iter().map(hex::encode).collect();
    assert_eq!(journaled, expected, "every merged coin journaled once");
    node.stop().await;
}

/// A witness pass's rebuild keeps only the coins its reports cover, plus
/// one per subtree to show where a report ends: coins newer than every
/// report do not count against the cap the pass was sized on. Here the
/// selection scan's read is stale, so the witnesses are rebuilt by a full
/// scan, and the merges' subtrees hold one newer coin each past the cap:
/// both merges are proved and submitted.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_witness_rebuild_keeps_only_what_the_reports_cover() {
    let run = merge_through_stale_reads(2, None).await;
    if let Err(error) = &run.result {
        panic!("KEPT-COUNTS-NEWER: the rebuild refused coins no report covers: {error:#}");
    }
    assert_eq!((run.cited.len(), run.submitted), (2, 2), "{:?}", run.lines);
    assert!(run.cited.iter().all(|root| *root == run.root));
}

/// A rebuild whose accumulator read is stale is retried whole: sized again
/// on the next read, not refused. Here the selection scan's read and the
/// first rebuild's are stale; the second rebuild merges both.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_stale_sizing_read_is_retried() {
    let run = merge_through_stale_reads(3, None).await;
    let retried = "Spend witnesses not ready (the accumulator records changed while being read); rescanning, attempt 2 of 3.";
    assert!(
        run.result.is_ok() && run.lines.iter().any(|line| line == retried),
        "SIZING-READ-UNRETRIED: a stale sizing read was not retried: {:?} {:?}",
        run.result,
        run.lines
    );
    assert_eq!((run.cited.len(), run.submitted), (2, 2));
}

/// A witness pass builds from the accumulator read it was sized on. Here
/// the late coins' reports land, publishing a newer root, just after the
/// first rebuild's read: both merges still cite the root that read folds
/// to, as a later read's subtrees were never sized.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_witness_pass_builds_from_the_read_it_sized_on() {
    let run = merge_through_stale_reads(2, Some(2)).await;
    assert!(run.landed, "the late reports landed");
    run.result.as_ref().unwrap();
    assert_eq!(run.cited.len(), 2, "{:?}", run.lines);
    assert!(
        run.cited.iter().all(|root| *root == run.root),
        "SIZED-FROM-EARLIER-READ: a merge cites a root other than its pass's sizing read"
    );
}

/// A batch's first merge from a fresh scan is held only to the roots GLOBAL
/// retains, as a single operation is: a rescan would cite a root no younger,
/// so refusing it at half the history would stop every rerun the same way.
/// Later merges of that scan keep the half-history margin and rescan. Here
/// the scan's first two merges cite a root [`SUBMIT_ROOT_MAX_AGE`] + 1 roots
/// old (GLOBAL published that many after it, then the coins' root again, so
/// the scan reads): the first is submitted, the second is dropped for a
/// rescan, whose merge cites the current root. Placeholder proofs.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_batch_merge_submits_a_fresh_first_merge_past_half_the_history() {
    use quil_lattice_ct::confidential::{
        coin_tree::RootRecord,
        relation::membership::{Node, NODE_BYTES},
        transfer::Transfer,
    };
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    crate::retry::NO_WAIT.store(true, SeqCst);
    let directory = tempfile::tempdir().unwrap();
    let mut tc = paid_mint_ctx(directory.path(), String::new());
    let network =
        quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = Arc::new(
        RecipientWallet::load(&tc, &network, &quil_execution::domains::QUIL_TOKEN).unwrap(),
    );
    let received = Arc::new(Mutex::new(Vec::new()));
    let capture = received.clone();
    let server = quil_rpc::node_service::NodeRpcServer::new().with_send_handler_fn(Arc::new(
        move |_, payload, _| {
            let capture = capture.clone();
            Box::pin(async move {
                let bundle =
                    quil_execution::message_envelope::CanonicalMessageBundle::from_canonical_bytes(
                        &payload,
                    )
                    .map_err(|e| e.to_string())?;
                let request = bundle.requests[0].as_ref().ok_or("missing merge")?;
                capture.lock().unwrap().push(request.inner_bytes.clone());
                Ok(())
            })
        },
    ));
    let node = ServedCoins::start(&wallet, server).await;
    node.age(&wallet, SUBMIT_ROOT_MAX_AGE + 1);
    node.publish(&wallet, [node.fixture.root.clone()]);
    let aged = RootRecord {
        root: Node::from_bytes(&[1; NODE_BYTES]).unwrap(),
        ..node.fixture.root.clone()
    };
    assert_eq!(
        wallet.root_age(&node.client, &aged).await.unwrap(),
        RootAge::Retained(SUBMIT_ROOT_MAX_AGE + 1),
        "the premise: the cited root is just past half the history"
    );
    assert_eq!(
        wallet
            .root_age(&node.client, &node.fixture.root)
            .await
            .unwrap(),
        RootAge::Retained(0),
        "the premise: the coins' root is current again"
    );
    tc.connect_opts.listen_grpc_multiaddr = node.multiaddr.clone();
    tc.submit_opts = tc.connect_opts.clone();
    let proved = Arc::new(AtomicUsize::new(0));
    let calls = proved.clone();
    let cited = aged.root.clone();
    let prove =
        move |wallet: Arc<RecipientWallet>,
              spend: Spend,
              recipients: Vec<(RecipientAddress, u128)>,
              _limits: quil_lattice_ct::confidential::transfer::CompileLimits| {
            let call = calls.fetch_add(1, SeqCst);
            let cited = cited.clone();
            async move {
                let mut statement = spend_statement(&wallet, &spend, &recipients, 1);
                if call < 2 {
                    statement.root = cited;
                }
                anyhow::Ok(
                    Transfer {
                        statement,
                        proof: placeholder_proof(),
                    }
                    .encode()
                    .unwrap(),
                )
            }
        };
    run_merge_batch_proving(
        &tc,
        &hex::encode(quil_execution::domains::QUIL_TOKEN),
        1,
        (64, 16),
        std::time::Duration::ZERO,
        MAX_WITNESS_SUBTREE_COINS,
        prove,
    )
    .await
    .unwrap_or_else(|e| {
        panic!("FRESH-HALF-HISTORY: a fresh first merge was refused at half the history: {e:#}")
    });
    assert_eq!(
        proved.load(SeqCst),
        3,
        "the second merge of a scan kept no half-history margin"
    );
    let captured = received.lock().unwrap().clone();
    let roots: Vec<_> = captured
        .iter()
        .map(|bytes| {
            Transfer::decode(bytes, &wallet.network, &wallet.application)
                .unwrap()
                .statement
                .root
        })
        .collect();
    assert!(
        roots == [aged.root, node.fixture.root.root.clone()],
        "the aged first merge, then the rescan's merge at the current root"
    );
    assert_eq!(
        super::super::legacy::recently_journaled(directory.path(), MERGE_JOURNAL).len(),
        8
    );
    node.stop().await;
}

/// A batch merge whose first merge from a scan cites a stale root stops
/// with the refusal: the scan was fresh for that merge, so scanning again
/// cannot cure it and the run never loops proving. Nothing is submitted or
/// journaled. Placeholder proofs; the first cites an evicted root.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_batch_merge_stops_when_its_first_merge_is_stale() {
    use quil_lattice_ct::confidential::{
        relation::membership::{Node, NODE_BYTES},
        transfer::Transfer,
    };
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    crate::retry::NO_WAIT.store(true, SeqCst);
    let directory = tempfile::tempdir().unwrap();
    let mut tc = paid_mint_ctx(directory.path(), String::new());
    let network =
        quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = Arc::new(
        RecipientWallet::load(&tc, &network, &quil_execution::domains::QUIL_TOKEN).unwrap(),
    );
    let received = Arc::new(Mutex::new(Vec::new()));
    let capture = received.clone();
    let server = quil_rpc::node_service::NodeRpcServer::new().with_send_handler_fn(Arc::new(
        move |_, payload, _| {
            let capture = capture.clone();
            Box::pin(async move {
                let bundle =
                    quil_execution::message_envelope::CanonicalMessageBundle::from_canonical_bytes(
                        &payload,
                    )
                    .map_err(|e| e.to_string())?;
                let request = bundle.requests[0].as_ref().ok_or("missing merge")?;
                capture.lock().unwrap().push(request.inner_bytes.clone());
                Ok(())
            })
        },
    ));
    let node = ServedCoins::start(&wallet, server).await;
    tc.connect_opts.listen_grpc_multiaddr = node.multiaddr.clone();
    tc.submit_opts = tc.connect_opts.clone();
    let proved = Arc::new(AtomicUsize::new(0));
    let calls = proved.clone();
    let prove =
        move |wallet: Arc<RecipientWallet>,
              spend: Spend,
              recipients: Vec<(RecipientAddress, u128)>,
              _limits: quil_lattice_ct::confidential::transfer::CompileLimits| {
            let call = calls.fetch_add(1, SeqCst);
            async move {
                let mut statement = spend_statement(&wallet, &spend, &recipients, 1);
                if call == 0 {
                    statement.root = Node::from_bytes(&[0xee; NODE_BYTES]).unwrap();
                }
                anyhow::Ok(
                    Transfer {
                        statement,
                        proof: placeholder_proof(),
                    }
                    .encode()
                    .unwrap(),
                )
            }
        };
    let result = run_merge_batch_proving(
        &tc,
        &hex::encode(quil_execution::domains::QUIL_TOKEN),
        1,
        (64, 16),
        std::time::Duration::ZERO,
        MAX_WITNESS_SUBTREE_COINS,
        prove,
    )
    .await;
    let captured = received.lock().unwrap().clone();
    for bytes in &captured {
        let merge = Transfer::decode(bytes, &wallet.network, &wallet.application).unwrap();
        assert!(
            merge.statement.root == node.fixture.root.root,
            "BATCH-ROOT-UNCHECKED: the stale first merge was submitted"
        );
    }
    assert_eq!(
        proved.load(SeqCst),
        1,
        "FIRST-STALE-LOOPS: a scan that was fresh for its stale merge was rescanned"
    );
    let error = result.expect_err("a stale first merge did not stop the run");
    assert!(error.is::<StaleRoot>(), "{error}");
    assert!(
        captured.is_empty(),
        "a merge was submitted after a stale first merge"
    );
    assert!(
        super::super::legacy::recently_journaled(directory.path(), MERGE_JOURNAL).is_empty(),
        "a stale first merge journaled coins"
    );
    node.stop().await;
}

/// A wallet loaded from a token context on a node serving nine of its
/// coins, that context on that node, and the node; the wallet keeps its
/// config in `directory`.
#[cfg(feature = "native-proof")]
async fn served_loaded_wallet(
    directory: &std::path::Path,
) -> (Arc<RecipientWallet>, TokenCtx, ServedCoins) {
    let unserved = paid_mint_ctx(directory, "/ip4/127.0.0.1/tcp/1".into());
    let wallet = Arc::new(
        RecipientWallet::load(&unserved, &[31; 32], &quil_execution::domains::QUIL_TOKEN).unwrap(),
    );
    let node = ServedCoins::start(&wallet, recording_node(Ok(())).0).await;
    let opts = crate::rpc::ConnectOpts {
        listen_grpc_multiaddr: node.multiaddr.clone(),
        ..Default::default()
    };
    let tc = TokenCtx {
        connect_opts: opts.clone(),
        submit_opts: opts,
        ..unserved
    };
    (wallet, tc, node)
}

/// Submit `bytes` through the wallet's path: its cited root checked, sent
/// to the node.
#[cfg(feature = "native-proof")]
async fn submit_checked(
    wallet: &RecipientWallet,
    tc: &TokenCtx,
    node: &ServedCoins,
    bytes: Vec<u8>,
) {
    let mut client = node.client.clone();
    let checked = RootChecked::check(wallet, &client, bytes, RootLimit::Retained)
        .await
        .unwrap();
    wallet
        .submit(&mut client, &tc.submit_key_manager, checked)
        .await
        .unwrap();
}

/// GLOBAL holds `record` at its address `data` in `store`.
#[cfg(feature = "native-proof")]
fn record_global(store: &Arc<quil_store::RocksHypergraphStore>, data: [u8; 32], record: &[u8]) {
    use quil_types::store::*;
    let global = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS;
    let shard = quil_hypergraph::addressing::shard_key_for_location(
        &quil_hypergraph::addressing::Location {
            app_address: global,
            data_address: data,
        },
    );
    let txn = HypergraphStore::new_transaction(store.as_ref(), false).unwrap();
    HypergraphStore::save_vertex_underlying(
        store.as_ref(),
        txn.as_ref(),
        "vertex",
        "adds",
        &shard,
        &[global.as_slice(), data.as_slice()].concat(),
        record,
    )
    .unwrap();
    txn.commit().unwrap();
}

/// GLOBAL records `marker` of `application` consumed by `operation`, in
/// `store`.
#[cfg(feature = "native-proof")]
fn record_consumed(
    store: &Arc<quil_store::RocksHypergraphStore>,
    application: &[u8; 32],
    marker: &[u8; 32],
    operation: &[u8; 32],
) {
    use quil_execution::token_intrinsic::global_commit;
    record_global(
        store,
        global_commit::consumed_address(application, marker).unwrap(),
        &global_commit::encode_consumed_record(operation).unwrap(),
    );
}

/// A settlement whose input another operation consumed after the node
/// listed it unspent is refused by every node on arrival and never
/// certified: the wait for it reads that from its inputs' consumption
/// records and fails at once, naming the coin, instead of waiting out its
/// deadline.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_settlement_whose_input_was_consumed_fails_its_wait_at_once() {
    use quil_lattice_ct::confidential::settlement::Settlement;
    crate::retry::NO_WAIT.store(true, std::sync::atomic::Ordering::SeqCst);
    let directory = tempfile::tempdir().unwrap();
    let (wallet, tc, node) = served_loaded_wallet(directory.path()).await;
    let (operations, addresses) = cited_root_operations(&wallet, &node).await;
    let (name, settlement) = operations[2].clone();
    assert_eq!(name, "settlement");
    submit_checked(&wallet, &tc, &node, settlement.clone()).await;
    let statement = Settlement::decode(&settlement, &wallet.network, &wallet.application)
        .unwrap()
        .statement;
    let receipt =
        quil_execution::token_intrinsic::settlement_record::receipt_address(&statement).unwrap();
    let marker = quil_execution::token_intrinsic::spent::marker_address(
        &wallet.network,
        &wallet.application,
        &statement.funding.images[0],
    )
    .unwrap();
    record_consumed(
        &node.fixture.store,
        &wallet.application,
        &marker,
        &[0xee; 32],
    );
    let started = std::time::Instant::now();
    let error = settlement_claim(
        &tc,
        statement.destination,
        receipt,
        statement.settlement,
        &ClaimBinding::Bundle(statement.context),
        None,
        std::time::Duration::from_secs(20),
    )
    .await
    .expect_err("a settlement whose input another operation consumed was certified");
    let message = format!("{error:#}");
    eprintln!("REACH consumed-input settlement wait ended: {message}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "input_unchecked: the wait ran {:?} to its deadline: {message}",
        started.elapsed()
    );
    assert!(
        addresses
            .iter()
            .any(|address| message.contains(&hex::encode(address)))
            && message.contains(&hex::encode([0xee; 32])),
        "coin_unnamed: the error names not both the consumed coin and its consumer: {message}"
    );
    node.stop().await;
}

/// A poll whose budget ends before its reads do leaves them for the next
/// poll, which goes on from the input they reached: polls with no budget
/// at all still read a spend's second input, which another operation
/// consumed, and end its wait.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn polls_with_no_budget_read_every_input_in_turn() {
    let directory = tempfile::tempdir().unwrap();
    let (wallet, tc, node) = served_loaded_wallet(directory.path()).await;
    let (first, second) = ([0x41; 32], [0x42; 32]);
    let operation = [0x43; 32];
    super::pending::PendingSpends::at(&tc.config_dir).record(super::pending::PendingSpend {
        application: wallet.application,
        operation,
        receipt: None,
        at: RecipientWallet::unix_now(),
        inputs: [first, second]
            .map(|marker| super::pending::SpentInput { marker, coin: None })
            .to_vec(),
    });
    record_consumed(
        &node.fixture.store,
        &wallet.application,
        &second,
        &[0xee; 32],
    );
    let mut watch =
        super::pending::InputWatch::operation(&tc, "transfer", &wallet.application, &operation);
    let started = std::time::Instant::now();
    let deadline = started + std::time::Duration::from_secs(60);
    let mut polls = 0u32;
    let spent = loop {
        polls += 1;
        match watch
            .poll(&node.client, deadline, std::time::Duration::ZERO)
            .await
        {
            Err(spent) => break spent,
            Ok(()) => {
                assert!(
                    started.elapsed() < std::time::Duration::from_secs(5),
                    "reads_restarted: {polls} polls with no budget never read the second \
                     input"
                );
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    };
    eprintln!("REACH consumed-input second input read after {polls} polls");
    assert_eq!(spent.input.marker, second, "the poll named another input");
    assert_eq!(spent.by, [0xee; 32]);
    node.stop().await;
}

/// A coin this wallet just spent stays out of its next selection while the
/// node, its GLOBAL view behind, still lists it unspent: the next spend
/// does not take it again and fail.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_coin_this_wallet_just_spent_is_not_selected_again() {
    crate::retry::NO_WAIT.store(true, std::sync::atomic::Ordering::SeqCst);
    let directory = tempfile::tempdir().unwrap();
    let (wallet, tc, node) = served_loaded_wallet(directory.path()).await;
    let (operations, addresses) = cited_root_operations(&wallet, &node).await;
    let before = wallet
        .clone()
        .scan_spendable(&node.client, 64, 16)
        .await
        .unwrap();
    assert!(
        addresses
            .iter()
            .all(|address| before.iter().any(|coin| coin.address == *address)),
        "the node lists the coins unspent"
    );
    submit_checked(&wallet, &tc, &node, operations[0].1.clone()).await;
    let after = wallet
        .clone()
        .scan_spendable(&node.client, 64, 16)
        .await
        .unwrap();
    eprintln!("REACH consumed-input selection after a spend");
    let again: Vec<String> = after
        .iter()
        .filter(|coin| addresses.contains(&coin.address))
        .map(|coin| hex::encode(coin.address))
        .collect();
    assert!(
        again.is_empty(),
        "spent_reselected: a just-spent coin was selected again: {again:?}"
    );
    assert_eq!(
        after.len(),
        before.len() - addresses.len(),
        "only the spent coins are held"
    );
    node.stop().await;
}

/// A settlement whose inputs' consumption records name the settlement
/// itself committed: its wait goes on for the certificate and never tells
/// the user it can never commit, which would invite paying twice.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_settlement_that_consumed_its_own_inputs_is_not_called_refused() {
    use quil_execution::token_intrinsic::{global_commit, settlement_record, spent};
    use quil_lattice_ct::confidential::settlement::Settlement;
    crate::retry::NO_WAIT.store(true, std::sync::atomic::Ordering::SeqCst);
    let directory = tempfile::tempdir().unwrap();
    let (wallet, tc, node) = served_loaded_wallet(directory.path()).await;
    let (operations, _) = cited_root_operations(&wallet, &node).await;
    let (name, settlement) = operations[2].clone();
    assert_eq!(name, "settlement");
    submit_checked(&wallet, &tc, &node, settlement.clone()).await;
    let operation = global_commit::tx_id(&settlement);
    let journal = std::fs::read_to_string(tc.config_dir.join("wallet-pending-spends.txt"))
        .unwrap_or_default();
    assert!(
        journal.contains(&hex::encode(operation)),
        "premise: the wallet journaled not the settlement it submitted:\n{journal}"
    );
    let statement = Settlement::decode(&settlement, &wallet.network, &wallet.application)
        .unwrap()
        .statement;
    for image in &statement.funding.images {
        let marker = spent::marker_address(&wallet.network, &wallet.application, image).unwrap();
        record_consumed(
            &node.fixture.store,
            &wallet.application,
            &marker,
            &operation,
        );
    }
    let error = settlement_claim(
        &tc,
        statement.destination,
        settlement_record::receipt_address(&statement).unwrap(),
        statement.settlement,
        &ClaimBinding::Bundle(statement.context),
        None,
        std::time::Duration::from_secs(3),
    )
    .await
    .expect_err("a settlement no root certifies was claimed");
    let message = format!("{error:#}");
    eprintln!("REACH consumed-input own settlement wait ended: {message}");
    assert!(
        message.contains("not yet certified") && !message.contains("can never commit"),
        "committed_as_spent: a settlement that consumed its own inputs was called refused: \
         {message}"
    );
    node.stop().await;
}

/// A settle over operations the global commit never decides because
/// another operation consumed one of their inputs (a shield's legacy
/// source, a mint claim's receipt) ends each of those waits at once,
/// naming the consumer, this wallet's own when it journaled it, and goes on
/// to the next operation; a rejected one frees its journal entry.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_settle_ends_each_wait_whose_input_was_consumed_and_goes_on() {
    use quil_execution::token_intrinsic::{
        global_commit::{self, Decision},
        spend_entries,
    };
    use quil_lattice_ct::confidential::{
        memo::create_output,
        mint_claim::MintClaim,
        shield::{Shield, ShieldStatement},
    };
    crate::retry::NO_WAIT.store(true, std::sync::atomic::Ordering::SeqCst);
    let directory = tempfile::tempdir().unwrap();
    let (wallet, tc, node) = served_loaded_wallet(directory.path()).await;
    let (operations, _) = cited_root_operations(&wallet, &node).await;
    let (name, transfer) = operations[0].clone();
    assert_eq!(name, "transfer");
    let output = |amount| {
        create_output(&wallet.context, wallet.address(), amount)
            .unwrap()
            .output
    };
    let shield = Shield {
        statement: ShieldStatement {
            network: wallet.network,
            application: wallet.application,
            transparent_address: [0x81; 32],
            owner_public_key: [7; 57],
            amount: 12,
            fee: 2,
            outputs: vec![output(10)],
        },
        signature: [0; 114],
        proof: placeholder_proof(),
    }
    .encode()
    .unwrap();
    let claim = MintClaim {
        network: wallet.network,
        application: wallet.application,
        cited_global_frame: 3,
        global_root: [5; 32],
        receipt: [6; 32],
        fee: 1,
        outputs: vec![output(7)],
        forest_proof: vec![1],
    }
    .encode()
    .unwrap();
    let mut submitted = Vec::new();
    for bytes in [&shield, &claim, &transfer] {
        submit_checked(&wallet, &tc, &node, bytes.clone()).await;
        submitted.push(Submitted::of(&wallet.network, wallet.application, bytes).unwrap());
    }
    let consumed = |bytes: &[u8]| {
        let kind = u32::from_be_bytes(bytes[..4].try_into().unwrap());
        spend_entries::commit_needs(&wallet.application, kind, bytes)
            .unwrap()
            .consumptions[0]
    };
    let (store, application) = (&node.fixture.store, &wallet.application);
    let transfer_id = global_commit::tx_id(&transfer);
    record_consumed(store, application, &consumed(&shield), &[0xee; 32]);
    record_consumed(store, application, &consumed(&claim), &transfer_id);
    record_global(
        store,
        global_commit::decision_address(application, &transfer_id).unwrap(),
        &global_commit::encode_decision_record(&Decision::Rejected {
            frame: 7,
            reason: "a test rejection".into(),
        })
        .unwrap(),
    );
    let wait = std::time::Duration::from_secs(20);
    let started = std::time::Instant::now();
    let error = inclusion::settle(
        &tc,
        &wallet,
        "operation",
        &submitted,
        Follow { wait, max_pages: 4 },
        started + wait,
    )
    .await
    .expect_err("operations refused or rejected settled");
    let message = format!("{error:#}");
    eprintln!("REACH consumed-input settle ended: {message}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "decision_unchecked: the settle ran {:?} to its deadline: {message}",
        started.elapsed()
    );
    assert!(
        message.contains("a test rejection"),
        "settle_continue: the settle stopped before the rejected transfer's decision: {message}"
    );
    assert!(
        message.contains(&format!("by operation 0x{}", hex::encode([0xee; 32])))
            && message.contains(&format!(
                "by this wallet's earlier operation 0x{}",
                hex::encode(transfer_id)
            )),
        "consumer_unnamed: the errors name not each consumer, this wallet's as its own: \
         {message}"
    );
    let journal = std::fs::read_to_string(tc.config_dir.join("wallet-pending-spends.txt"))
        .unwrap_or_default();
    assert!(
        !journal.contains(&hex::encode(transfer_id)),
        "decided_release: the rejected transfer still holds its coins:\n{journal}"
    );
    node.stop().await;
}
