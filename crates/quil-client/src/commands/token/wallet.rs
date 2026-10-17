//! Recipient wallet using the existing encrypted q-onion key.
//! No plaintext spend-key file or legacy spend-base derivation is used here.
use super::TokenCtx;
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
use quil_crypto::sntrup761;
use quil_lattice_ct::confidential::{
    address::RecipientAddress,
    memo::{open_output, OpenedOutput},
    relation::membership::RecipientSecret,
    transfer::{parameter_context, Output},
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use zeroize::Zeroizing;

#[cfg(all(test, feature = "native-proof"))]
#[path = "wallet_native_tests.rs"]
mod native_tests;

#[cfg(test)]
#[path = "wallet_submission_tests.rs"]
mod submission_tests;

// Shared by mint, shield and transfer preparation as well as native work. A permit
// stays in the blocking worker when its async caller is cancelled.
#[cfg(feature = "native-proof")]
static PROVING: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

pub(super) struct RecipientWallet {
    context: [u8; 32],
    network: [u8; 32],
    application: [u8; 32],
    kem_secret: Zeroizing<Vec<u8>>,
    recipient: RecipientSecret,
    address: RecipientAddress,
}

/// What a settlement binds: the bundle it funds, or — when the payer does not
/// yet know that bundle — the claimant key that will later name one.
#[cfg(feature = "native-proof")]
#[derive(Clone)]
pub(super) enum SettlementBinding {
    Bundle([u8; 32]),
    Claimant(quil_lattice_ct::confidential::settlement::Claimant),
}

#[cfg(feature = "native-proof")]
impl SettlementBinding {
    fn context(&self) -> [u8; 32] {
        match self {
            Self::Bundle(context) => *context,
            Self::Claimant(_) => [0; 32],
        }
    }
    fn claimant(&self) -> Option<quil_lattice_ct::confidential::settlement::Claimant> {
        match self {
            Self::Bundle(_) => None,
            Self::Claimant(claimant) => Some(claimant.clone()),
        }
    }
    /// The claimant key of `key_id` in the local keystore.
    fn of_key(key_manager: &quil_keys::FileKeyManager, key_id: &str) -> anyhow::Result<Self> {
        let signer = key_manager.get_signer_by_id(key_id)
            .map_err(|e| anyhow::anyhow!("claimant key {key_id}: {e}"))?;
        // Claimants are application authority keys: post-quantum only. The
        // node refuses any other, so refuse before paying for the settlement.
        anyhow::ensure!(
            quil_execution::token_intrinsic::signature::is_post_quantum_authority(signer.key_type() as u32),
            "claimant key {key_id} is not a Falcon-512 key; settlement claimants are post-quantum only"
        );
        Ok(Self::Claimant(quil_lattice_ct::confidential::settlement::Claimant {
            key_type: signer.key_type() as u32,
            public_key: signer.public_key().to_vec(),
        }))
    }
}

/// How a claim proves it may spend its settlement: the bundle context the
/// record names, or the claimant key and its signature over that bundle.
#[cfg(feature = "native-proof")]
pub(super) enum ClaimBinding {
    Bundle([u8; 32]),
    Claimant { key_type: u32, public_key: Vec<u8>, signature: Vec<u8> },
}

pub(super) struct EscrowDestination {
    pub(super) recipient: RecipientAddress,
    pub(super) refund: RecipientAddress,
    pub(super) amount: u128,
    pub(super) policy: quil_lattice_ct::confidential::pending_claim::EscrowPolicy,
}

pub(super) struct OwnedCoin {
    pub(super) address: [u8; 32],
    pub(super) output: Output,
    pub(super) amount: Zeroizing<u128>,
    image: [u8; IDENTITY_BYTES],
}

fn select_coins(mut coins: Vec<OwnedCoin>, amount: u128, fee: u128, max_inputs: usize) -> anyhow::Result<(Vec<OwnedCoin>, Zeroizing<u128>)> {
    anyhow::ensure!(amount > 0 && max_inputs > 0, "amount and input limit must be positive");
    // Largest first avoids exhausting the witness limit on small coins while
    // a larger coin later in the scan could fund the transfer.
    coins.sort_by(|a, b| (*b.amount).cmp(&*a.amount).then(a.address.cmp(&b.address)));
    let mut remaining = Zeroizing::new([fee, amount]);
    let mut selected = Vec::new();
    let mut addresses = std::collections::BTreeSet::new();
    let mut images = std::collections::BTreeSet::new();
    for coin in coins {
        if *coin.amount == 0 { continue; }
        anyhow::ensure!(selected.len() < max_inputs, "cannot fund transfer within the input limit");
        anyhow::ensure!(addresses.insert(coin.address) && images.insert(coin.image), "duplicate selected coin or spend image");
        let mut available = Zeroizing::new(*coin.amount);
        for owed in remaining.iter_mut() {
            let paid = (*available).min(*owed);
            *available -= paid; *owed -= paid;
        }
        selected.push(coin);
        if remaining.iter().all(|owed| *owed == 0) { return Ok((selected, available)); }
    }
    anyhow::bail!("insufficient node-reported unspent funds")
}

/// Bounded scan state. A failed page leaves it unchanged; an expired snapshot
/// requires a fresh scan, never an implicit jump to a new database generation.
pub(super) struct CoinScan {
    snapshot_id: Option<[u8; 32]>,
    root: Option<quil_lattice_ct::confidential::coin_tree::RootRecord>,
    after: Option<[u8; 32]>,
    remaining_pages: usize,
    finished: bool,
}
impl CoinScan {
    pub(super) fn new(max_pages: usize) -> anyhow::Result<Self> {
        anyhow::ensure!(max_pages > 0, "scan page budget must be positive");
        Ok(Self {
            snapshot_id: None,
            root: None,
            after: None,
            remaining_pages: max_pages,
            finished: false,
        })
    }
    pub(super) fn finished(&self) -> bool {
        self.finished
    }
}

/// Cold witness indexes may need synchronization before a spend can be
/// prepared. Retry only explicit transient responses, with an overall deadline
/// that includes individual RPC calls and capped exponential backoff.
async fn retry_witness_request<T, F, Fut>(timeout: std::time::Duration, mut request: F) -> Result<T, tonic::Status>
where F: FnMut() -> Fut, Fut: std::future::Future<Output = Result<T, tonic::Status>> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut delay = std::time::Duration::from_millis(250);
    let mut reported = false;
    loop {
        let result = tokio::time::timeout_at(deadline, request()).await
            .map_err(|_| tonic::Status::deadline_exceeded("witness preparation deadline exceeded; retry after synchronization"))?;
        match result {
            Ok(value) => return Ok(value),
            Err(error) if matches!(error.code(), tonic::Code::Unavailable | tonic::Code::ResourceExhausted) => {
                if !reported { eprintln!("Waiting for the node to prepare spend witnesses..."); reported = true; }
                tokio::time::timeout_at(deadline, tokio::time::sleep(delay)).await
                    .map_err(|_| tonic::Status::deadline_exceeded("witness preparation deadline exceeded; retry after synchronization"))?;
                delay = (delay * 2).min(std::time::Duration::from_secs(5));
            }
            Err(error) => return Err(error),
        }
    }
}

impl RecipientWallet {
    /// Check the complete framing/context before choosing a transport domain.
    /// This is not proof verification; receiving execution verifies the proof.
    fn prepare_submission(&self, bytes: Vec<u8>) -> anyhow::Result<(Vec<u8>, quil_types::proto::global::MessageRequest)> {
        use quil_lattice_ct::confidential::{custom_mint::{self, CustomMint}, mint::Mint, mint_claim::MintClaim, pending_create::PendingCreate, pending_claim::PendingClaim, shield::Shield, transfer::Transfer};
        use quil_execution::token_engine::{TYPE_LATTICE_MINT, TYPE_LATTICE_MINT_CLAIM, TYPE_LATTICE_PENDING, TYPE_LATTICE_PENDING_CLAIM, TYPE_LATTICE_SHIELD, TYPE_LATTICE_TRANSACTION};
        let domain = quil_execution::token_intrinsic::wire::domain(&bytes)?;
        anyhow::ensure!(domain == self.application, "operation belongs to another application");
        let kind = u32::from_be_bytes(bytes[..4].try_into().unwrap());
        // Custom-token issuance shares the mint prefix but is application state,
        // so it is delivered to its application rather than GLOBAL.
        let custom_mint = kind == TYPE_LATTICE_MINT && bytes.get(4..12) == Some(custom_mint::VERSION.as_slice());
        let decoded = match kind {
            TYPE_LATTICE_MINT if custom_mint => {
                anyhow::ensure!(domain != quil_execution::domains::QUIL_TOKEN, "QUIL issuance uses the reward mint");
                CustomMint::decode(&bytes, &self.network, &domain).map(|_| ())
            }
            TYPE_LATTICE_MINT => {
                anyhow::ensure!(domain == quil_execution::domains::QUIL_TOKEN, "custom-token mint uses the custom issuance encoding");
                Mint::decode(&bytes, &self.network, &domain).map(|_| ())
            }
            TYPE_LATTICE_MINT_CLAIM => {
                anyhow::ensure!(domain == quil_execution::domains::QUIL_TOKEN, "custom-token mint claim is not supported");
                MintClaim::decode(&bytes, &self.network, &domain).map(|_| ())
            }
            TYPE_LATTICE_SHIELD => quil_lattice_ct::confidential::shield::AnyShield::decode(&bytes, &self.network, &domain).map(|_| ()),
            TYPE_LATTICE_TRANSACTION => Transfer::decode(&bytes, &self.network, &domain).map(|_| ()),
            TYPE_LATTICE_PENDING => PendingCreate::decode(&bytes, &self.network, &domain).map(|_| ()),
            TYPE_LATTICE_PENDING_CLAIM => PendingClaim::decode(&bytes, &self.network, &domain).map(|_| ()),
            // A settlement spends QUIL on the QUIL shard like a transfer.
            quil_execution::token_intrinsic::constants::TYPE_LATTICE_SETTLEMENT => {
                anyhow::ensure!(domain == quil_execution::domains::QUIL_TOKEN, "settlements spend QUIL");
                quil_lattice_ct::confidential::settlement::Settlement::decode(&bytes, &self.network, &domain).map(|_| ())
            }
            _ => anyhow::bail!("unsupported token operation"),
        };
        decoded.map_err(|e| anyhow::anyhow!("invalid token operation: {e:?}"))?;
        let destination = if kind == TYPE_LATTICE_MINT && !custom_mint { quil_execution::domains::GLOBAL } else { domain };
        Ok((destination.to_vec(), quil_types::proto::global::MessageRequest {
            request: Some(quil_types::proto::global::message_request::Request::TokenOperation(
                quil_types::proto::token::TokenOperation { canonical_bytes: bytes })),
            ..Default::default()
        }))
    }

    /// Submit one already-built operation using the node's authenticated Send
    /// transport. Successful delivery does not establish transaction finality.
    pub(super) async fn submit(
        &self,
        client: &mut quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
        key_manager: &quil_keys::FileKeyManager,
        bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        let (domain, request) = self.prepare_submission(bytes.clone())?;
        crate::send::send_message_request(client, key_manager, domain, request).await?;
        Ok(())
    }

    /// Fetch one known escrow, requesting the complete typed record rather
    /// than the legacy field projection. Content identity is checked locally;
    /// inclusion, consumption and refund eligibility remain admission checks.
    pub(super) async fn fetch_escrow(
        &self,
        client: &quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
        address: [u8; 32],
    ) -> anyhow::Result<quil_execution::token_intrinsic::escrow::StoredEscrow> {
        let mut vertex = self.application.to_vec(); vertex.extend_from_slice(&address);
        let response = client.clone().max_decoding_message_size(
            quil_execution::token_intrinsic::escrow::MAX_ESCROW_BLOB_BYTES + 1024)
            .get_vertex_data(quil_types::proto::node::GetVertexDataRequest { address: vertex, full_data: true })
            .await?.into_inner();
        self.decode_escrow_response(address, response)
    }

    fn decode_escrow_response(
        &self, address: [u8; 32], response: quil_types::proto::node::GetVertexDataResponse,
    ) -> anyhow::Result<quil_execution::token_intrinsic::escrow::StoredEscrow> {
        anyhow::ensure!(response.set_type == "vertex" && response.phase_type == "adds"
            && response.shard_l2 == self.application
            && response.shard_l1 == quil_hypergraph::addressing::get_bloom_filter_indices(&self.application, 256, 3)
            && response.entries.is_empty(), "escrow response has wrong shard, phase or representation");
        anyhow::ensure!(!response.raw_data.is_empty(), "escrow record is unavailable");
        quil_execution::token_intrinsic::escrow::decode_escrow_blob(&response.raw_data, &self.context, &address)
            .map_err(|e| anyhow::anyhow!("escrow response: {e}"))
    }

    /// Node-local selection hint only; the global commit decides. A spend is
    /// consumed once it commits through the global frame, so the hint reads the
    /// GLOBAL consumption record. Querying reveals that record's address to the
    /// RPC provider.
    pub(super) async fn is_unspent_hint(
        &self,
        client: &quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
        image: &[u8; IDENTITY_BYTES],
    ) -> anyhow::Result<bool> {
        let marker = quil_execution::token_intrinsic::spent::marker_address(&self.network, &self.application, image)?;
        let record = quil_execution::token_intrinsic::global_commit::consumed_address(&self.application, &marker)?;
        let (present, _) = self.global_record(client, &record).await?;
        // Any occupied record, including malformed or empty contents, is spent.
        Ok(!present)
    }

    /// Read one GLOBAL record: `(present, blob)`.
    async fn global_record(
        &self,
        client: &quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
        record: &[u8; 32],
    ) -> anyhow::Result<(bool, Vec<u8>)> {
        let mut address = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
        address.extend_from_slice(record);
        let response = client.clone().max_decoding_message_size(66_560)
            .get_vertex_data(quil_types::proto::node::GetVertexDataRequest { address, full_data: true })
            .await?.into_inner();
        Self::decode_global_record(response)
    }

    fn decode_global_record(response: quil_types::proto::node::GetVertexDataResponse) -> anyhow::Result<(bool, Vec<u8>)> {
        let global = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS;
        anyhow::ensure!(response.set_type == "vertex" && response.phase_type == "adds"
            && response.shard_l2 == global
            && response.shard_l1 == quil_hypergraph::addressing::get_bloom_filter_indices(&global, 256, 3)
            && response.entries.is_empty(), "global record response has wrong shard, phase or representation");
        let present = response.present.ok_or_else(|| anyhow::anyhow!("RPC does not report vertex presence"))?;
        anyhow::ensure!(present || response.raw_data.is_empty(), "absent record response contains data");
        Ok((present, response.raw_data))
    }

    /// Recover and authorize a claim from a content-addressed escrow record.
    /// The supplied global frame is only a preparation hint; consensus checks
    /// its own authenticated anchor and current consumption at admission.
    pub(super) fn prepare_pending_claim(
        &self,
        escrow_address: [u8; 32],
        escrow: &quil_execution::token_intrinsic::escrow::StoredEscrow,
        branch: quil_lattice_ct::confidential::pending_claim::ClaimBranch,
        global_frame: Option<u64>,
        signer: &dyn quil_types::crypto::Signer,
        recipients: &[(&RecipientAddress, u128)],
        fee: u128,
        max_outputs: usize,
    ) -> anyhow::Result<(
        quil_lattice_ct::confidential::pending_claim::PendingClaimStatement,
        [u8; 666],
        quil_lattice_ct::confidential::relation::CompiledAmountRelation,
    )> {
        use quil_lattice_ct::confidential::{memo::{create_output, open_escrow_recovery, EscrowRecoveryMemo},
            pending_claim::{ClaimBranch, PendingClaimStatement}, MAX_PRIVATE_COINS};
        anyhow::ensure!(!recipients.is_empty() && recipients.len() <= max_outputs.min(MAX_PRIVATE_COINS - 1), "claim outputs exceed configured limits");
        anyhow::ensure!(recipients.iter().all(|(address, _)| address.context() == &self.context), "recipient belongs to another network or application");
        anyhow::ensure!(self.application == quil_execution::domains::QUIL_TOKEN || fee == 0, "custom-token outflow cannot pay a QUIL fee");
        let (expected_address, _) = quil_execution::token_intrinsic::escrow::create_escrow(
            &self.context, escrow.frame_number, &escrow.output, &escrow.policy, &escrow.refund_recovery)?;
        anyhow::ensure!(expected_address == escrow_address, "escrow content address mismatch");
        let authority = match branch {
            ClaimBranch::Recipient => &escrow.policy.recipient,
            // Shards execute the refund at a GLOBAL anchor at least
            // `GLOBAL_ANCHOR_SAFETY_MARGIN` behind the head `global_frame`
            // came from, and skip it until that anchor reaches the deadline.
            // Judge the deadline there, so the wallet proves and submits it
            // only once the shards can admit it.
            ClaimBranch::Refund => escrow.policy.key_for_branch(branch,
                global_frame.ok_or_else(|| anyhow::anyhow!("refund preparation requires a global frame reference"))?
                    .saturating_sub(quil_execution::token_intrinsic::constants::GLOBAL_ANCHOR_SAFETY_MARGIN))
                .ok_or_else(|| anyhow::anyhow!("refund deadline has not been reached at the shards' anchor"))?,
        };
        anyhow::ensure!(signer.key_type() == quil_types::crypto::KeyType::Falcon512 && signer.public_key() == authority.as_slice(),
            "signer does not match selected escrow authority");
        let recipient_recovery = EscrowRecoveryMemo { owner: escrow.output.owner, ciphertext: escrow.output.memo };
        let recovery = match branch { ClaimBranch::Recipient => &recipient_recovery, ClaimBranch::Refund => &escrow.refund_recovery };
        let opened = open_escrow_recovery(&self.context, &self.kem_secret, &self.recipient, &escrow.output.commitment, recovery)
            .map_err(|e| anyhow::anyhow!("escrow recovery: {e:?}"))?;
        anyhow::ensure!(recipients.iter().try_fold(fee, |sum, (_, amount)| sum.checked_add(*amount)) == Some(opened.amount()),
            "escrow amount must equal outputs plus fee");
        let created = recipients.iter().map(|(address, amount)| create_output(&self.context, address, *amount))
            .collect::<Result<Vec<_>, _>>().map_err(|e| anyhow::anyhow!("claim output: {e:?}"))?;
        let statement = PendingClaimStatement { network: self.network, application: self.application,
            escrow_address, source: escrow.output.commitment.clone(), policy: escrow.policy.clone(), branch, fee,
            outputs: created.iter().map(|output| output.output.clone()).collect() };
        let canonical = statement.context_bytes().map_err(|e| anyhow::anyhow!("claim context: {e:?}"))?;
        let signature: [u8; 666] = signer.sign_with_domain(&canonical, &self.context)?.try_into()
            .map_err(|_| anyhow::anyhow!("invalid claim signature length"))?;
        anyhow::ensure!(quil_crypto::falcon_verify(authority, &signature, &canonical, &self.context), "claim signature did not verify");
        let openings: Vec<_> = recipients.iter().zip(&created).map(|((_, amount), output)| (*amount, &output.opening)).collect();
        let relation = statement.private_relation((opened.amount(), opened.opening()), &openings, max_outputs)
            .map_err(|e| anyhow::anyhow!("claim relation: {e:?}"))?;
        Ok((statement, signature, relation))
    }

    /// Prove off the async runtime and verify the finalized public statement.
    /// Source discovery, consensus eligibility and broadcast remain external.
    #[cfg(feature = "native-proof")]
    pub(super) async fn create_pending_claim(
        self: std::sync::Arc<Self>,
        escrow_address: [u8; 32],
        escrow: quil_execution::token_intrinsic::escrow::StoredEscrow,
        branch: quil_lattice_ct::confidential::pending_claim::ClaimBranch,
        global_frame: Option<u64>, signer: std::sync::Arc<dyn quil_types::crypto::Signer>,
        recipients: Vec<(RecipientAddress, u128)>, fee: u128, max_outputs: usize,
        budget: quil_lattice_ct::confidential::relation::backend::native::NativeBudget,
    ) -> anyhow::Result<Vec<u8>> {
        use quil_lattice_ct::confidential::{pending_claim::PendingClaim, relation::backend::native};
        let permit = PROVING.acquire().await?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let destinations: Vec<_> = recipients.iter().map(|(address, amount)| (address, *amount)).collect();
            let (statement, signature, relation) = self.prepare_pending_claim(escrow_address, &escrow, branch, global_frame,
                signer.as_ref(), &destinations, fee, max_outputs)?;
            let proof = native::prove(&relation, budget).map_err(|e| anyhow::anyhow!("claim proving: {e:?}"))?;
            drop(relation);
            let claim = PendingClaim { statement, signature, proof };
            let bytes = claim.encode().map_err(|e| anyhow::anyhow!("claim encoding: {e:?}"))?;
            let public = claim.statement.public_relation(max_outputs).map_err(|e| anyhow::anyhow!("claim public relation: {e:?}"))?;
            anyhow::ensure!(native::verify_owned(public, &claim.proof, budget).map_err(|e| anyhow::anyhow!("claim verification: {e:?}"))?,
                "generated claim failed public verification");
            Ok(bytes)
        }).await?
    }

    /// Fetch a historical authorization for the original mint and check its
    /// exact outputs before constructing the app-side claim. This neither
    /// broadcasts the claim nor establishes independent global finality.
    pub(super) async fn create_mint_claim(
        &self,
        client: &quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
        mint_bytes: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        use quil_execution::token_intrinsic::mint_authorization::{receipt_address, claim_from_witness};
        let mint = quil_lattice_ct::confidential::mint::Mint::decode(mint_bytes, &self.network, &self.application)
            .map_err(|e| anyhow::anyhow!("invalid original mint: {e:?}"))?;
        let receipt = receipt_address(&mint.statement)?;
        let response = client.clone().max_decoding_message_size(64 * 1024)
            .get_mint_authorization_witness(quil_types::proto::node::GetMintAuthorizationWitnessRequest {
                receipt: receipt.to_vec(),
            }).await?.into_inner();
        if response.found {
            println!("Mint claim cites global frame {}.", response.cited_frame);
        }
        let claim = claim_from_witness(&mint.statement, quil_types::store::MintAuthorizationWitnessData {
            found: response.found, forest_proof: response.forest_proof,
            cited_frame: response.cited_frame, global_root: response.global_root,
        })?;
        claim.encode().map_err(|e| anyhow::anyhow!("mint claim encoding: {e:?}"))
    }

    /// Discover one QUIL reward claim through bounded RPC data and verify its
    /// fields against the returned root before signing. The node supplies this
    /// root; consensus admission independently resolves the cited global frame.
    pub(super) async fn reward_claim(
        &self,
        client: &quil_types::proto::node::node_service_client::NodeServiceClient<
            tonic::transport::Channel,
        >,
        signer: &dyn quil_types::crypto::Signer,
    ) -> anyhow::Result<(
        u64,
        [u8; 32],
        quil_lattice_ct::confidential::mint::RewardClaim,
    )> {
        anyhow::ensure!(
            self.application == quil_execution::domains::QUIL_TOKEN,
            "reward discovery requires QUIL"
        );
        anyhow::ensure!(
            signer.key_type() == quil_types::crypto::KeyType::Falcon512,
            "reward discovery requires a Falcon signer"
        );
        let public_key: [u8; 897] = signer
            .public_key()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid claimant key length"))?;
        let owner = quil_crypto::poseidon::hash_bytes_to_32(&public_key)?;
        let response = client
            .clone()
            .max_decoding_message_size(64 * 1024)
            .get_prover_reward_witness(quil_types::proto::node::GetProverRewardWitnessRequest {
                domain: self.application.to_vec(),
                owner_prover_address: owner.to_vec(),
            })
            .await?
            .into_inner();
        Self::decode_reward_claim(public_key, response)
    }

    pub(super) fn decode_reward_claim(
        public_key: [u8; 897],
        response: quil_types::proto::node::GetProverRewardWitnessResponse,
    ) -> anyhow::Result<(
        u64,
        [u8; 32],
        quil_lattice_ct::confidential::mint::RewardClaim,
    )> {
        anyhow::ensure!(response.found, "no claimable prover reward found");
        let root: [u8; 32] = response
            .reward_root
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("reward witness lacks a checked root"))?;
        let value = u128::from_le_bytes(
            response
                .value
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid reward amount width"))?,
        );
        let owner = quil_crypto::poseidon::hash_bytes_to_32(&public_key)?;
        quil_execution::token_intrinsic::reward_witness::verify_reward_membership(
            &owner,
            value,
            &root,
            &response.forest_proof,
        )?;
        Ok((
            response.cited_frame,
            root,
            quil_lattice_ct::confidential::mint::RewardClaim {
                owner,
                value,
                public_key,
                forest_proof: response.forest_proof,
            },
        ))
    }

    /// Build a QUIL reward mint from explicit claims and their Falcon signers.
    /// Admission authenticates membership and current balances independently.
    /// Destinations plus fee must exhaust the claimed total; change is explicit.
    pub(super) fn prepare_mint(
        &self,
        cited_frame: u64,
        reward_root: [u8; 32],
        claims: &[quil_lattice_ct::confidential::mint::RewardClaim],
        signers: &[std::sync::Arc<dyn quil_types::crypto::Signer>],
        recipients: &[(RecipientAddress, u128)],
        fee: u128,
        max_claims: usize,
        max_outputs: usize,
    ) -> anyhow::Result<(
        quil_lattice_ct::confidential::mint::MintStatement,
        Vec<[u8; 666]>,
        quil_lattice_ct::confidential::relation::CompiledAmountRelation,
    )> {
        use quil_lattice_ct::confidential::{
            memo::create_output, mint::MintStatement, MAX_PRIVATE_COINS,
        };
        anyhow::ensure!(
            self.application == quil_execution::domains::QUIL_TOKEN,
            "custom-token mint policy is not integrated"
        );
        anyhow::ensure!(
            !claims.is_empty()
                && claims.len() <= max_claims.min(MAX_PRIVATE_COINS)
                && signers.len() == claims.len(),
            "mint claims or signers exceed configured limits"
        );
        anyhow::ensure!(
            !recipients.is_empty() && recipients.len() <= max_outputs.min(MAX_PRIVATE_COINS),
            "mint outputs exceed configured limits"
        );
        anyhow::ensure!(
            recipients.iter().all(|(a, _)| a.context() == &self.context),
            "recipient belongs to a different network or application"
        );
        for (claim, signer) in claims.iter().zip(signers) {
            anyhow::ensure!(
                signer.key_type() == quil_types::crypto::KeyType::Falcon512
                    && signer.public_key() == claim.public_key
                    && quil_crypto::poseidon::hash_bytes_to_32(&claim.public_key)? == claim.owner,
                "reward claimant does not match Falcon signer"
            );
        }
        let mut statement = MintStatement {
            network: self.network,
            application: self.application,
            cited_frame,
            reward_root,
            fee,
            claims: claims.to_vec(),
            outputs: Vec::new(),
        };
        let total = statement
            .total()
            .map_err(|e| anyhow::anyhow!("mint total: {e:?}"))?;
        anyhow::ensure!(
            recipients
                .iter()
                .try_fold(fee, |sum, (_, a)| sum.checked_add(*a))
                == Some(total),
            "reward claims must equal outputs plus fee"
        );
        let created = recipients
            .iter()
            .map(|(a, amount)| create_output(&self.context, a, *amount))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("mint output: {e:?}"))?;
        statement.outputs = created.iter().map(|o| o.output.clone()).collect();
        let context = statement
            .context_bytes()
            .map_err(|e| anyhow::anyhow!("mint context: {e:?}"))?;
        let signatures = signers
            .iter()
            .zip(claims)
            .map(|(signer, claim)| {
                let signature: [u8; 666] = signer
                    .sign_with_domain(&context, &self.context)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid claimant signature length"))?;
                anyhow::ensure!(
                    quil_crypto::falcon_verify(
                        &claim.public_key,
                        &signature,
                        &context,
                        &self.context
                    ),
                    "claimant signature did not verify"
                );
                Ok(signature)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let openings: Vec<_> = recipients
            .iter()
            .zip(&created)
            .map(|((_, a), o)| (*a, &o.opening))
            .collect();
        let relation = statement
            .private_relation(&openings, max_claims, max_outputs)
            .map_err(|e| anyhow::anyhow!("mint relation: {e:?}"))?;
        Ok((statement, signatures, relation))
    }

    /// Prove and independently verify a reward mint away from the async runtime.
    /// Claim discovery, authoritative admission and broadcast remain external.
    #[cfg(feature = "native-proof")]
    pub(super) async fn create_mint(
        self: std::sync::Arc<Self>,
        cited_frame: u64,
        reward_root: [u8; 32],
        claims: Vec<quil_lattice_ct::confidential::mint::RewardClaim>,
        signers: Vec<std::sync::Arc<dyn quil_types::crypto::Signer>>,
        recipients: Vec<(RecipientAddress, u128)>,
        fee: u128,
        max_claims: usize,
        max_outputs: usize,
        budget: quil_lattice_ct::confidential::relation::backend::native::NativeBudget,
    ) -> anyhow::Result<Vec<u8>> {
        use quil_lattice_ct::confidential::{mint::Mint, relation::backend::native};
        let permit = PROVING.acquire().await?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let (statement, signatures, relation) = self.prepare_mint(
                cited_frame,
                reward_root,
                &claims,
                &signers,
                &recipients,
                fee,
                max_claims,
                max_outputs,
            )?;
            let proof = native::prove(&relation, budget)
                .map_err(|e| anyhow::anyhow!("mint proving: {e:?}"))?;
            drop(relation);
            let mint = Mint {
                statement,
                signatures,
                proof,
            };
            let bytes = mint
                .encode()
                .map_err(|e| anyhow::anyhow!("mint encoding: {e:?}"))?;
            let public = mint
                .statement
                .public_relation(max_claims, max_outputs)
                .map_err(|e| anyhow::anyhow!("public mint relation: {e:?}"))?;
            anyhow::ensure!(
                native::verify_owned(public, &mint.proof, budget)
                    .map_err(|e| anyhow::anyhow!("mint verification: {e:?}"))?,
                "generated mint failed public verification"
            );
            Ok(bytes)
        })
        .await?
    }

    /// Build a custom-token (non-QUIL) issuance under the token's deployed mint
    /// policy. `authority` must be the configured authority for authority- or
    /// signature-policy tokens; `None` builds a permissionless statement for a
    /// free payment policy. Admission decides against the deployed configuration.
    #[cfg(feature = "native-proof")]
    pub(super) fn prepare_custom_mint(
        &self,
        authority: Option<&std::sync::Arc<dyn quil_types::crypto::Signer>>,
        recipients: &[(RecipientAddress, u128)],
        entitlement_proof: Vec<u8>,
        max_outputs: usize,
    ) -> anyhow::Result<(
        quil_lattice_ct::confidential::custom_mint::CustomMintStatement,
        Vec<u8>,
        quil_lattice_ct::confidential::relation::CompiledAmountRelation,
    )> {
        use quil_lattice_ct::confidential::{custom_mint::CustomMintStatement, memo::create_output, MAX_PRIVATE_COINS};
        use rand::RngCore;
        anyhow::ensure!(
            self.application != quil_execution::domains::QUIL_TOKEN,
            "QUIL issuance uses the reward mint"
        );
        // Mint authorities are post-quantum only, so a classical key cannot
        // sign a mint the network would admit; say so before proving it.
        if let Some(authority) = authority {
            anyhow::ensure!(
                quil_execution::token_intrinsic::signature::is_post_quantum_authority(authority.key_type() as u32),
                "mint authority keys must be post-quantum (Falcon-512)"
            );
        }
        anyhow::ensure!(
            !recipients.is_empty() && recipients.len() <= max_outputs.min(MAX_PRIVATE_COINS),
            "mint outputs exceed configured limits"
        );
        anyhow::ensure!(
            recipients.iter().all(|(a, _)| a.context() == &self.context),
            "recipient belongs to a different network or application"
        );
        let amount = recipients
            .iter()
            .try_fold(0u128, |sum, (_, a)| sum.checked_add(*a))
            .ok_or_else(|| anyhow::anyhow!("mint total overflows"))?;
        anyhow::ensure!(amount > 0 && recipients.iter().all(|(_, a)| *a > 0), "mint amounts must be positive");
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.try_fill_bytes(&mut nonce)?;
        let (authority_key_type, authority_public_key) = match authority {
            Some(signer) => (signer.key_type() as u32, signer.public_key().to_vec()),
            None => (0, Vec::new()),
        };
        let created = recipients
            .iter()
            .map(|(a, amount)| create_output(&self.context, a, *amount))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("mint output: {e:?}"))?;
        let statement = CustomMintStatement {
            network: self.network,
            application: self.application,
            authority_key_type,
            authority_public_key,
            nonce,
            amount,
            entitlement_proof,
            outputs: created.iter().map(|o| o.output.clone()).collect(),
        };
        let context = statement
            .context_bytes()
            .map_err(|e| anyhow::anyhow!("mint context: {e:?}"))?;
        let signature = match authority {
            Some(signer) => {
                let signature = signer.sign_with_domain(&context, &self.context)?;
                quil_execution::token_intrinsic::custom_mint::verify_authority_signature(
                    authority_key_type, &statement.authority_public_key, &context, &self.context, &signature,
                )
                .map_err(|e| anyhow::anyhow!("authority signature did not verify: {e}"))?;
                signature
            }
            None => Vec::new(),
        };
        let openings: Vec<_> = recipients
            .iter()
            .zip(&created)
            .map(|((_, a), o)| (*a, &o.opening))
            .collect();
        let relation = statement
            .private_relation(&openings, max_outputs)
            .map_err(|e| anyhow::anyhow!("mint relation: {e:?}"))?;
        Ok((statement, signature, relation))
    }

    /// Prove and independently verify a custom-token mint away from the async
    /// runtime. Policy lookup, authoritative admission and broadcast remain external.
    #[cfg(feature = "native-proof")]
    pub(super) async fn create_custom_mint(
        self: std::sync::Arc<Self>,
        authority: Option<std::sync::Arc<dyn quil_types::crypto::Signer>>,
        recipients: Vec<(RecipientAddress, u128)>,
        entitlement_proof: Vec<u8>,
        max_outputs: usize,
        budget: quil_lattice_ct::confidential::relation::backend::native::NativeBudget,
    ) -> anyhow::Result<Vec<u8>> {
        use quil_lattice_ct::confidential::{custom_mint::CustomMint, relation::backend::native};
        let permit = PROVING.acquire().await?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let (statement, signature, relation) =
                self.prepare_custom_mint(authority.as_ref(), &recipients, entitlement_proof, max_outputs)?;
            let proof = native::prove(&relation, budget)
                .map_err(|e| anyhow::anyhow!("custom mint proving: {e:?}"))?;
            drop(relation);
            let mint = CustomMint { statement, signature, proof };
            let bytes = mint
                .encode()
                .map_err(|e| anyhow::anyhow!("custom mint encoding: {e:?}"))?;
            let public = mint
                .statement
                .public_relation(max_outputs)
                .map_err(|e| anyhow::anyhow!("public custom mint relation: {e:?}"))?;
            anyhow::ensure!(
                native::verify_owned(public, &mint.proof, budget)
                    .map_err(|e| anyhow::anyhow!("custom mint verification: {e:?}"))?,
                "generated custom mint failed public verification"
            );
            Ok(bytes)
        })
        .await?
    }

    /// Construct and sign a shield from an explicitly selected transparent
    /// source. Admission must independently authenticate its value and owner.
    /// No implicit change output is created: destinations plus fee must match.
    pub(super) fn prepare_shield(
        &self,
        source: [u8; 32],
        amount: u128,
        signer: &dyn quil_types::crypto::Signer,
        recipients: &[(RecipientAddress, u128)],
        fee: u128,
        max_outputs: usize,
    ) -> anyhow::Result<(
        quil_lattice_ct::confidential::shield::ShieldStatement,
        [u8; 114],
        quil_lattice_ct::confidential::relation::CompiledAmountRelation,
    )> {
        use quil_lattice_ct::confidential::{
            memo::create_output, shield::ShieldStatement, MAX_PRIVATE_COINS,
        };
        anyhow::ensure!(
            signer.key_type() == quil_types::crypto::KeyType::Ed448,
            "transparent source requires an Ed448 owner"
        );
        let public = signer
            .public_key()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid source owner public key length"))?;
        anyhow::ensure!(
            !recipients.is_empty() && recipients.len() <= max_outputs.min(MAX_PRIVATE_COINS),
            "shield outputs exceed configured limits"
        );
        anyhow::ensure!(
            recipients.iter().all(|(a, _)| a.context() == &self.context),
            "recipient belongs to a different network or application"
        );
        // A single public source cannot fund a sum above u128::MAX.
        let total = recipients
            .iter()
            .try_fold(fee, |sum, (_, a)| sum.checked_add(*a));
        anyhow::ensure!(total == Some(amount), "source must equal outputs plus fee");
        let created = recipients
            .iter()
            .map(|(a, amount)| create_output(&self.context, a, *amount))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("shield output: {e:?}"))?;
        let statement = ShieldStatement {
            network: self.network,
            application: self.application,
            transparent_address: source,
            owner_public_key: public,
            amount,
            fee,
            outputs: created.iter().map(|o| o.output.clone()).collect(),
        };
        let context = statement
            .context_bytes()
            .map_err(|e| anyhow::anyhow!("shield context: {e:?}"))?;
        let signature: [u8; 114] = signer
            .sign(&context)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid source owner signature length"))?;
        anyhow::ensure!(
            quil_crypto::ed448_verify(&public, &context, &signature),
            "source owner signature did not verify"
        );
        let openings: Vec<_> = recipients
            .iter()
            .zip(&created)
            .map(|((_, a), o)| (*a, &o.opening))
            .collect();
        let relation = statement
            .private_relation(&openings, max_outputs)
            .map_err(|e| anyhow::anyhow!("shield relation: {e:?}"))?;
        Ok((statement, signature, relation))
    }

    /// Prove off the async runtime and independently verify the public statement.
    /// Returns bounded wire bytes; source admission and broadcast are external.
    #[cfg(feature = "native-proof")]
    pub(super) async fn create_shield(
        self: std::sync::Arc<Self>,
        source: [u8; 32],
        amount: u128,
        signer: std::sync::Arc<dyn quil_types::crypto::Signer>,
        recipients: Vec<(RecipientAddress, u128)>,
        fee: u128,
        max_outputs: usize,
        budget: quil_lattice_ct::confidential::relation::backend::native::NativeBudget,
    ) -> anyhow::Result<Vec<u8>> {
        use quil_lattice_ct::confidential::{relation::backend::native, shield::Shield};
        let permit = PROVING.acquire().await?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let (statement, signature, relation) = self.prepare_shield(
                source,
                amount,
                signer.as_ref(),
                &recipients,
                fee,
                max_outputs,
            )?;
            let proof = native::prove(&relation, budget)
                .map_err(|e| anyhow::anyhow!("shield proving: {e:?}"))?;
            drop(relation);
            let shield = Shield {
                statement,
                signature,
                proof,
            };
            let bytes = shield
                .encode()
                .map_err(|e| anyhow::anyhow!("shield encoding: {e:?}"))?;
            let public = shield
                .statement
                .public_relation(max_outputs)
                .map_err(|e| anyhow::anyhow!("public shield relation: {e:?}"))?;
            anyhow::ensure!(
                native::verify_owned(public, &shield.proof, budget)
                    .map_err(|e| anyhow::anyhow!("shield verification: {e:?}"))?,
                "generated shield failed public verification"
            );
            Ok(bytes)
        })
        .await?
    }

    /// A batch shield's statement, the owner's signature over it and the
    /// private relation: many legacy coins of one owner, one proof over their
    /// total. `sources` must ascend by address.
    pub(super) fn prepare_batch_shield(
        &self,
        sources: Vec<quil_lattice_ct::confidential::shield::ShieldSource>,
        signer: &dyn quil_types::crypto::Signer,
        recipients: &[(RecipientAddress, u128)],
        fee: u128,
        max_outputs: usize,
    ) -> anyhow::Result<(
        quil_lattice_ct::confidential::shield::BatchShieldStatement,
        [u8; 114],
        quil_lattice_ct::confidential::relation::CompiledAmountRelation,
    )> {
        use quil_lattice_ct::confidential::{memo::create_output, shield::BatchShieldStatement, MAX_PRIVATE_COINS};
        anyhow::ensure!(signer.key_type() == quil_types::crypto::KeyType::Ed448, "transparent sources require an Ed448 owner");
        let public = signer.public_key().try_into()
            .map_err(|_| anyhow::anyhow!("invalid source owner public key length"))?;
        anyhow::ensure!(
            !recipients.is_empty() && recipients.len() <= max_outputs.min(MAX_PRIVATE_COINS),
            "shield outputs exceed configured limits"
        );
        anyhow::ensure!(recipients.iter().all(|(a, _)| a.context() == &self.context),
            "recipient belongs to a different network or application");
        let total = sources.iter().try_fold(0u128, |sum, source| sum.checked_add(source.amount))
            .ok_or_else(|| anyhow::anyhow!("legacy sources overflow u128"))?;
        let spent = recipients.iter().try_fold(fee, |sum, (_, a)| sum.checked_add(*a));
        anyhow::ensure!(spent == Some(total), "sources must equal outputs plus fee");
        let created = recipients.iter()
            .map(|(a, amount)| create_output(&self.context, a, *amount))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("shield output: {e:?}"))?;
        let statement = BatchShieldStatement {
            network: self.network,
            application: self.application,
            owner_public_key: public,
            sources,
            fee,
            outputs: created.iter().map(|o| o.output.clone()).collect(),
        };
        let context = statement.context_bytes().map_err(|e| anyhow::anyhow!("batch shield context: {e:?}"))?;
        let signature: [u8; 114] = signer.sign(&context)?.try_into()
            .map_err(|_| anyhow::anyhow!("invalid source owner signature length"))?;
        anyhow::ensure!(quil_crypto::ed448_verify(&public, &context, &signature), "source owner signature did not verify");
        let openings: Vec<_> = recipients.iter().zip(&created).map(|((_, a), o)| (*a, &o.opening)).collect();
        let relation = statement.private_relation(&openings, max_outputs)
            .map_err(|e| anyhow::anyhow!("batch shield relation: {e:?}"))?;
        Ok((statement, signature, relation))
    }

    /// [`Self::create_shield`] for a batch: prove off the async runtime and
    /// verify the public statement before returning wire bytes.
    #[cfg(feature = "native-proof")]
    pub(super) async fn create_batch_shield(
        self: std::sync::Arc<Self>,
        sources: Vec<quil_lattice_ct::confidential::shield::ShieldSource>,
        signer: std::sync::Arc<dyn quil_types::crypto::Signer>,
        recipients: Vec<(RecipientAddress, u128)>,
        fee: u128,
        max_outputs: usize,
        budget: quil_lattice_ct::confidential::relation::backend::native::NativeBudget,
    ) -> anyhow::Result<Vec<u8>> {
        use quil_lattice_ct::confidential::{relation::backend::native, shield::BatchShield};
        let permit = PROVING.acquire().await?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let (statement, signature, relation) =
                self.prepare_batch_shield(sources, signer.as_ref(), &recipients, fee, max_outputs)?;
            let proof = native::prove(&relation, budget).map_err(|e| anyhow::anyhow!("batch shield proving: {e:?}"))?;
            drop(relation);
            let shield = BatchShield { statement, signature, proof };
            let bytes = shield.encode().map_err(|e| anyhow::anyhow!("batch shield encoding: {e:?}"))?;
            let public = shield.statement.public_relation(max_outputs)
                .map_err(|e| anyhow::anyhow!("public batch shield relation: {e:?}"))?;
            anyhow::ensure!(
                native::verify_owned(public, &shield.proof, budget).map_err(|e| anyhow::anyhow!("batch shield verification: {e:?}"))?,
                "generated batch shield failed public verification"
            );
            Ok(bytes)
        })
        .await?
    }

    /// Build through authenticated RPC paths, prepare and prove off the async runtime,
    /// and verify from the finalized public statement before returning wire bytes.
    /// The caller still needs network admission; this does not broadcast.
    #[cfg(feature = "native-proof")]
    pub(super) async fn create_transfer(
        self: std::sync::Arc<Self>,
        client: &quil_types::proto::node::node_service_client::NodeServiceClient<
            tonic::transport::Channel,
        >,
        coins: Vec<([u8; 32], Output)>,
        recipients: Vec<(RecipientAddress, u128)>,
        fee: u128,
        limits: quil_lattice_ct::confidential::transfer::CompileLimits,
        budget: quil_lattice_ct::confidential::relation::backend::native::NativeBudget,
    ) -> anyhow::Result<Vec<u8>> {
        use quil_lattice_ct::confidential::{relation::backend::native, transfer::Transfer};
        // Native calls serialize internally, but waiting after compilation would
        // let concurrent requests retain multiple large private relations. Hold
        // this permit through the worker, even if its async caller is cancelled.
        let permit = PROVING.acquire().await?;
        let selected: Vec<_> = coins
            .iter()
            .map(|(address, output)| (*address, output))
            .collect();
        let (root, paths) = self.witnesses(client, &selected).await?;
        drop(selected);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let selected: Vec<_> = coins
                .iter()
                .map(|(address, output)| (*address, output))
                .collect();
            let destinations: Vec<_> = recipients
                .iter()
                .map(|(address, amount)| (address, *amount))
                .collect();
            #[cfg(test)]
            let phase = std::time::Instant::now();
            let (statement, relation) =
                self.prepare_transfer(&selected, &root, &paths, &destinations, fee, limits)?;
            #[cfg(test)]
            eprintln!("wallet_transfer_phase phase=private_relation seconds={:.6}", phase.elapsed().as_secs_f64());
            #[cfg(test)]
            let phase = std::time::Instant::now();
            let proof = native::prove(&relation, budget)
                .map_err(|e| anyhow::anyhow!("transfer proving: {e:?}"))?;
            #[cfg(test)]
            eprintln!("wallet_transfer_phase phase=native_prove_including_submission seconds={:.6}", phase.elapsed().as_secs_f64());
            // Free the private compiler witness before allocating public verification state.
            drop(relation);
            let transfer = Transfer { statement, proof };
            let bytes = transfer
                .encode()
                .map_err(|e| anyhow::anyhow!("transfer encoding: {e:?}"))?;
            #[cfg(test)]
            let phase = std::time::Instant::now();
            let public = transfer
                .statement
                .public_relation(limits)
                .map_err(|e| anyhow::anyhow!("public transfer relation: {e:?}"))?;
            #[cfg(test)]
            eprintln!("wallet_transfer_phase phase=public_relation seconds={:.6}", phase.elapsed().as_secs_f64());
            #[cfg(test)]
            let phase = std::time::Instant::now();
            let valid = native::verify_owned(public, &transfer.proof, budget)
                .map_err(|e| anyhow::anyhow!("transfer verification: {e:?}"))?;
            #[cfg(test)]
            eprintln!("wallet_transfer_phase phase=native_verify_including_submission seconds={:.6}", phase.elapsed().as_secs_f64());
            anyhow::ensure!(valid, "generated transfer failed public verification");
            Ok(bytes)
        })
        .await?
    }

    /// Recover selected notes and construct the finalized statement and private
    /// relation. Root retention, spent images and fee policy remain admission
    /// decisions; callers must obtain paths through the authenticated witness API.
    pub(super) fn prepare_transfer(
        &self,
        coins: &[([u8; 32], &Output)],
        root: &quil_lattice_ct::confidential::coin_tree::RootRecord,
        paths: &[quil_lattice_ct::confidential::coin_tree::AuthPath],
        recipients: &[(&RecipientAddress, u128)],
        fee: u128,
        limits: quil_lattice_ct::confidential::transfer::CompileLimits,
    ) -> anyhow::Result<(
        quil_lattice_ct::confidential::transfer::TransferStatement,
        quil_lattice_ct::confidential::relation::CompiledAmountRelation,
    )> {
        self.prepare_funding(coins, root, paths, recipients, fee, limits, None, None)
            .map(|(statement, relation, _)| (statement, relation))
    }

    /// Reuse transfer ownership/membership and conservation, with one escrow
    /// output followed by change. Bind policy and both recovery records before
    /// proving; the escrow output must never become an ordinary stored coin.
    pub(super) fn prepare_pending_create(
        &self,
        coins: &[([u8; 32], &Output)],
        root: &quil_lattice_ct::confidential::coin_tree::RootRecord,
        paths: &[quil_lattice_ct::confidential::coin_tree::AuthPath],
        escrow: &EscrowDestination,
        change: &[(&RecipientAddress, u128)],
        fee: u128,
        limits: quil_lattice_ct::confidential::transfer::CompileLimits,
    ) -> anyhow::Result<(
        quil_lattice_ct::confidential::pending_create::PendingCreateStatement,
        quil_lattice_ct::confidential::relation::CompiledAmountRelation,
    )> {
        anyhow::ensure!(escrow.refund.context() == &self.context, "refund address belongs to another network or application");
        anyhow::ensure!(self.application == quil_execution::domains::QUIL_TOKEN || fee == 0, "custom-token outflow cannot pay a QUIL fee");
        anyhow::ensure!(change.len() < limits.max_outputs.min(quil_lattice_ct::confidential::MAX_PRIVATE_COINS),
            "pending outputs exceed configured limits");
        let mut recipients = Vec::with_capacity(change.len().saturating_add(1));
        recipients.push((&escrow.recipient, escrow.amount)); recipients.extend_from_slice(change);
        let (funding, relation, recovery) = self.prepare_funding(coins, root, paths, &recipients, fee, limits, Some(&escrow.refund), None)?;
        let statement = quil_lattice_ct::confidential::pending_create::PendingCreateStatement {
            funding, policy: escrow.policy.clone(),
            refund_recovery: recovery.ok_or_else(|| anyhow::anyhow!("missing refund recovery"))?,
        };
        let context = statement.context_bytes().map_err(|e| anyhow::anyhow!("pending funding context: {e:?}"))?;
        Ok((statement, relation.with_transaction_context(&context)))
    }

    #[cfg(feature = "native-proof")]
    pub(super) async fn create_pending(
        self: std::sync::Arc<Self>,
        client: &quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
        coins: Vec<([u8; 32], Output)>, escrow: EscrowDestination,
        change: Vec<(RecipientAddress, u128)>, fee: u128,
        limits: quil_lattice_ct::confidential::transfer::CompileLimits,
        budget: quil_lattice_ct::confidential::relation::backend::native::NativeBudget,
    ) -> anyhow::Result<Vec<u8>> {
        use quil_lattice_ct::confidential::{pending_create::PendingCreate, relation::backend::native};
        let permit = PROVING.acquire().await?;
        let selected: Vec<_> = coins.iter().map(|(address, output)| (*address, output)).collect();
        let (root, paths) = self.witnesses(client, &selected).await?;
        drop(selected);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let selected: Vec<_> = coins.iter().map(|(address, output)| (*address, output)).collect();
            let change: Vec<_> = change.iter().map(|(address, amount)| (address, *amount)).collect();
            let (statement, relation) = self.prepare_pending_create(&selected, &root, &paths, &escrow, &change, fee, limits)?;
            let proof = native::prove(&relation, budget).map_err(|e| anyhow::anyhow!("pending funding proving: {e:?}"))?;
            drop(relation);
            let tx = PendingCreate { statement, proof };
            let bytes = tx.encode().map_err(|e| anyhow::anyhow!("pending funding encoding: {e:?}"))?;
            let public = tx.statement.public_relation(limits).map_err(|e| anyhow::anyhow!("pending funding public relation: {e:?}"))?;
            anyhow::ensure!(native::verify_owned(public, &tx.proof, budget).map_err(|e| anyhow::anyhow!("pending funding verification: {e:?}"))?,
                "generated pending funding failed public verification");
            Ok(bytes)
        }).await?
    }

    /// Spend selected QUIL coins into a cross-domain settlement: the public
    /// outflow is this operation's fee plus `settlement`, which only
    /// `destination` may consume, once, in the bundle `binding` names — the
    /// bundle's own SHA3, or the claimant key that names one later.
    /// Change (possibly zero) returns to this wallet.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_settlement(
        &self,
        coins: &[([u8; 32], &Output)],
        root: &quil_lattice_ct::confidential::coin_tree::RootRecord,
        paths: &[quil_lattice_ct::confidential::coin_tree::AuthPath],
        change: u128, fee: u128, settlement: u128,
        destination: [u8; 32], binding: &SettlementBinding,
        payment: Option<(RecipientAddress, [u8; 32], u128)>,
        limits: quil_lattice_ct::confidential::transfer::CompileLimits,
    ) -> anyhow::Result<(
        quil_lattice_ct::confidential::settlement::SettlementStatement,
        quil_lattice_ct::confidential::relation::CompiledAmountRelation,
    )> {
        anyhow::ensure!(self.application == quil_execution::domains::QUIL_TOKEN, "settlements spend QUIL");
        let outflow = fee.checked_add(settlement).ok_or_else(|| anyhow::anyhow!("settlement exceeds the token amount range"))?;
        let own = self.address().clone();
        let mut recipients: Vec<(&RecipientAddress, u128)> = Vec::with_capacity(2);
        if let Some((payee, _, value)) = &payment {
            recipients.push((payee, *value));
        }
        recipients.push((&own, change));
        let (funding, relation, _) = self.prepare_funding(coins, root, paths, &recipients, outflow, limits, None,
            payment.as_ref().map(|(_, nonce, _)| *nonce))?;
        let statement = quil_lattice_ct::confidential::settlement::SettlementStatement {
            funding, fee, settlement, destination, context: binding.context(), claimant: binding.claimant(),
            payment: payment.map(|(payee, nonce, value)| quil_lattice_ct::confidential::settlement::Payment { payee, nonce, value }),
        };
        statement.check_payment().map_err(|e| anyhow::anyhow!("payment coin: {e:?}"))?;
        let bound = statement.context_bytes().map_err(|e| anyhow::anyhow!("settlement context: {e:?}"))?;
        Ok((statement, relation.with_transaction_context(&bound)))
    }

    #[cfg(feature = "native-proof")]
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn create_settlement(
        self: std::sync::Arc<Self>,
        client: &quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
        coins: Vec<([u8; 32], Output)>, change: u128, fee: u128, settlement: u128,
        destination: [u8; 32], binding: SettlementBinding,
        payment: Option<(RecipientAddress, [u8; 32], u128)>,
        limits: quil_lattice_ct::confidential::transfer::CompileLimits,
        budget: quil_lattice_ct::confidential::relation::backend::native::NativeBudget,
    ) -> anyhow::Result<Vec<u8>> {
        use quil_lattice_ct::confidential::{relation::backend::native, settlement::Settlement};
        let permit = PROVING.acquire().await?;
        let selected: Vec<_> = coins.iter().map(|(address, output)| (*address, output)).collect();
        let (root, paths) = self.witnesses(client, &selected).await?;
        drop(selected);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let selected: Vec<_> = coins.iter().map(|(address, output)| (*address, output)).collect();
            let (statement, relation) = self.prepare_settlement(
                &selected, &root, &paths, change, fee, settlement, destination, &binding, payment, limits,
            )?;
            let proof = native::prove(&relation, budget).map_err(|e| anyhow::anyhow!("settlement proving: {e:?}"))?;
            drop(relation);
            let tx = Settlement { statement, proof };
            let bytes = tx.encode().map_err(|e| anyhow::anyhow!("settlement encoding: {e:?}"))?;
            let public = tx.statement.public_relation(limits).map_err(|e| anyhow::anyhow!("settlement public relation: {e:?}"))?;
            anyhow::ensure!(native::verify_owned(public, &tx.proof, budget).map_err(|e| anyhow::anyhow!("settlement verification: {e:?}"))?,
                "generated settlement failed public verification");
            Ok(bytes)
        }).await?
    }

    fn prepare_funding(
        &self,
        coins: &[([u8; 32], &Output)],
        root: &quil_lattice_ct::confidential::coin_tree::RootRecord,
        paths: &[quil_lattice_ct::confidential::coin_tree::AuthPath],
        recipients: &[(&RecipientAddress, u128)], fee: u128,
        limits: quil_lattice_ct::confidential::transfer::CompileLimits,
        escrow_refund: Option<&RecipientAddress>,
        payment_nonce: Option<[u8; 32]>,
    ) -> anyhow::Result<(
        quil_lattice_ct::confidential::transfer::TransferStatement,
        quil_lattice_ct::confidential::relation::CompiledAmountRelation,
        Option<quil_lattice_ct::confidential::memo::EscrowRecoveryMemo>,
    )> {
        use quil_lattice_ct::confidential::{
            memo::create_output,
            relation::membership::{InputPath, MembershipKey, MAX_DEPTH},
            transfer::TransferStatement,
            MAX_PRIVATE_COINS,
        };
        anyhow::ensure!(root.context == self.context, "root context mismatch");
        anyhow::ensure!(
            !coins.is_empty()
                && coins.len() <= limits.max_inputs
                && coins.len() <= MAX_PRIVATE_COINS
                && paths.len() == coins.len()
                && !recipients.is_empty()
                && recipients.len() <= limits.max_outputs
                && recipients.len() <= MAX_PRIVATE_COINS
                && root.depth > 0
                && usize::from(root.depth) <= limits.max_depth.min(MAX_DEPTH),
            "transfer dimensions exceed configured limits"
        );
        anyhow::ensure!(
            coins
                .iter()
                .map(|(address, _)| address)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == coins.len(),
            "duplicate selected coins"
        );
        anyhow::ensure!(
            recipients
                .iter()
                .all(|(address, _)| address.context() == &self.context),
            "recipient belongs to a different network or application"
        );
        // Each memo authenticates both the commitment and recipient owner before
        // returning the secret witness. No sender-supplied spend secret is used.
        let opened = coins
            .iter()
            .map(|(_, output)| self.open(output))
            .collect::<anyhow::Result<Vec<_>>>()?;
        // Totals may exceed u128 even though each individual amount cannot.
        // The bounded number of notes fits in two u128 limbs. Clear aggregate
        // amounts on drop instead of allocating secret BigUint temporaries.
        fn total(amounts: impl Iterator<Item = u128>) -> Zeroizing<[u128; 2]> {
            let mut sum = Zeroizing::new([0u128; 2]);
            for amount in amounts {
                let (low, carry) = sum[0].overflowing_add(amount);
                sum[0] = low;
                sum[1] += u128::from(carry);
            }
            sum
        }
        let input_total = total(opened.iter().map(|coin| coin.amount));
        let output_total = total(
            recipients
                .iter()
                .map(|(_, amount)| *amount)
                .chain(std::iter::once(fee)),
        );
        anyhow::ensure!(
            input_total == output_total,
            "inputs must equal outputs plus fee"
        );
        let key = MembershipKey::derive(&self.context);
        let images = opened
            .iter()
            .map(|coin| {
                key.key_image(&coin.secrets.owner)
                    .identity_bytes()
                    .map_err(|e| anyhow::anyhow!("input image: {e:?}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let mut refund_recovery = None;
        let created = recipients
            .iter()
            .enumerate()
            .map(|(index, (address, amount))| {
                if let Some(refund) = escrow_refund.filter(|_| index == 0) {
                    use quil_lattice_ct::confidential::memo::{create_escrow_recovery, CreatedOutput};
                    let escrow = create_escrow_recovery(&self.context, address, refund, *amount)
                        .map_err(|e| anyhow::anyhow!("escrow recovery creation: {e:?}"))?;
                    refund_recovery = Some(escrow.refund);
                    return Ok(CreatedOutput { opening: escrow.opening, output: Output {
                        commitment: escrow.commitment, owner: escrow.recipient.owner, memo: escrow.recipient.ciphertext,
                    }});
                }
                if let Some(nonce) = payment_nonce.filter(|_| index == 0) {
                    // A public payment coin: its nonce is published with the
                    // settlement so the payee's coin can be checked by anyone.
                    return quil_lattice_ct::confidential::memo::create_output_with_nonce(&self.context, address, *amount, &nonce)
                        .map_err(|e| anyhow::anyhow!("payment output: {e:?}"));
                }
                create_output(&self.context, address, *amount)
                    .map_err(|e| anyhow::anyhow!("recipient output: {e:?}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let statement = TransferStatement {
            network: self.network,
            application: self.application,
            depth: root.depth,
            root: root.root.clone(),
            images,
            outputs: created.iter().map(|coin| coin.output.clone()).collect(),
            fee,
        };
        let input_witness: Vec<_> = opened
            .iter()
            .zip(coins)
            .map(|(coin, (_, output))| (coin.amount, &coin.secrets.opening, &output.commitment))
            .collect();
        let output_witness: Vec<_> = recipients
            .iter()
            .zip(&created)
            .map(|((_, amount), coin)| (*amount, &coin.opening))
            .collect();
        let input_paths: Vec<_> = opened
            .iter()
            .zip(paths)
            .map(|(coin, path)| InputPath {
                owner: &coin.secrets.owner,
                siblings: &path.siblings,
                right: &path.right,
            })
            .collect();
        let relation = statement
            .private_relation(&input_witness, &output_witness, &input_paths, limits)
            .map_err(|e| anyhow::anyhow!("transfer witness: {e:?}"))?;
        Ok((statement, relation, refund_recovery))
    }

    pub(super) async fn scan_next(
        &self,
        client: &quil_types::proto::node::node_service_client::NodeServiceClient<
            tonic::transport::Channel,
        >,
        scan: &mut CoinScan,
    ) -> anyhow::Result<Vec<([u8; 32], Output)>> {
        anyhow::ensure!(
            !scan.finished && scan.remaining_pages > 0,
            "scan ended or page budget exhausted"
        );
        let response = client
            .clone()
            .max_decoding_message_size(256 * 1024)
            .list_coins(quil_types::proto::node::ListCoinsRequest {
                domain: self.application.to_vec(),
                snapshot_id: scan.snapshot_id.map(|id| id.to_vec()).unwrap_or_default(),
                after: scan.after.map(|id| id.to_vec()).unwrap_or_default(),
            })
            .await?
            .into_inner();
        self.decode_scan_page(scan, response)
    }

    fn recover_page(&self, page: Vec<([u8; 32], Output)>) -> anyhow::Result<Vec<OwnedCoin>> {
        use quil_lattice_ct::confidential::{memo::MemoError, relation::membership::MembershipKey};
        let key = MembershipKey::derive(&self.context);
        let mut owned = Vec::new();
        for (address, output) in page {
            let opened = match open_output(&self.context, &self.kem_secret, &self.recipient, &output) {
                Ok(opened) => opened,
                Err(MemoError::Authentication) => continue,
                Err(error) => anyhow::bail!("coin recovery: {error:?}"),
            };
            let image = key.key_image(&opened.secrets.owner).identity_bytes()
                .map_err(|e| anyhow::anyhow!("coin image: {e:?}"))?;
            owned.push(OwnedCoin { address, output, amount: Zeroizing::new(opened.amount), image });
        }
        Ok(owned)
    }

    /// Complete bounded scan. Errors discard partial results. The RPC provider
    /// observes queried markers; these are node-local, current-state hints.
    pub(super) async fn scan_unspent(
        self: std::sync::Arc<Self>,
        client: &quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
        max_pages: usize, max_owned: usize,
    ) -> anyhow::Result<Vec<OwnedCoin>> {
        anyhow::ensure!(max_owned > 0, "owned coin limit must be positive");
        let mut scan = CoinScan::new(max_pages)?;
        let mut unspent = Vec::new();
        while !scan.finished() {
            let page = self.scan_next(client, &mut scan).await?;
            let wallet = self.clone();
            let owned = tokio::task::spawn_blocking(move || wallet.recover_page(page)).await??;
            for coin in owned {
                if self.is_unspent_hint(client, &coin.image).await? {
                    anyhow::ensure!(unspent.len() < max_owned, "owned coin limit exceeded; scan incomplete");
                    unspent.push(coin);
                }
            }
        }
        Ok(unspent)
    }

    fn decode_escrow_page(
        &self,
        scan: &mut CoinScan,
        response: quil_types::proto::node::ListEscrowsResponse,
    ) -> anyhow::Result<Vec<([u8; 32], quil_execution::token_intrinsic::escrow::StoredEscrow)>> {
        anyhow::ensure!(!scan.finished && scan.remaining_pages > 0, "scan ended or page budget exhausted");
        anyhow::ensure!(prost::Message::encoded_len(&response) <= 256 * 1024, "escrow page exceeds size limit");
        anyhow::ensure!(response.network.as_slice() == self.network, "scan network mismatch");
        let id: [u8; 32] = response.snapshot_id.try_into().map_err(|_| anyhow::anyhow!("invalid scan identity"))?;
        anyhow::ensure!(scan.snapshot_id.is_none_or(|old| old == id), "scan snapshot changed");
        let cursor = if response.cursor.is_empty() { None } else {
            Some(<[u8; 32]>::try_from(response.cursor).map_err(|_| anyhow::anyhow!("invalid scan cursor"))?)
        };
        anyhow::ensure!(response.escrows.len() <= 8 && cursor >= scan.after
            && (!response.has_more || (cursor.is_some() && cursor > scan.after)), "invalid scan progress");
        let mut previous = scan.after;
        let mut escrows = Vec::new();
        for escrow in response.escrows {
            let address: [u8; 32] = escrow.address.try_into().map_err(|_| anyhow::anyhow!("invalid escrow address"))?;
            anyhow::ensure!(previous.is_none_or(|old| address > old) && cursor.is_some_and(|end| address <= end), "invalid escrow order");
            let stored = quil_execution::token_intrinsic::escrow::decode_escrow_blob(&escrow.raw_data, &self.context, &address)?;
            escrows.push((address, stored));
            previous = Some(address);
        }
        // Commit continuation only after every record has passed validation.
        scan.snapshot_id = Some(id);
        scan.after = cursor;
        scan.remaining_pages -= 1;
        scan.finished = !response.has_more;
        Ok(escrows)
    }

    pub(super) async fn scan_escrows(
        self: std::sync::Arc<Self>,
        client: &quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
        authority: Vec<u8>, max_pages: usize, max_owned: usize,
    ) -> anyhow::Result<Vec<([u8; 32], Zeroizing<u128>, bool, u64)>> {
        use quil_lattice_ct::confidential::memo::{open_escrow_recovery, EscrowRecoveryMemo};
        anyhow::ensure!(max_owned > 0, "owned escrow limit must be positive");
        let mut scan = CoinScan::new(max_pages)?;
        let mut owned = Vec::new();
        while !scan.finished() {
            anyhow::ensure!(scan.remaining_pages > 0, "escrow scan page budget exhausted");
            let response = client.clone().max_decoding_message_size(256 * 1024)
                .list_escrows(quil_types::proto::node::ListCoinsRequest {
                    domain: self.application.to_vec(), snapshot_id: scan.snapshot_id.map(|id| id.to_vec()).unwrap_or_default(),
                    after: scan.after.map(|id| id.to_vec()).unwrap_or_default(),
                }).await?.into_inner();
            let wallet = self.clone();
            let authority = authority.clone();
            let (next_scan, recovered) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                let page = wallet.decode_escrow_page(&mut scan, response)?;
                let mut recovered = Vec::new();
                for (address, escrow) in page {
                    for refund in [false, true] {
                        let key = if refund { &escrow.policy.refund } else { &escrow.policy.recipient };
                        if key.as_slice() != authority { continue; }
                        let recipient = EscrowRecoveryMemo { owner: escrow.output.owner, ciphertext: escrow.output.memo };
                        let memo = if refund { &escrow.refund_recovery } else { &recipient };
                        if let Ok(opened) = open_escrow_recovery(&wallet.context, &wallet.kem_secret, &wallet.recipient, &escrow.output.commitment, memo) {
                            recovered.push((address, Zeroizing::new(opened.amount()), refund, escrow.policy.refund_after_global_frame));
                        }
                    }
                }
                Ok((scan, recovered))
            }).await??;
            scan = next_scan;
            for escrow in recovered {
                // Open only if the global commit holds it unconsumed: an escrow
                // whose creation never committed has no record at all.
                let record = quil_execution::token_intrinsic::global_commit::escrow_address(&self.application, &escrow.0)?;
                let (present, blob) = self.global_record(client, &record).await?;
                let open = present && !quil_execution::token_intrinsic::global_commit::parse_escrow_record(&blob)
                    .map_err(|e| anyhow::anyhow!("escrow record: {e}"))?.2;
                if open {
                    anyhow::ensure!(owned.len() < max_owned, "owned escrow limit exceeded; scan incomplete");
                    owned.push(escrow);
                }
            }
        }
        Ok(owned)
    }

    fn decode_scan_page(
        &self,
        scan: &mut CoinScan,
        response: quil_types::proto::node::ListCoinsResponse,
    ) -> anyhow::Result<Vec<([u8; 32], Output)>> {
        use quil_lattice_ct::confidential::{coin_tree::RootRecord, AmountCommitment};
        anyhow::ensure!(
            !scan.finished && scan.remaining_pages > 0,
            "scan ended or page budget exhausted"
        );
        anyhow::ensure!(
            prost::Message::encoded_len(&response) <= 256 * 1024,
            "scan response exceeds size limit"
        );
        anyhow::ensure!(
            response.network.as_slice() == self.network,
            "scan network mismatch"
        );
        let id: [u8; 32] = response
            .snapshot_id
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid scan identity"))?;
        anyhow::ensure!(
            scan.snapshot_id.is_none_or(|old| old == id),
            "scan snapshot changed"
        );
        let root = RootRecord::decode(&response.root_record, &self.context)
            .map_err(|e| anyhow::anyhow!("scan root: {e:?}"))?;
        anyhow::ensure!(
            scan.root.as_ref().is_none_or(|old| old == &root),
            "scan root changed"
        );
        let cursor: Option<[u8; 32]> = if response.cursor.is_empty() {
            None
        } else {
            Some(
                response
                    .cursor
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid scan cursor"))?,
            )
        };
        anyhow::ensure!(
            response.coins.len() <= 8
                && cursor >= scan.after
                && (!response.has_more || (cursor.is_some() && cursor > scan.after)),
            "invalid scan progress"
        );
        let mut previous = scan.after;
        let mut coins = Vec::with_capacity(response.coins.len());
        for coin in response.coins {
            let address: [u8; 32] = coin
                .address
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid scanned address"))?;
            anyhow::ensure!(
                previous.is_none_or(|old| address > old)
                    && cursor.is_some_and(|end| address <= end),
                "invalid scanned coin order"
            );
            let output = Output {
                owner: coin
                    .owner
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid scanned owner"))?,
                commitment: AmountCommitment::from_bytes(&coin.commitment)
                    .map_err(|e| anyhow::anyhow!("scanned commitment: {e:?}"))?,
                memo: coin
                    .memo
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid scanned memo"))?,
            };
            let (actual_address, _) =
                quil_execution::token_intrinsic::state::create_coin(
                    &self.context,
                    coin.frame_number,
                    &output,
                    coin.position,
                )?;
            anyhow::ensure!(
                actual_address == address,
                "scanned coin content address mismatch"
            );
            // A coin's address decides its block, so a position outside that
            // block is a malformed record. The identity no longer covers the
            // position (it is what picks it), so this is the check that keeps
            // a serving peer from inventing one.
            {
                use quil_execution::token_intrinsic::coin_blocks;
                let (block, _) = coin_blocks::locate(coin.position);
                anyhow::ensure!(
                    coin_blocks::block_for_address(coin_blocks::creation_width(block), &address)
                        .map(|expected| expected == block)
                        .unwrap_or(false),
                    "scanned coin position does not belong to its address"
                );
            }
            coins.push((address, output));
            previous = Some(address);
        }
        scan.snapshot_id = Some(id);
        scan.root = Some(root);
        scan.after = cursor;
        scan.remaining_pages -= 1;
        scan.finished = !response.has_more;
        Ok(coins)
    }

    pub(super) fn load(
        tc: &TokenCtx,
        network: &[u8; 32],
        application: &[u8; 32],
    ) -> anyhow::Result<Self> {
        let secret = Zeroizing::new(
            tc.key_manager
                .get_secret_key_bytes_by_id("q-onion-key")
                .map_err(|e| anyhow::anyhow!("q-onion-key secret: {e}"))?,
        );
        let public = tc
            .key_manager
            .get_public_key_bytes_by_id("q-onion-key")
            .map_err(|e| anyhow::anyhow!("q-onion-key public: {e}"))?;
        Self::from_keys(network, application, &public, secret)
    }
    fn from_keys(
        network: &[u8; 32],
        application: &[u8; 32],
        public: &[u8],
        secret: Zeroizing<Vec<u8>>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            public.len() == sntrup761::SNTRUP761_PUBLIC_KEY_LEN
                && secret.len() == sntrup761::SNTRUP761_SECRET_KEY_LEN,
            "invalid wallet NTRU key lengths"
        );
        // Refuse to print an address whose memo key cannot be opened by this
        // wallet. This is a local key-consistency check, not address authentication.
        let (expected, ciphertext) = sntrup761::encapsulate(public)?;
        let expected = Zeroizing::new(expected);
        let recovered = Zeroizing::new(sntrup761::decapsulate(&ciphertext, &secret)?);
        anyhow::ensure!(
            *expected == *recovered,
            "wallet NTRU public and secret keys do not match"
        );
        let context = parameter_context(network, application);
        let mut hash = Shake256::default();
        hash.update(b"quil/coin/wallet-recipient/v3\0");
        hash.update(&(secret.len() as u64).to_le_bytes());
        hash.update(&secret);
        let mut seed = Zeroizing::new([0u8; 32]);
        hash.finalize_xof().read(seed.as_mut());
        let recipient = RecipientSecret::from_seed(&context, &seed);
        let address = RecipientAddress::new(&context, &recipient, public)
            .map_err(|e| anyhow::anyhow!("confidential address: {e:?}"))?;
        Ok(Self {
            context,
            network: *network,
            application: *application,
            kem_secret: secret,
            recipient,
            address,
        })
    }

    fn unix_now() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }

    /// Fetch paths for selected public coin records through a bounded RPC and
    /// check their canonical representation and membership in the returned root.
    /// Admission still decides whether that root is retained by the network.
    pub(super) async fn witnesses(
        &self,
        client: &quil_types::proto::node::node_service_client::NodeServiceClient<
            tonic::transport::Channel,
        >,
        coins: &[([u8; 32], &Output)],
    ) -> anyhow::Result<(
        quil_lattice_ct::confidential::coin_tree::RootRecord,
        Vec<quil_lattice_ct::confidential::coin_tree::AuthPath>,
    )> {
        anyhow::ensure!(
            !coins.is_empty() && coins.len() <= 4,
            "select one to four coins per witness request"
        );
        anyhow::ensure!(
            coins
                .iter()
                .map(|(address, _)| address)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == coins.len(),
            "duplicate selected coins"
        );
        let client = client.clone().max_decoding_message_size((1 << 20) - 1);
        let request = quil_types::proto::node::GetCoinWitnessesRequest {
            domain: self.application.to_vec(),
            addresses: coins.iter().map(|(address, _)| address.to_vec()).collect(),
        };
        let response = retry_witness_request(std::time::Duration::from_secs(1800), || {
            let mut client = client.clone(); let request = request.clone();
            async move { client.get_coin_witnesses(request).await.map(tonic::Response::into_inner) }
        }).await?;
        self.decode_witnesses(coins, response)
    }

    fn decode_witnesses(
        &self,
        coins: &[([u8; 32], &Output)],
        response: quil_types::proto::node::GetCoinWitnessesResponse,
    ) -> anyhow::Result<(
        quil_lattice_ct::confidential::coin_tree::RootRecord,
        Vec<quil_lattice_ct::confidential::coin_tree::AuthPath>,
    )> {
        use quil_lattice_ct::confidential::{
            coin_tree::{AuthPath, RootRecord},
            relation::membership::{MembershipKey, Node},
        };
        anyhow::ensure!(
            response.network.as_slice() == self.network.as_slice(),
            "witness network mismatch"
        );
        let root = RootRecord::decode(&response.root_record, &self.context)
            .map_err(|e| anyhow::anyhow!("witness root: {e:?}"))?;
        anyhow::ensure!(
            response.witnesses.len() == coins.len(),
            "witness count mismatch"
        );
        let key = MembershipKey::derive(&self.context);
        let mut paths = Vec::with_capacity(coins.len());
        for ((address, output), witness) in coins.iter().zip(response.witnesses) {
            anyhow::ensure!(
                witness.address.as_slice() == address.as_slice() && witness.found,
                "selected coin missing or mismatched"
            );
            anyhow::ensure!(
                witness.siblings.len() == usize::from(root.depth)
                    && witness.right.len() == usize::from(root.depth),
                "witness depth mismatch"
            );
            let siblings = witness
                .siblings
                .iter()
                .map(|bytes| {
                    Node::from_bytes(bytes).map_err(|e| anyhow::anyhow!("witness node: {e:?}"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let owner = Node::from_identity_bytes(&output.owner)
                .map_err(|e| anyhow::anyhow!("coin owner: {e:?}"))?;
            let mut node = key.leaf(&owner, &output.commitment);
            for (sibling, &right) in siblings.iter().zip(&witness.right) {
                node = if right {
                    key.parent(sibling, &node)
                } else {
                    key.parent(&node, sibling)
                };
            }
            anyhow::ensure!(
                node == root.root,
                "witness does not authenticate selected coin"
            );
            paths.push(AuthPath {
                siblings,
                right: witness.right,
            });
        }
        Ok((root, paths))
    }

    pub(super) fn address(&self) -> &RecipientAddress {
        &self.address
    }
    pub(super) fn open(&self, output: &Output) -> anyhow::Result<OpenedOutput> {
        open_output(&self.context, &self.kem_secret, &self.recipient, output)
            .map_err(|e| anyhow::anyhow!("memo: {e:?}"))
    }
}

fn identifier(value: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("identifier must contain exactly 32 bytes"))
}

/// Wallet-side circuit dimensions: the compiled network policy the node
/// enforces, so wallet and node cannot drift.
#[cfg(feature = "native-proof")]
fn compile_limits() -> quil_lattice_ct::confidential::transfer::CompileLimits {
    // Limits are identical across networks; network 0 is the canonical source.
    quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(0).limits
}

/// The network's minimum proof-bound QUIL fee, used when a command omits `--fee`.
#[cfg(feature = "native-proof")]
/// Reserve a proof-bound fee before proving. The charge is the shared
/// world-state-growth price applied to the bytes the operation's admission
/// will stage (`token_intrinsic::cost`); the wallet prices the operation's
/// shape exactly, so no payload budget or compiled minimum is involved.
/// Explicit fees bypass estimation. A missing quote never becomes a default:
/// that would prepare a transaction known to be underpriced.
#[cfg(feature = "native-proof")]
pub(super) async fn quoted_quil_fee(
    tc: &TokenCtx, explicit: Option<u128>, shape: quil_execution::token_intrinsic::cost::Shape,
    global_venue: bool,
) -> anyhow::Result<u128> {
    if let Some(fee) = explicit { return Ok(fee); }
    let policy = quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(tc.node_config.p2p.network);
    let context = quil_lattice_ct::confidential::transfer::parameter_context(&policy.network, &quil_execution::domains::QUIL_TOKEN);
    let cost = quil_execution::token_intrinsic::cost::shape_growth(&context, shape)?;
    quoted_quil_fee_for_cost(tc, None, cost, global_venue).await
}

/// [`quoted_quil_fee`] for an operation whose state growth is already known.
#[cfg(feature = "native-proof")]
pub(super) async fn quoted_quil_fee_for_cost(
    tc: &TokenCtx, explicit: Option<u128>, cost: u64, global_venue: bool,
) -> anyhow::Result<u128> {
    if let Some(fee) = explicit { return Ok(fee); }
    let policy = quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(tc.node_config.p2p.network);
    let quote = tc.connect().await?.get_token_fee_quote(quil_types::proto::node::GetTokenFeeQuoteRequest {
        application: quil_execution::domains::QUIL_TOKEN.to_vec(), max_payload_bytes: cost, global_venue,
    }).await.map_err(|e| anyhow::anyhow!("fee estimate unavailable: {e}; provide an explicit --fee or use a node serving this execution venue"))?.into_inner();
    anyhow::ensure!(!global_venue || quote.global_execution, "global venue fee quote was not priced for global execution");
    let charge = checked_quil_fee_quote(&quote, &policy.network, cost)?;
    let fee = with_fee_headroom(charge)?;
    println!("Estimated fee: {fee} base units for {cost} bytes of state growth (snapshot frame {}; {charge} at the snapshot plus {AUTOMATIC_FEE_HEADROOM_PERCENT}% for fee-vote movement before inclusion).", quote.observed_frame);
    Ok(fee)
}

/// Headroom an automatic fee carries over the quoted charge. The fee
/// multiplier vote is a moving average that can rise between quoting, proving
/// and inclusion; paying the exact snapshot charge makes a transaction fail its
/// post-proving refresh (or admission) whenever the vote ticks up. The excess is
/// paid to the shard's provers like the rest of the fee. Explicit fees are exact.
pub(super) const AUTOMATIC_FEE_HEADROOM_PERCENT: u128 = 10;

pub(super) fn with_fee_headroom(charge: u128) -> anyhow::Result<u128> {
    let headroom = charge.checked_mul(AUTOMATIC_FEE_HEADROOM_PERCENT)
        .map(|scaled| scaled.div_ceil(100))
        .ok_or_else(|| anyhow::anyhow!("fee exceeds the token amount range"))?;
    charge.checked_add(headroom).ok_or_else(|| anyhow::anyhow!("fee exceeds the token amount range"))
}

/// Validate a quote against its own pricing inputs and return the exact
/// charge for `cost` bytes of state growth at that snapshot.
#[cfg(feature = "native-proof")]
fn checked_quil_fee_quote(
    quote: &quil_types::proto::node::GetTokenFeeQuoteResponse,
    network: &[u8; 32], cost: u64,
) -> anyhow::Result<u128> {
    anyhow::ensure!(quote.network.as_slice() == network.as_slice() && quote.application.as_slice() == quil_execution::domains::QUIL_TOKEN.as_slice()
        && quote.max_payload_bytes == cost && cost > 0 && cost < 1 << 20,
        "fee quote context does not match request");
    let budget = u128::from_be_bytes(quote.fee_budget.as_slice().try_into()
        .map_err(|_| anyhow::anyhow!("fee quote amount must be exactly 16 bytes"))?);
    let selector = quil_execution::pricing::network_selector(network)
        .ok_or_else(|| anyhow::anyhow!("invalid network identifier"))?;
    let expected = quil_execution::pricing::fee_budget_for_payload_limit(
        selector, quote.difficulty, quote.world_state_bytes, cost, quote.fee_multiplier_vote,
    )?;
    anyhow::ensure!(num_bigint::BigInt::from(budget) == expected, "fee quote arithmetic does not match pricing inputs");
    anyhow::ensure!(!quote.global_execution || quote.fee_multiplier_vote == 1,
        "global fee quote has an invalid vote");
    let cost = num_bigint::BigInt::from(cost);
    let required = quil_execution::pricing::fee_multiplier_for_cost(
        selector, quote.difficulty, quote.world_state_bytes, &cost, quote.fee_multiplier_vote,
    )? * &cost;
    anyhow::ensure!(required <= expected, "fee quote budget does not cover the exact charge");
    required.to_string().parse::<u128>().map_err(|_| anyhow::anyhow!("fee exceeds the token amount range"))
}

/// Refresh an available venue quote after proving. Unavailable venue quotes
/// leave explicit-fee submission possible; they do not certify affordability.
#[cfg(feature = "native-proof")]
async fn refresh_submission_fee(
    tc: &TokenCtx,
    client: &mut quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
    bytes: &[u8],
) -> anyhow::Result<()> {
    use quil_execution::token_intrinsic::{cost, wire};
    let application = wire::domain(bytes)?;
    let tp = u32::from_be_bytes(bytes[..4].try_into().unwrap());
    if application != quil_execution::domains::QUIL_TOKEN || !matches!(tp, 0x0512 | 0x0513 | 0x0514 | 0x0515 | 0x0516 | 0x0518) {
        return Ok(());
    }
    let cost = cost::state_growth(bytes)?;
    let quote = match client.get_token_fee_quote(quil_types::proto::node::GetTokenFeeQuoteRequest {
        application: application.to_vec(), max_payload_bytes: cost,
        // Reward mint authorizations execute in the global venue.
        global_venue: tp == quil_execution::token_intrinsic::constants::TYPE_LATTICE_MINT,
    }).await {
        Ok(response) => response.into_inner(),
        Err(error) if matches!(error.code(), tonic::Code::Unavailable | tonic::Code::Unimplemented) => {
            println!("Fee refresh unavailable; submitting the supplied fee for node validation.");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let policy = quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(tc.node_config.p2p.network);
    check_submission_fee_quote(&quote, &policy.network, cost, wire::fee(bytes)?)
}

#[cfg(feature = "native-proof")]
fn check_submission_fee_quote(
    quote: &quil_types::proto::node::GetTokenFeeQuoteResponse, network: &[u8; 32],
    cost: u64, paid: u128,
) -> anyhow::Result<()> {
    let required = checked_quil_fee_quote(quote, network, cost)?;
    anyhow::ensure!(paid >= required,
        "fee changed while preparing transaction: supplied {paid}, snapshot requires {required} for {cost} bytes of state growth; rebuild with an adequate --fee");
    Ok(())
}

/// Native submission-accounting budget for wallet proving; not an RSS cap.
#[cfg(feature = "native-proof")]
fn native_budget() -> quil_lattice_ct::confidential::relation::backend::native::NativeBudget {
    quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(0).native_budget
}

/// Default escrow lifetime when no refund frame is given: ~1 day at 10 s/frame
/// from the node's current global head (same default as the legacy command).
const DEFAULT_REFUND_FRAMES: u64 = 8640;

/// Confidential escrow (pending) address: the recipient's confidential address
/// followed by its Falcon claim authority key.
pub(super) fn encode_escrow_address(address: &RecipientAddress, falcon_public: &[u8]) -> anyhow::Result<String> {
    anyhow::ensure!(falcon_public.len() == quil_crypto::FALCON_PUBLIC_KEY_LEN, "invalid escrow authority key length");
    let mut bytes = address.encode().to_vec();
    bytes.extend_from_slice(falcon_public);
    Ok(format!("0x{}", hex::encode(bytes)))
}

pub(super) fn parse_escrow_address(value: &str, context: &[u8; 32])
    -> anyhow::Result<(RecipientAddress, [u8; quil_crypto::FALCON_PUBLIC_KEY_LEN])> {
    use quil_lattice_ct::confidential::address::ADDRESS_BYTES;
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))?;
    anyhow::ensure!(bytes.len() == ADDRESS_BYTES + quil_crypto::FALCON_PUBLIC_KEY_LEN,
        "escrow address must be a confidential address followed by a Falcon public key");
    let address = RecipientAddress::decode(&bytes[..ADDRESS_BYTES], context)
        .map_err(|e| anyhow::anyhow!("escrow recipient address: {e:?}"))?;
    let authority = bytes[ADDRESS_BYTES..].try_into().map_err(|_| anyhow::anyhow!("invalid escrow authority key"))?;
    Ok((address, authority))
}

fn parse_recipient(value: &str, context: &[u8; 32]) -> anyhow::Result<RecipientAddress> {
    RecipientAddress::decode(&hex::decode(value.strip_prefix("0x").unwrap_or(value))?, context)
        .map_err(|e| anyhow::anyhow!("recipient address: {e:?}"))
}

/// The keystore Falcon key used as escrow and reward authority.
fn falcon_signer(tc: &TokenCtx) -> anyhow::Result<std::sync::Arc<quil_crypto::FalconSigner>> {
    let secret = Zeroizing::new(tc.key_manager.get_secret_key_bytes_by_id("q-prover-key")?);
    let public = tc.key_manager.get_public_key_bytes_by_id("q-prover-key")?;
    anyhow::ensure!(secret.len() == quil_crypto::FALCON_SIGNING_KEY_LEN
        && public.len() == quil_crypto::FALCON_PUBLIC_KEY_LEN, "invalid Falcon authority key encoding");
    anyhow::ensure!(quil_crypto::falcon_public_from_signing_key(&secret).as_deref() == Some(public.as_slice()),
        "Falcon authority keypair does not match");
    Ok(std::sync::Arc::new(quil_crypto::FalconSigner::from_bytes(&secret, &public)))
}

/// The legacy Ed448 peer identity that owns transparent (legacy) coins.
fn legacy_owner_signer(tc: &TokenCtx) -> anyhow::Result<std::sync::Arc<dyn quil_types::crypto::Signer>> {
    let raw = Zeroizing::new(hex::decode(&tc.node_config.p2p.peer_priv_key)?);
    anyhow::ensure!(raw.len() == 114, "peer key must be 57-byte seed plus 57-byte public key");
    Ok(std::sync::Arc::new(quil_crypto::Ed448Signer::from_bytes(&raw[..57], &raw[57..])?))
}

/// Output amounts for splitting one coin: the requested pieces plus any
/// remainder, bounded by the circuit's output limit. Overflow-safe.
pub(super) fn split_amounts(coin: u128, pieces: &[u128], fee: u128, max_outputs: usize) -> anyhow::Result<Vec<u128>> {
    anyhow::ensure!(!pieces.is_empty() && pieces.iter().all(|piece| *piece > 0), "split pieces must be positive");
    let spent = pieces.iter().try_fold(fee, |sum, piece| sum.checked_add(*piece))
        .ok_or_else(|| anyhow::anyhow!("split total overflows"))?;
    let remainder = coin.checked_sub(spent).ok_or_else(|| anyhow::anyhow!("split pieces plus fee exceed the coin"))?;
    let mut amounts = pieces.to_vec();
    if remainder > 0 { amounts.push(remainder); }
    anyhow::ensure!(amounts.len() <= max_outputs,
        "one split produces at most {max_outputs} coins including the remainder; split again from a resulting coin");
    Ok(amounts)
}

/// Coins to merge: the requested addresses, or the largest coins when none are
/// named, bounded by the circuit's input limit. Returns the checked total.
pub(super) fn merge_selection(mut coins: Vec<OwnedCoin>, requested: &[[u8; 32]], max_inputs: usize)
    -> anyhow::Result<(Vec<OwnedCoin>, u128)> {
    coins.retain(|coin| *coin.amount > 0);
    let selected: Vec<OwnedCoin> = if requested.is_empty() {
        coins.sort_by(|a, b| (*b.amount).cmp(&*a.amount).then(a.address.cmp(&b.address)));
        coins.into_iter().take(max_inputs).collect()
    } else {
        let mut selected = Vec::with_capacity(requested.len());
        for address in requested {
            let index = coins.iter().position(|coin| coin.address == *address)
                .ok_or_else(|| anyhow::anyhow!("coin 0x{} is not an unspent coin of this wallet", hex::encode(address)))?;
            selected.push(coins.swap_remove(index));
        }
        selected
    };
    anyhow::ensure!(selected.len() >= 2, "merging requires at least two unspent coins");
    anyhow::ensure!(selected.len() <= max_inputs, "merge at most {max_inputs} coins per transaction");
    let total = selected.iter().try_fold(0u128, |sum, coin| sum.checked_add(*coin.amount))
        .ok_or_else(|| anyhow::anyhow!("merged total overflows"))?;
    Ok((selected, total))
}

pub(super) fn run(tc: &TokenCtx, application: &str, escrow: bool) -> anyhow::Result<()> {
    let network =
        quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = RecipientWallet::load(tc, &network, &identifier(application)?)?;
    if escrow {
        let authority = tc.key_manager.get_public_key_bytes_by_id("q-prover-key")?;
        println!("{}", encode_escrow_address(wallet.address(), &authority)?);
    } else {
        println!("0x{}", hex::encode(wallet.address().encode()));
    }
    Ok(())
}

pub(super) async fn run_balance(tc: &TokenCtx, application: &str, max_pages: usize, max_coins: usize) -> anyhow::Result<()> {
    let application_id = identifier(application)?;
    if application_id == quil_execution::domains::QUIL_TOKEN {
        println!("{}", super::balance::claimable_rewards(tc).await);
    }
    let network = quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = std::sync::Arc::new(RecipientWallet::load(tc, &network, &application_id)?);
    let client = tc.connect().await?;
    let coins = wallet.scan_unspent(&client, max_pages, max_coins).await?;
    let total = coins.iter().try_fold(0u128, |sum, coin| sum.checked_add(*coin.amount))
        .ok_or_else(|| anyhow::anyhow!("balance overflows u128"))?;
    println!("{total} base units across {} coins reported unspent by the configured node (not a finalized balance)", coins.len());
    Ok(())
}

pub(super) async fn run_escrows(tc: &TokenCtx, application: &str, max_pages: usize, max_escrows: usize) -> anyhow::Result<()> {
    let network = quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = std::sync::Arc::new(RecipientWallet::load(tc, &network, &identifier(application)?)?);
    let authority = tc.key_manager.get_public_key_bytes_by_id("q-prover-key")?;
    let client = tc.connect().await?;
    let escrows = wallet.scan_escrows(&client, authority, max_pages, max_escrows).await?;
    println!("{} recovered escrow authorities reported unconsumed by the configured node:", escrows.len());
    for (address, amount, refund, deadline) in escrows {
        println!("0x{} {} branch={} refund_after_global_frame={}", hex::encode(address), *amount,
            if refund { "refund" } else { "recipient" }, deadline);
    }
    Ok(())
}

pub(super) async fn run_coins(tc: &TokenCtx, application: &str, max_pages: usize, max_coins: usize) -> anyhow::Result<()> {
    let network = quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = std::sync::Arc::new(RecipientWallet::load(tc, &network, &identifier(application)?)?);
    let client = tc.connect().await?;
    let coins = wallet.scan_unspent(&client, max_pages, max_coins).await?;
    println!("{} recovered coins reported unspent by the configured node:", coins.len());
    for coin in coins {
        println!("0x{} {}", hex::encode(coin.address), *coin.amount);
    }
    Ok(())
}

#[cfg(feature = "native-proof")]
/// `fee` is the caller's explicit fee, or `None` to quote one. The fee is
/// bound into the proof, so it is chosen before proving — and the per-byte
/// price can move while the wallet waits for witnesses and builds the proof,
/// which is minutes now that a spend proves against the canonical root. The
/// headroom covers a small move; a larger one is answered with the price the
/// refresh just reported, by re-quoting and rebuilding rather than making the
/// caller retry by hand. An explicit fee is exact by contract, never re-quoted.
pub(super) async fn run_transfer(tc: &TokenCtx, application: &str, recipient: &str, amount: u128,
    requested_fee: Option<u128>, max_pages: usize, max_coins: usize) -> anyhow::Result<()> {
    let application = identifier(application)?;
    anyhow::ensure!(amount > 0, "transfer amount must be positive");
    anyhow::ensure!(
        application == quil_execution::domains::QUIL_TOKEN || requested_fee.unwrap_or(0) == 0,
        "custom-token outflow cannot pay a QUIL fee",
    );
    let network = quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = std::sync::Arc::new(RecipientWallet::load(tc, &network, &application)?);
    let recipient = parse_recipient(recipient, &wallet.context)?;
    let limits = compile_limits();
    let mut client = tc.connect().await?;
    const FEE_REBUILDS: usize = 3;
    let mut attempt = 0usize;
    let bytes = loop {
        attempt += 1;
        let fee = transfer_fee(tc, &application, requested_fee, limits.max_inputs).await?;
        let coins = wallet.clone().scan_unspent(&client, max_pages, max_coins).await?;
        let (selected, change) = select_coins(coins, amount, fee, limits.max_inputs)?;
        let mut destinations = vec![(recipient.clone(), amount)];
        if *change != 0 { destinations.push((wallet.address().clone(), *change)); }
        let bytes = wallet.clone().create_transfer(&client, selected.into_iter().map(|coin| (coin.address, coin.output)).collect(),
            destinations, fee, limits, native_budget()).await?;
        match refresh_submission_fee(tc, &mut client, &bytes).await {
            Ok(()) => break bytes,
            Err(error) if requested_fee.is_none() && attempt < FEE_REBUILDS => {
                println!("The fee moved while preparing the transfer ({error}); re-quoting and rebuilding.");
            }
            Err(error) => return Err(error),
        }
    };
    submit_refreshed_operation(tc, &wallet, bytes).await?;
    println!("Confidential transfer submitted. Finalized inclusion is not yet confirmed.");
    Ok(())
}

/// The fee a transfer pays: the caller's, or a quote for two coins and the
/// input limit's markers. Custom-token outflow carries no QUIL fee.
#[cfg(feature = "native-proof")]
async fn transfer_fee(
    tc: &TokenCtx, application: &[u8; 32], explicit: Option<u128>, max_inputs: usize,
) -> anyhow::Result<u128> {
    if application != &quil_execution::domains::QUIL_TOKEN {
        return Ok(explicit.unwrap_or(0));
    }
    let shape = quil_execution::token_intrinsic::cost::Shape { coins: 2, markers: max_inputs, escrow: false };
    quoted_quil_fee(tc, explicit, shape, false).await
}

/// Pay `amount` QUIL to `destination` for the bundle `binding` names — its
/// SHA3-256 (`settlement_claim::bundle_context`), or, for a pre-funded
/// settlement, the claimant key that names one later. Returns the receipt the
/// destination bundle's claim spends once the settlement's GLOBAL record is
/// certified.
#[cfg(feature = "native-proof")]
pub(super) async fn run_pay(tc: &TokenCtx, destination: [u8; 32], amount: u128, binding: SettlementBinding, fee: Option<u128>,
    payment: Option<(RecipientAddress, u128)>, max_pages: usize, max_coins: usize) -> anyhow::Result<[u8; 32]> {
    use quil_lattice_ct::confidential::settlement::Settlement;
    anyhow::ensure!(amount > 0, "settlement amount must be positive");
    anyhow::ensure!(destination != quil_execution::domains::QUIL_TOKEN && destination != quil_execution::domains::GLOBAL,
        "settlements pay another application");
    let application = quil_execution::domains::QUIL_TOKEN;
    let network = quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = std::sync::Arc::new(RecipientWallet::load(tc, &network, &application)?);
    let limits = compile_limits();
    // One change output and up to the input limit of spent markers, plus the
    // GLOBAL record.
    let cost = quil_execution::token_intrinsic::cost::settlement_growth(&wallet.context,
        quil_execution::token_intrinsic::cost::Shape { coins: 1 + usize::from(payment.is_some()), markers: limits.max_inputs, escrow: false })?;
    let requested_fee = fee;
    let mut client = tc.connect().await?;
    // The fee is bound into the proof, so it must be chosen before proving —
    // and the per-byte price can move while the proof is built (world state
    // grows, the multiplier vote drifts). The headroom covers a small move; a
    // larger one is answered with the price the refresh just reported, by
    // re-quoting and rebuilding rather than making the caller retry by hand.
    // An explicit fee is exact by contract and is never re-quoted.
    const FEE_REBUILDS: usize = 3;
    let (bytes, fee) = {
        let mut attempt = 0usize;
        loop {
            attempt += 1;
            let fee = quoted_quil_fee_for_cost(tc, requested_fee, cost, false).await?;
            let payment = match payment.clone() {
                Some((payee, value)) => {
                    anyhow::ensure!(value > 0 && payee.context() == &wallet.context, "payment must be a positive QUIL amount to a QUIL address");
                    let mut nonce = [0u8; 32];
                    rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut nonce)?;
                    Some((payee, nonce, value))
                }
                None => None,
            };
            // The payment coin is funded from the same inputs as the settlement.
            let fee_and_payment = fee.checked_add(payment.as_ref().map_or(0, |(_, _, value)| *value))
                .ok_or_else(|| anyhow::anyhow!("payment exceeds the token amount range"))?;
            let coins = wallet.clone().scan_unspent(&client, max_pages, max_coins).await?;
            let (selected, change) = select_coins(coins, amount, fee_and_payment, limits.max_inputs)?;
            if let Some((_, _, value)) = &payment {
                println!("Paying {value} base units to the payee in the same transaction.");
            }
            let bytes = wallet.clone().create_settlement(&client, selected.into_iter().map(|coin| (coin.address, coin.output)).collect(),
                *change, fee, amount, destination, binding.clone(), payment, limits, native_budget()).await?;
            match refresh_submission_fee(tc, &mut client, &bytes).await {
                Ok(()) => break (bytes, fee),
                Err(error) if requested_fee.is_none() && attempt < FEE_REBUILDS => {
                    println!("The fee moved while proving ({error}); re-quoting and rebuilding.");
                }
                Err(error) => return Err(error),
            }
        }
    };
    let receipt = quil_execution::token_intrinsic::settlement_record::receipt_address(
        &Settlement::decode(&bytes, &network, &application).map_err(|e| anyhow::anyhow!("settlement decode: {e:?}"))?.statement,
    )?;
    wallet.submit(&mut tc.connect_submit().await?, &tc.key_manager, bytes).await?;
    println!("Settlement submitted: {amount} base units to {} (fee {fee}).", hex::encode(destination));
    println!("Receipt: {}", hex::encode(receipt));
    Ok(receipt)
}


/// A settlement this wallet paid before its destination bundle existed, held
/// in a local journal until a bundle claims it. The journal is a convenience:
/// the settlement itself lives in global state, and its receipt plus the
/// claimant key are all a claim needs.
#[cfg(feature = "native-proof")]
#[derive(Clone)]
pub(super) struct PrefundedSettlement {
    pub(super) receipt: [u8; 32],
    pub(super) destination: [u8; 32],
    pub(super) amount: u128,
    /// Keystore id of the claimant key that authorizes the funded bundle.
    pub(super) key_id: String,
    pub(super) created: u64,
    /// When a claim was last built against it, zero if never. A claimed entry
    /// is never auto-reused again: reusing one whose bundle did land wastes
    /// the next bundle, and one whose bundle did not land is still claimable
    /// by hand with `token settlement-claim`.
    pub(super) used: u64,
}

#[cfg(feature = "native-proof")]
fn prefund_journal(tc: &TokenCtx) -> std::path::PathBuf {
    tc.config_dir.join("wallet-prefunded-settlements.txt")
}

#[cfg(feature = "native-proof")]
fn read_prefunded(tc: &TokenCtx) -> Vec<PrefundedSettlement> {
    let parse = |line: &str| -> Option<PrefundedSettlement> {
        let field: Vec<&str> = line.split_whitespace().collect();
        if field.len() != 6 {
            return None;
        }
        Some(PrefundedSettlement {
            receipt: hex::decode(field[0]).ok()?.try_into().ok()?,
            destination: hex::decode(field[1]).ok()?.try_into().ok()?,
            amount: field[2].parse().ok()?,
            key_id: field[3].to_string(),
            created: field[4].parse().ok()?,
            used: field[5].parse().ok()?,
        })
    };
    std::fs::read_to_string(prefund_journal(tc)).unwrap_or_default().lines().filter_map(parse).collect()
}

#[cfg(feature = "native-proof")]
fn write_prefunded(tc: &TokenCtx, entries: &[PrefundedSettlement]) -> anyhow::Result<()> {
    let body: String = entries.iter()
        .map(|e| format!("{} {} {} {} {} {}\n", hex::encode(e.receipt), hex::encode(e.destination), e.amount, e.key_id, e.created, e.used))
        .collect();
    std::fs::write(prefund_journal(tc), body).map_err(|e| anyhow::anyhow!("pre-funded settlement journal: {e}"))
}

/// Replace (or add) one entry, keyed by receipt.
#[cfg(feature = "native-proof")]
fn record_prefunded(tc: &TokenCtx, entry: PrefundedSettlement) -> anyhow::Result<()> {
    let mut entries: Vec<PrefundedSettlement> = read_prefunded(tc).into_iter().filter(|e| e.receipt != entry.receipt).collect();
    entries.push(entry);
    write_prefunded(tc, &entries)
}

#[cfg(feature = "native-proof")]
fn forget_prefunded(tc: &TokenCtx, receipt: &[u8; 32]) -> anyhow::Result<()> {
    let entries: Vec<PrefundedSettlement> = read_prefunded(tc).into_iter().filter(|e| &e.receipt != receipt).collect();
    write_prefunded(tc, &entries)
}

/// Whether `destination` has already consumed `receipt`, read from the
/// destination application's own tree. An unreadable answer is reported as not
/// consumed: the settlement is spent either way, and a doomed submission is
/// rejected without cost.
///
/// The marker's only field sits at key `[0xff; 32]`, which is not a hypergraph
/// field index, so it is never decoded into `entries`; the vertex's `present`
/// flag is what says the marker is there.
#[cfg(feature = "native-proof")]
async fn settlement_consumed(tc: &TokenCtx, destination: &[u8; 32], receipt: &[u8; 32]) -> bool {
    let marker = match quil_execution::token_intrinsic::settlement_claim::consumption_marker(destination, receipt) {
        Ok(marker) => marker,
        Err(_) => return false,
    };
    let address = [destination.as_slice(), marker.as_slice()].concat();
    let Ok(mut client) = tc.connect().await else { return false };
    match client.get_vertex_data(quil_types::proto::node::GetVertexDataRequest { address, ..Default::default() }).await {
        Ok(response) => {
            let response = response.into_inner();
            response.present.unwrap_or(false) || !response.entries.is_empty()
        }
        Err(_) => false,
    }
}

/// Take the smallest never-claimed pre-funded settlement of `destination` that
/// covers `required` and is not already consumed, marking it claimed. `None`
/// when there is none to reuse.
#[cfg(feature = "native-proof")]
async fn take_prefunded(tc: &TokenCtx, destination: [u8; 32], required: u128) -> anyhow::Result<Option<PrefundedSettlement>> {
    let now = RecipientWallet::unix_now();
    let mut entries = read_prefunded(tc);
    entries.sort_by_key(|e| (e.amount, e.receipt));
    let usable: Vec<[u8; 32]> = entries.iter()
        .filter(|e| e.destination == destination && e.amount >= required && e.used == 0)
        .map(|e| e.receipt)
        .collect();
    for receipt in usable {
        if settlement_consumed(tc, &destination, &receipt).await {
            forget_prefunded(tc, &receipt)?;
            continue;
        }
        let mut entries = read_prefunded(tc);
        let Some(entry) = entries.iter_mut().find(|e| e.receipt == receipt) else { continue };
        entry.used = now;
        let taken = entry.clone();
        write_prefunded(tc, &entries)?;
        return Ok(Some(taken));
    }
    Ok(None)
}

/// Pay `amount` QUIL to `destination` now, for a bundle chosen later: the
/// settlement names the claimant key `key_id` instead of a bundle, and any
/// bundle that key signs may spend it, once. Records it in the local journal,
/// where paid submissions to `destination` pick it up automatically.
#[cfg(feature = "native-proof")]
pub(super) async fn run_prefund(tc: &TokenCtx, destination: [u8; 32], amount: u128, fee: Option<u128>,
    key_id: &str, max_pages: usize, max_coins: usize) -> anyhow::Result<()> {
    let binding = SettlementBinding::of_key(&tc.key_manager, key_id)?;
    let receipt = run_pay(tc, destination, amount, binding, fee, None, max_pages, max_coins).await?;
    record_prefunded(tc, PrefundedSettlement {
        receipt, destination, amount, key_id: key_id.to_string(), created: RecipientWallet::unix_now(), used: 0,
    })?;
    println!("Pre-funded {amount} base units for {}; any bundle signed by {key_id} may claim it once.", hex::encode(destination));
    Ok(())
}

/// List this wallet's pre-funded settlements, dropping those the destination
/// has already consumed.
///
/// Consumption is read from the configured node, which only answers for
/// applications whose state it holds: a regular node serves the shards it
/// covers, so read through an archive (`--read-rpc`) to see an application
/// executed in the global venue. A settlement this node cannot speak for is
/// listed as it stands, never dropped.
#[cfg(feature = "native-proof")]
pub(super) async fn run_prefunded(tc: &TokenCtx) -> anyhow::Result<()> {
    let entries = read_prefunded(tc);
    if entries.is_empty() {
        println!("No pre-funded settlements.");
        return Ok(());
    }
    let mut remaining = Vec::with_capacity(entries.len());
    for entry in entries {
        if settlement_consumed(tc, &entry.destination, &entry.receipt).await {
            println!("{} consumed by {}", hex::encode(entry.receipt), hex::encode(entry.destination));
            continue;
        }
        let state = if entry.used == 0 { "unclaimed" } else { "claimed by a bundle; claim it by hand if that bundle never landed" };
        println!("{} {} base units for {} (claimant key {}) — {state}", hex::encode(entry.receipt), entry.amount,
            hex::encode(entry.destination), entry.key_id);
        remaining.push(entry);
    }
    write_prefunded(tc, &remaining)
}

/// Pay, from this wallet's QUIL, for a bundle of operations on another
/// application and return the claim to place first in that bundle.
///
/// `rest` is the destination bundle with its first request left empty. The
/// settlement covers the destination venue's quoted charge for the bundle's
/// state growth (plus the claim's marker) with the automatic headroom and goes
/// to that venue's provers. `payment`, when given, also pays `value` QUIL to the
/// payee in the same transaction (a paid mint's price). Waits up to `wait` for
/// the settlement's GLOBAL record to be certified.
#[cfg(feature = "native-proof")]
pub(super) async fn pay_for_bundle(
    tc: &TokenCtx,
    destination: [u8; 32],
    rest: &quil_execution::message_envelope::CanonicalMessageBundle,
    payment: Option<(RecipientAddress, u128)>,
    wait: std::time::Duration,
) -> anyhow::Result<(Vec<u8>, bool)> {
    use quil_execution::token_intrinsic::settlement_claim::{bundle_context, marker_record, request_cost};
    let cost = rest.requests.iter().skip(1).flatten()
        .try_fold(marker_record()?.len() as u64, |total, request| -> anyhow::Result<u64> {
            let token = if quil_execution::token_intrinsic::dispatch::is_confidential_type(request.inner_type_prefix) {
                quil_execution::token_intrinsic::cost::state_growth(&request.inner_bytes)?
            } else { 0 };
            total.checked_add(request_cost(request)?).and_then(|t| t.checked_add(token))
                .ok_or_else(|| anyhow::anyhow!("bundle cost overflow"))
        })?;
    let network = quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let request = |global_venue| quil_types::proto::node::GetTokenFeeQuoteRequest {
        application: destination.to_vec(), max_payload_bytes: cost, global_venue,
    };
    // An application no shard covers (and a deploy's base domain) executes in
    // the global venue; a node that does not quote that venue for the
    // application still quotes global pricing directly.
    let quote = match tc.connect().await?.get_token_fee_quote(request(false)).await {
        Ok(quote) => quote.into_inner(),
        Err(status) if status.code() == tonic::Code::Unavailable => tc.connect().await?
            .get_token_fee_quote(request(true)).await
            .map_err(|e| anyhow::anyhow!("destination fee quote unavailable: {e}"))?.into_inner(),
        Err(status) => anyhow::bail!("destination fee quote unavailable: {status}"),
    };
    anyhow::ensure!(quote.network.as_slice() == network.as_slice() && quote.application.as_slice() == destination.as_slice(),
        "destination fee quote context does not match request");
    let selector = quil_execution::pricing::network_selector(&network)
        .ok_or_else(|| anyhow::anyhow!("invalid network identifier"))?;
    let charge = quil_execution::pricing::fee_multiplier_for_cost(selector, quote.difficulty, quote.world_state_bytes,
        &num_bigint::BigInt::from(cost), quote.fee_multiplier_vote)? * num_bigint::BigInt::from(cost);
    let charge: u128 = charge.to_string().parse().map_err(|_| anyhow::anyhow!("charge exceeds the token amount range"))?;
    let amount = with_fee_headroom(charge)?.max(1);
    let context = bundle_context(rest)?;
    println!("This bundle needs {amount} base units for {cost} bytes of state growth on {} (snapshot frame {}).",
        hex::encode(destination), quote.observed_frame);
    let claimed_payment = match &payment {
        Some((payee, value)) => Some((quil_execution::token_intrinsic::settlement_record::payment_address(&payee.encode())?, *value)),
        None => None,
    };
    // A pre-funded settlement of this destination pays for the bundle without
    // a new transaction. One that also carries a payment coin is not reused:
    // the payment is part of the settlement, chosen when it was paid.
    if payment.is_none() {
        if let Some(prefunded) = take_prefunded(tc, destination, amount).await? {
            let signer = tc.key_manager.get_signer_by_id(&prefunded.key_id)
                .map_err(|e| anyhow::anyhow!("claimant key {}: {e}", prefunded.key_id))?;
            let signature = signer.sign_with_domain(
                &quil_execution::token_intrinsic::settlement_claim::claimant_message(&network, &destination, &prefunded.receipt, &context),
                &quil_lattice_ct::confidential::transfer::parameter_context(&network, &destination),
            ).map_err(|e| anyhow::anyhow!("claimant signature: {e}"))?;
            let binding = ClaimBinding::Claimant {
                key_type: signer.key_type() as u32, public_key: signer.public_key().to_vec(), signature,
            };
            println!("Claiming pre-funded settlement {} ({} base units).", hex::encode(prefunded.receipt), prefunded.amount);
            let claim = settlement_claim(tc, destination, prefunded.receipt, prefunded.amount, &binding, None, wait).await?;
            return Ok((claim, quote.global_execution));
        }
    }
    let receipt = run_pay(tc, destination, amount, SettlementBinding::Bundle(context), None, payment, 128, 1024).await?;
    println!("Waiting for the settlement to be certified in global state...");
    let claim = settlement_claim(tc, destination, receipt, amount, &ClaimBinding::Bundle(context), claimed_payment, wait).await?;
    Ok((claim, quote.global_execution))
}

/// How long a custom-token operation waits for its QUIL settlement to be
/// certified before giving up.
#[cfg(feature = "native-proof")]
const SETTLEMENT_WAIT: std::time::Duration = std::time::Duration::from_secs(900);

/// Submit a wallet operation. QUIL operations pay their own fee; every other
/// application's operations carry a QUIL fee through a settlement claim.
#[cfg(feature = "native-proof")]
async fn submit_operation(
    tc: &TokenCtx,
    wallet: &RecipientWallet,
    client: &mut quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
    bytes: Vec<u8>,
) -> anyhow::Result<()> {
    if wallet.application == quil_execution::domains::QUIL_TOKEN {
        refresh_submission_fee(tc, client, &bytes).await?;
    }
    submit_refreshed_operation(tc, wallet, bytes).await
}

/// [`submit_operation`] for a caller that has just refreshed the fee itself
/// and rebuilt if it had moved — the price is not quoted twice.
#[cfg(feature = "native-proof")]
async fn submit_refreshed_operation(
    tc: &TokenCtx,
    wallet: &RecipientWallet,
    bytes: Vec<u8>,
) -> anyhow::Result<()> {
    if wallet.application == quil_execution::domains::QUIL_TOKEN {
        return wallet.submit(&mut tc.connect_submit().await?, &tc.key_manager, bytes).await;
    }
    submit_paid_operation(tc, wallet, bytes, None, SETTLEMENT_WAIT).await
}

/// Pay a QUIL settlement bound to `[claim, operation]` for the operation's
/// application, wait for certification, and submit claim and operation
/// together. `payment` adds a public payment coin (a paid mint's price).
#[cfg(feature = "native-proof")]
async fn submit_paid_operation(
    tc: &TokenCtx,
    wallet: &RecipientWallet,
    bytes: Vec<u8>,
    payment: Option<(RecipientAddress, u128)>,
    wait: std::time::Duration,
) -> anyhow::Result<()> {
    use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
    let (domain, request) = wallet.prepare_submission(bytes.clone())?;
    let timestamp = crate::send::now_millis();
    let rest = CanonicalMessageBundle {
        requests: vec![None, Some(CanonicalMessageRequest::wrap(bytes.clone()).map_err(|e| anyhow::anyhow!("wrap operation: {e}"))?)],
        timestamp,
    };
    let (claim, global_execution) = pay_for_bundle(tc, wallet.application, &rest, payment, wait).await?;
    let bundle = quil_types::proto::global::MessageBundle {
        requests: vec![
            quil_types::proto::global::MessageRequest {
                request: Some(quil_types::proto::global::message_request::Request::TokenOperation(
                    quil_types::proto::token::TokenOperation { canonical_bytes: claim })),
                timestamp: 0,
            },
            request,
        ],
        timestamp,
    };
    crate::send::send_to_venue(&mut tc.connect_submit().await?, &tc.key_manager, domain, global_execution, bundle).await?;
    println!("Submitted with its QUIL settlement claim.");
    Ok(())
}

/// Build a token's mint-entitlement tree from a file of
/// `<key type> <public key hex> <amount>` lines: prints the root to put in the
/// token's configuration and each entitlement's proof.
#[cfg(feature = "native-proof")]
pub(super) fn run_entitlements(tc: &TokenCtx, file: &std::path::Path) -> anyhow::Result<()> {
    use quil_execution::token_intrinsic::entitlement;
    let network = quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let text = std::fs::read_to_string(file)?;
    // Entitled keys are Falcon-512: application authority is post-quantum only.
    let key_type = quil_types::crypto::KeyType::Falcon512 as u32;
    let entries = text.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let mut fields = line.split_whitespace();
            let (key, amount) = (fields.next(), fields.next());
            let (Some(key), Some(amount), None) = (key, amount, fields.next()) else {
                anyhow::bail!("each line is `<Falcon-512 public key hex> <amount>`: {line:?}");
            };
            let key = hex::decode(key.strip_prefix("0x").unwrap_or(key))?;
            anyhow::ensure!(key.len() == quil_crypto::FALCON_PUBLIC_KEY_LEN,
                "entitled keys must be {}-byte Falcon-512 public keys: {line:?}", quil_crypto::FALCON_PUBLIC_KEY_LEN);
            Ok((key, amount.parse::<u128>()?))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    anyhow::ensure!(!entries.is_empty(), "no entitlements in {}", file.display());
    let leaves: Vec<[u8; 32]> = entries.iter()
        .map(|(key, amount)| entitlement::leaf(&network, key_type, key, *amount))
        .collect();
    let (root, proofs) = entitlement::build(&leaves)?;
    println!("Entitlement root: {}", hex::encode(root));
    for ((key, amount), proof) in entries.iter().zip(&proofs) {
        println!("{} {amount} proof {}", hex::encode(key), hex::encode(proof));
    }
    Ok(())
}

/// Print this wallet's QUIL payee address and its payment address.
#[cfg(feature = "native-proof")]
pub(super) fn run_payment_address(tc: &TokenCtx) -> anyhow::Result<()> {
    let network = quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = RecipientWallet::load(tc, &network, &quil_execution::domains::QUIL_TOKEN)?;
    let encoded = wallet.address().encode();
    println!("Payee address: {}", hex::encode(encoded));
    println!("Payment address: {}", hex::encode(quil_execution::token_intrinsic::settlement_record::payment_address(&encoded)?));
    Ok(())
}

/// Build the claim spending settlement `receipt` in `destination`'s bundle,
/// from a global membership witness. Waits up to `wait` for the settlement's
/// GLOBAL record to reach a certified root this node retains.
#[cfg(feature = "native-proof")]
pub(super) async fn settlement_claim(tc: &TokenCtx, destination: [u8; 32], receipt: [u8; 32], amount: u128,
    binding: &ClaimBinding, payment: Option<([u8; 32], u128)>, wait: std::time::Duration) -> anyhow::Result<Vec<u8>> {
    use quil_execution::token_intrinsic::{settlement_claim::SettlementClaim, settlement_record};
    let network = quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let deadline = std::time::Instant::now() + wait;
    loop {
        let response = tc.connect().await?
            .get_mint_authorization_witness(quil_types::proto::node::GetMintAuthorizationWitnessRequest { receipt: receipt.to_vec() })
            .await;
        match response {
            Ok(witness) => {
                let witness = witness.into_inner();
                if witness.found {
                    let global_root: [u8; 32] = witness.global_root.as_slice().try_into()
                        .map_err(|_| anyhow::anyhow!("witness global root must be 32 bytes"))?;
                    let claim = SettlementClaim {
                        network, application: destination, cited_global_frame: witness.cited_frame, global_root,
                        receipt, settlement: amount,
                        context: match binding {
                            ClaimBinding::Bundle(context) => *context,
                            ClaimBinding::Claimant { .. } => [0; 32],
                        },
                        payment_address: payment.map_or([0; 32], |(address, _)| address),
                        payment: payment.map_or(0, |(_, value)| value),
                        claimant_key_type: match binding {
                            ClaimBinding::Bundle(_) => 0,
                            ClaimBinding::Claimant { key_type, .. } => *key_type,
                        },
                        claimant_public_key: match binding {
                            ClaimBinding::Bundle(_) => Vec::new(),
                            ClaimBinding::Claimant { public_key, .. } => public_key.clone(),
                        },
                        claimant_signature: match binding {
                            ClaimBinding::Bundle(_) => Vec::new(),
                            ClaimBinding::Claimant { signature, .. } => signature.clone(),
                        },
                        forest_proof: witness.forest_proof,
                    };
                    // The record must carry exactly this destination, context
                    // and amount; a mismatch will never admit.
                    settlement_record::verify_membership(&network, &claim.entry()?, &global_root, &claim.forest_proof)
                        .map_err(|e| anyhow::anyhow!("settlement record does not match the requested claim: {e}"))?;
                    return Ok(claim.encode()?);
                }
            }
            Err(status) if matches!(status.code(), tonic::Code::Unavailable) => {}
            Err(status) => return Err(anyhow::anyhow!("settlement witness: {status}")),
        }
        anyhow::ensure!(std::time::Instant::now() < deadline,
            "settlement record not yet certified in a retained global root; retry later");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

/// Split one unspent coin into the requested pieces plus remainder, all owned
/// by this wallet. One transaction yields at most the circuit's output count.
#[cfg(feature = "native-proof")]
pub(super) async fn run_split(tc: &TokenCtx, application: &str, coin: &str, pieces: &[u128], fee: u128,
    max_pages: usize, max_coins: usize) -> anyhow::Result<()> {
    let application = identifier(application)?;
    let coin_address = identifier(coin)?;
    anyhow::ensure!(application == quil_execution::domains::QUIL_TOKEN || fee == 0, "custom-token outflow cannot pay a QUIL fee");
    let network = quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = std::sync::Arc::new(RecipientWallet::load(tc, &network, &application)?);
    let limits = compile_limits();
    let mut client = tc.connect().await?;
    let coins = wallet.clone().scan_unspent(&client, max_pages, max_coins).await?;
    let source = coins.into_iter().find(|owned| owned.address == coin_address)
        .ok_or_else(|| anyhow::anyhow!("coin is not an unspent coin of this wallet"))?;
    let amounts = split_amounts(*source.amount, pieces, fee, limits.max_outputs)?;
    let destinations = amounts.into_iter().map(|amount| (wallet.address().clone(), amount)).collect();
    let bytes = wallet.clone().create_transfer(&client, vec![(source.address, source.output)], destinations, fee, limits, native_budget()).await?;
    submit_operation(tc, &wallet, &mut client, bytes).await?;
    println!("Confidential split submitted. Finalized inclusion is not yet confirmed.");
    Ok(())
}

/// Merge the named coins (or the largest unspent coins) into one coin owned by
/// this wallet. One transaction consumes at most the circuit's input count.
#[cfg(feature = "native-proof")]
pub(super) async fn run_merge(tc: &TokenCtx, application: &str, coins: &[String], fee: u128,
    max_pages: usize, max_coins: usize) -> anyhow::Result<()> {
    let application = identifier(application)?;
    anyhow::ensure!(application == quil_execution::domains::QUIL_TOKEN || fee == 0, "custom-token outflow cannot pay a QUIL fee");
    let requested = coins.iter().filter(|value| value.as_str() != "all").map(|value| identifier(value))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let network = quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = std::sync::Arc::new(RecipientWallet::load(tc, &network, &application)?);
    let limits = compile_limits();
    let mut client = tc.connect().await?;
    let owned = wallet.clone().scan_unspent(&client, max_pages, max_coins).await?;
    let (selected, total) = merge_selection(owned, &requested, limits.max_inputs)?;
    let merged = total.checked_sub(fee).filter(|merged| *merged > 0)
        .ok_or_else(|| anyhow::anyhow!("merged coins must exceed the fee"))?;
    let bytes = wallet.clone().create_transfer(&client, selected.into_iter().map(|coin| (coin.address, coin.output)).collect(),
        vec![(wallet.address().clone(), merged)], fee, limits, native_budget()).await?;
    submit_operation(tc, &wallet, &mut client, bytes).await?;
    println!("Confidential merge submitted. Finalized inclusion is not yet confirmed.");
    Ok(())
}

/// Fund a escrow for a recipient's escrow address. This wallet's
/// Falcon key is the refund authority; the refund frame defaults to the node's
/// current global head plus about one day. Delivery is not finality.
#[cfg(feature = "native-proof")]
pub(super) async fn run_pending_create(tc: &TokenCtx, application: &str, recipient: &str, amount: u128, fee: u128,
    refund_after: Option<u64>, max_pages: usize, max_coins: usize) -> anyhow::Result<()> {
    use quil_lattice_ct::confidential::pending_claim::EscrowPolicy;
    use quil_types::crypto::Signer;
    let application = identifier(application)?;
    anyhow::ensure!(amount > 0, "escrow amount must be positive");
    anyhow::ensure!(application == quil_execution::domains::QUIL_TOKEN || fee == 0, "custom-token outflow cannot pay a QUIL fee");
    let network = quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = std::sync::Arc::new(RecipientWallet::load(tc, &network, &application)?);
    let (recipient_address, recipient_authority) = parse_escrow_address(recipient, &wallet.context)?;
    let refund_signer = falcon_signer(tc)?;
    let limits = compile_limits();
    let mut client = tc.connect().await?;
    let refund_after_global_frame = match refund_after {
        Some(frame) => frame,
        None => client.get_node_info(quil_types::proto::node::GetNodeInfoRequest::default()).await?
            .into_inner().last_global_head_frame.checked_add(DEFAULT_REFUND_FRAMES)
            .ok_or_else(|| anyhow::anyhow!("refund frame overflows"))?,
    };
    let coins = wallet.clone().scan_unspent(&client, max_pages, max_coins).await?;
    let (selected, change) = select_coins(coins, amount, fee, limits.max_inputs)?;
    let escrow = EscrowDestination {
        recipient: recipient_address,
        refund: wallet.address().clone(),
        amount,
        policy: EscrowPolicy {
            recipient: recipient_authority,
            refund: refund_signer.public_key().try_into().map_err(|_| anyhow::anyhow!("invalid refund authority key"))?,
            refund_after_global_frame,
        },
    };
    let mut change_outputs = Vec::new();
    if *change != 0 { change_outputs.push((wallet.address().clone(), *change)); }
    let bytes = wallet.clone().create_pending(&client, selected.into_iter().map(|coin| (coin.address, coin.output)).collect(),
        escrow, change_outputs, fee, limits, native_budget()).await?;
    submit_operation(tc, &wallet, &mut client, bytes).await?;
    println!("Confidential escrow funding submitted; refund authority becomes eligible at global frame {refund_after_global_frame}. Finalized inclusion is not yet confirmed.");
    Ok(())
}

/// Two-stage QUIL reward mint. Without `--claim`, discover this prover's reward,
/// prove and submit the global authorization, and save its bytes for the claim
/// stage. With `--claim <file>`, build the application claim from the finalized
/// authorization and submit it. Delivery is not finality at either stage.
#[cfg(feature = "native-proof")]
pub(super) async fn run_mint(tc: &TokenCtx, recipient: Option<&str>, fee: u128, claim: Option<&std::path::Path>) -> anyhow::Result<()> {
    use quil_types::crypto::Signer;
    let application = quil_execution::domains::QUIL_TOKEN;
    let network = quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = std::sync::Arc::new(RecipientWallet::load(tc, &network, &application)?);
    let mut client = tc.connect().await?;
    if let Some(path) = claim {
        let mint_bytes = std::fs::read(path)?;
        let bytes = wallet.create_mint_claim(&client, &mint_bytes).await?;
        submit_operation(tc, &wallet, &mut client, bytes).await?;
        println!("Confidential mint claim submitted. Finalized inclusion is not yet confirmed.");
        return Ok(());
    }
    let signer = falcon_signer(tc)?;
    let (cited_frame, reward_root, reward) = wallet.reward_claim(&client, signer.as_ref()).await?;
    let value = reward.value.checked_sub(fee).filter(|value| *value > 0)
        .ok_or_else(|| anyhow::anyhow!("claimable reward must exceed the fee"))?;
    let recipient = match recipient {
        Some(recipient) => parse_recipient(recipient, &wallet.context)?,
        None => wallet.address().clone(),
    };
    let signer: std::sync::Arc<dyn Signer> = signer;
    let bytes = wallet.clone().create_mint(cited_frame, reward_root, vec![reward], vec![signer],
        vec![(recipient, value)], fee, 1, 1, native_budget()).await?;
    let saved = tc.config_dir.join(format!("mint-{cited_frame}.bin"));
    std::fs::write(&saved, &bytes)?;
    submit_operation(tc, &wallet, &mut client, bytes).await?;
    println!("Confidential reward mint authorization submitted for global frame {cited_frame}. Once it is finalized, run `token mint --claim {}` to create the coins.", saved.display());
    Ok(())
}

/// Shield one transparent (legacy-owned) coin into confidential coins owned by
/// this wallet. Admission authenticates the source's value and owner.
#[cfg(feature = "native-proof")]
pub(super) async fn run_shield(tc: &TokenCtx, application: &str, source: &str, amount: u128, fee: u128) -> anyhow::Result<()> {
    let application = identifier(application)?;
    let source = identifier(source)?;
    anyhow::ensure!(application == quil_execution::domains::QUIL_TOKEN || fee == 0, "custom-token outflow cannot pay a QUIL fee");
    let shielded = amount.checked_sub(fee).filter(|shielded| *shielded > 0)
        .ok_or_else(|| anyhow::anyhow!("source amount must exceed the fee"))?;
    let network = quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = std::sync::Arc::new(RecipientWallet::load(tc, &network, &application)?);
    let owner = legacy_owner_signer(tc)?;
    let mut client = tc.connect().await?;
    let bytes = wallet.clone().create_shield(source, amount, owner, vec![(wallet.address().clone(), shielded)], fee, 1, native_budget()).await?;
    submit_operation(tc, &wallet, &mut client, bytes).await?;
    println!("Confidential shield submitted. Finalized inclusion is not yet confirmed.");
    Ok(())
}

/// Groups of at most `max` legacy coins, each group inside one shard of
/// `shards` (bit paths): a shard verifies only sources in its own range, so a
/// batch never spans two. A coin goes to the deepest shard covering it. Coins
/// no shard covers are returned apart. Groups ascend by address.
pub(super) fn shield_batches(
    mut coins: Vec<([u8; 32], u128)>,
    shards: &[Vec<bool>],
    max: usize,
) -> (Vec<Vec<quil_lattice_ct::confidential::shield::ShieldSource>>, Vec<[u8; 32]>) {
    use quil_lattice_ct::confidential::shield::ShieldSource;
    let covers = |path: &[bool], address: &[u8; 32]| path.iter().enumerate()
        .all(|(i, bit)| (address[i / 8] & (0x80 >> (i % 8)) != 0) == *bit);
    coins.sort();
    coins.dedup_by_key(|(address, _)| *address);
    let mut groups: std::collections::BTreeMap<Vec<bool>, Vec<ShieldSource>> = std::collections::BTreeMap::new();
    let mut uncovered = Vec::new();
    for (address, amount) in coins {
        match shards.iter().filter(|path| covers(path, &address)).max_by_key(|path| path.len()) {
            Some(path) => groups.entry(path.clone()).or_default().push(ShieldSource { address, amount }),
            None => uncovered.push(address),
        }
    }
    let batches = groups.into_values()
        .flat_map(|group| group.chunks(max.max(1)).map(<[ShieldSource]>::to_vec).collect::<Vec<_>>())
        .collect();
    (batches, uncovered)
}

/// The bit paths of `application`'s live shards (any active prover).
#[cfg(feature = "native-proof")]
async fn live_shard_paths(
    client: &mut quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
    application: &[u8; 32],
) -> anyhow::Result<Vec<Vec<bool>>> {
    let shards = client.get_shard_info(quil_types::proto::node::GetShardInfoRequest { include_all: true }).await
        .map_err(|e| anyhow::anyhow!("shard list: {}", e.message()))?.into_inner().shards;
    Ok(shards.iter()
        .filter(|shard| shard.filter.starts_with(application) && shard.active_provers > 0)
        .filter_map(|shard| quil_forest::decode_shard_filter_or_root(&shard.filter, 32).map(|(_, bits)| bits))
        .collect())
}

/// Legacy coins this wallet submitted in a batch shield within the last hour:
/// a resumed run leaves them for their batch to commit.
#[cfg(feature = "native-proof")]
fn recently_shielded(tc: &TokenCtx) -> std::collections::BTreeSet<[u8; 32]> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    std::fs::read_to_string(tc.config_dir.join("legacy-shield-journal.txt")).unwrap_or_default().lines()
        .filter_map(|line| {
            let (at, address) = line.split_once(' ')?;
            let at: u64 = at.parse().ok()?;
            let address: [u8; 32] = hex::decode(address).ok()?.try_into().ok()?;
            (now.saturating_sub(at) < 3_600).then_some(address)
        })
        .collect()
}

#[cfg(feature = "native-proof")]
fn record_shielded(tc: &TokenCtx, sources: &[quil_lattice_ct::confidential::shield::ShieldSource]) -> anyhow::Result<()> {
    use std::io::Write;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let mut file = std::fs::OpenOptions::new().create(true).append(true)
        .open(tc.config_dir.join("legacy-shield-journal.txt"))?;
    for source in sources {
        writeln!(file, "{now} {}", hex::encode(source.address))?;
    }
    Ok(())
}

/// Shield every unshielded legacy coin of this identity in batches of at most
/// `max_per_batch`, one shard per batch, each into one coin of this wallet.
#[cfg(feature = "native-proof")]
pub(super) async fn run_shield_all(tc: &TokenCtx, application: &str, max_per_batch: usize) -> anyhow::Result<()> {
    use quil_execution::token_intrinsic::cost::Shape;
    use quil_lattice_ct::confidential::shield::MAX_SHIELD_SOURCES;
    anyhow::ensure!((1..=MAX_SHIELD_SOURCES).contains(&max_per_batch),
        "a batch holds 1 to {MAX_SHIELD_SOURCES} legacy coins");
    let application = identifier(application)?;
    anyhow::ensure!(application == quil_execution::domains::QUIL_TOKEN, "only QUIL has legacy coins");
    let network = quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = std::sync::Arc::new(RecipientWallet::load(tc, &network, &application)?);
    let owner = legacy_owner_signer(tc)?;
    let mut client = tc.connect().await?;
    let pending = recently_shielded(tc);
    let coins: Vec<([u8; 32], u128)> = super::legacy::list(tc, &client, &application).await?.into_iter()
        .filter(|(address, _, shielded)| !shielded && !pending.contains(address))
        .map(|(address, amount, _)| (address, amount))
        .collect();
    if coins.is_empty() {
        println!("No unshielded legacy coins to shield{}.",
            if pending.is_empty() { "" } else { " (some submitted within the last hour are awaiting their batch)" });
        return Ok(());
    }
    let shards = live_shard_paths(&mut client, &application).await?;
    let (batches, uncovered) = shield_batches(coins, &shards, max_per_batch);
    if !uncovered.is_empty() {
        println!("{} legacy coins lie in no live shard and are left for a later run.", uncovered.len());
    }
    let count = batches.len();
    for (index, sources) in batches.into_iter().enumerate() {
        let total = sources.iter().try_fold(0u128, |sum, source| sum.checked_add(source.amount))
            .ok_or_else(|| anyhow::anyhow!("legacy sources overflow u128"))?;
        let fee = quoted_quil_fee(tc, None, Shape { coins: 1, markers: sources.len(), escrow: false }, false).await?;
        if fee >= total {
            println!("Batch {}/{count}: {} legacy coins worth {total} base units do not cover the fee {fee}; skipped.",
                index + 1, sources.len());
            continue;
        }
        let bytes = wallet.clone().create_batch_shield(sources.clone(), owner.clone(),
            vec![(wallet.address().clone(), total - fee)], fee, 1, native_budget()).await?;
        submit_operation(tc, &wallet, &mut client, bytes).await?;
        record_shielded(tc, &sources)?;
        println!("Batch {}/{count}: {} legacy coins, {} base units shielded (fee {fee}). Submitted; finalized inclusion is not yet confirmed.",
            index + 1, sources.len(), total - fee);
    }
    Ok(())
}

/// Explicit CLI submission; a successful RPC response is delivery, not finality.
#[cfg(feature = "native-proof")]
pub(super) async fn run_claim(tc: &TokenCtx, application: &str, escrow: &str, fee: u128, refund: bool) -> anyhow::Result<()> {
    use quil_lattice_ct::confidential::{memo::{open_escrow_recovery, EscrowRecoveryMemo},
        pending_claim::ClaimBranch, relation::backend::native::NativeBudget};
    let application = identifier(application)?;
    let escrow_address = identifier(escrow)?;
    anyhow::ensure!(application == quil_execution::domains::QUIL_TOKEN || fee == 0,
        "custom-token outflow cannot pay a QUIL fee");
    let network = quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = std::sync::Arc::new(RecipientWallet::load(tc, &network, &application)?);
    let signer = falcon_signer(tc)?;
    let mut client = tc.connect().await?;
    let stored = wallet.fetch_escrow(&client, escrow_address).await?;
    let (branch, recovery) = if refund {
        (ClaimBranch::Refund, stored.refund_recovery.clone())
    } else {
        (ClaimBranch::Recipient, EscrowRecoveryMemo { owner: stored.output.owner, ciphertext: stored.output.memo })
    };
    let opened = open_escrow_recovery(&wallet.context, &wallet.kem_secret, &wallet.recipient,
        &stored.output.commitment, &recovery).map_err(|e| anyhow::anyhow!("escrow recovery: {e:?}"))?;
    let amount = opened.amount().checked_sub(fee).filter(|amount| *amount > 0)
        .ok_or_else(|| anyhow::anyhow!("escrow amount must exceed the fee"))?;
    drop(opened);
    let global = if refund {
        Some(client.get_node_info(quil_types::proto::node::GetNodeInfoRequest::default()).await?
            .into_inner().last_global_head_frame)
    } else { None };
    let bytes = wallet.clone().create_pending_claim(escrow_address, stored, branch, global, signer,
        vec![(wallet.address().clone(), amount)], fee, 1, NativeBudget { max_native_bytes: 1 << 30 }).await?;
    submit_operation(tc, &wallet, &mut client, bytes).await?;
    println!("Confidential escrow claim submitted. Finalized inclusion is not yet confirmed.");
    Ok(())
}

/// Custom-token issuance. The keystore authority must be the token's configured
/// mint authority; `--permissionless` builds an unsigned statement for a free
/// payment policy. Delivery is not finality; admission checks the deployed policy.
#[cfg(feature = "native-proof")]
pub(super) async fn run_custom_mint(
    tc: &TokenCtx,
    application: &str,
    amount: u128,
    recipient: Option<&str>,
    authority_key: &str,
    permissionless: bool,
    paid: Option<(&str, u128, std::time::Duration)>,
    entitlement: Vec<u8>,
) -> anyhow::Result<()> {
    use quil_lattice_ct::confidential::relation::backend::native::NativeBudget;
    let application = identifier(application)?;
    anyhow::ensure!(amount > 0, "mint amount must be positive");
    anyhow::ensure!(application != quil_execution::domains::QUIL_TOKEN, "QUIL issuance uses the reward mint");
    let network = quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet = std::sync::Arc::new(RecipientWallet::load(tc, &network, &application)?);
    let recipient = match recipient {
        Some(recipient) => RecipientAddress::decode(
            &hex::decode(recipient.strip_prefix("0x").unwrap_or(recipient))?, &wallet.context)
            .map_err(|e| anyhow::anyhow!("recipient address: {e:?}"))?,
        None => wallet.address().clone(),
    };
    let authority: Option<std::sync::Arc<dyn quil_types::crypto::Signer>> = if permissionless {
        None
    } else {
        Some(std::sync::Arc::from(tc.key_manager.get_signer_by_id(authority_key)
            .map_err(|e| anyhow::anyhow!("mint authority key {authority_key}: {e}"))?))
    };
    let mut client = tc.connect().await?;
    let bytes = wallet.clone().create_custom_mint(authority, vec![(recipient, amount)], entitlement, 1,
        NativeBudget { max_native_bytes: 24 << 30 }).await?;
    if let Some((payee, price, wait)) = paid {
        // Paid mint: the claim's settlement pays the provers; its payment coin
        // pays the price to the token's payee.
        let quil_context = quil_lattice_ct::confidential::transfer::parameter_context(&network, &quil_execution::domains::QUIL_TOKEN);
        let payee = RecipientAddress::decode(&hex::decode(payee.strip_prefix("0x").unwrap_or(payee))?, &quil_context)
            .map_err(|e| anyhow::anyhow!("payee address: {e:?}"))?;
        submit_paid_operation(tc, &wallet, bytes, Some((payee, price)), wait).await?;
        println!("Paid custom-token mint submitted with its claim. Finalized inclusion is not yet confirmed.");
        return Ok(());
    }
    submit_operation(tc, &wallet, &mut client, bytes).await?;
    println!("Confidential custom-token mint submitted. Finalized inclusion is not yet confirmed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "native-proof")]
    #[test]
    fn automatic_fee_headroom_rounds_up_and_checks_range() {
        assert_eq!(super::with_fee_headroom(0).unwrap(), 0);
        assert_eq!(super::with_fee_headroom(1).unwrap(), 2);
        assert_eq!(super::with_fee_headroom(3_199_680).unwrap(), 3_519_648);
        // The observed vote drift (99 → 100, ~1%) stays covered.
        assert!(super::with_fee_headroom(3_199_680).unwrap() >= 3_199_900);
        assert!(super::with_fee_headroom(u128::MAX).is_err());
    }

    #[cfg(feature = "native-proof")]
    #[test]
    fn quoted_quil_fee_checks_context_amount_and_recomputes_budget() {
        let quote = quil_types::proto::node::GetTokenFeeQuoteResponse {
            application: quil_execution::domains::QUIL_TOKEN.to_vec(), network: vec![0; 32],
            observed_frame: 42, global_execution: true, difficulty: 50_000,
            world_state_bytes: 0, fee_multiplier_vote: 1, max_payload_bytes: 64,
            fee_budget: 127u128.to_be_bytes().to_vec(),
        };
        // The exact charge for 64 bytes of growth is multiplier (1) × 64, not
        // the conservative budget of 127 the quote carries.
        assert_eq!(super::checked_quil_fee_quote(&quote, &[0; 32], 64).unwrap(), 64);
        assert!(super::check_submission_fee_quote(&quote, &[0; 32], 64, 64).is_ok());
        assert!(super::check_submission_fee_quote(&quote, &[0; 32], 64, 63).is_err());
        let higher = quil_types::proto::node::GetTokenFeeQuoteResponse {
            global_execution: false, fee_multiplier_vote: 3,
            fee_budget: 381u128.to_be_bytes().to_vec(), ..quote.clone()
        };
        assert_eq!(super::checked_quil_fee_quote(&higher, &[0; 32], 64).unwrap(), 192);
        assert!(super::check_submission_fee_quote(&higher, &[0; 32], 64, 64).is_err());
        assert!(super::check_submission_fee_quote(&higher, &[0; 32], 64, 192).is_ok());
        for case in 0..7 {
            let mut bad = quote.clone();
            match case {
                0 => bad.network[0] ^= 1,
                1 => bad.application[0] ^= 1,
                2 => bad.max_payload_bytes += 1,
                3 => { bad.fee_budget.pop(); },
                4 => bad.fee_budget = 126u128.to_be_bytes().to_vec(),
                5 => bad.world_state_bytes = u64::MAX,
                _ => { bad.fee_multiplier_vote = 2; bad.fee_budget = 254u128.to_be_bytes().to_vec(); },
            }
            assert!(super::checked_quil_fee_quote(&bad, &[0; 32], 64).is_err(), "case {case}");
        }
        // A non-mainnet network prices growth at the fixed rate whatever the
        // world size: 64 bytes at vote 1 cost 64 units even in a 1-byte world.
        let mut testnet = [0u8; 32];
        testnet[31] = 1;
        let small_world = quil_types::proto::node::GetTokenFeeQuoteResponse {
            network: testnet.to_vec(), world_state_bytes: 1, difficulty: 5_000,
            fee_budget: 64u128.to_be_bytes().to_vec(), ..quote.clone()
        };
        assert_eq!(super::checked_quil_fee_quote(&small_world, &testnet, 64).unwrap(), 64);
        // A malformed network identifier cannot be priced.
        assert!(super::checked_quil_fee_quote(&quote, &[7; 32], 64).is_err());
    }

    use super::*;
    use quil_lattice_ct::confidential::{
        memo::create_output, relation::membership::MembershipKey,
    };

    #[cfg(feature = "native-proof")]
    #[tokio::test]
    async fn witness_retry_handles_transience_and_bounds_hung_requests() {
        let mut attempts = 0;
        let value = retry_witness_request(std::time::Duration::from_secs(5), || {
            attempts += 1; let attempt = attempts;
            async move { match attempt {
                1 => Err(tonic::Status::unavailable("index building")),
                2 => Err(tonic::Status::resource_exhausted("busy")),
                _ => Ok(7),
            } }
        }).await.unwrap();
        assert_eq!((value, attempts), (7, 3));
        let mut attempts = 0;
        let error = retry_witness_request(std::time::Duration::from_secs(5), || {
            attempts += 1;
            async { Err::<(), _>(tonic::Status::invalid_argument("bad request")) }
        }).await.unwrap_err();
        assert_eq!((error.code(), attempts), (tonic::Code::InvalidArgument, 1));
        let error = retry_witness_request(std::time::Duration::from_millis(10), ||
            std::future::pending::<Result<(), tonic::Status>>()).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
        let error = retry_witness_request(std::time::Duration::from_millis(10), ||
            async { Err::<(), _>(tonic::Status::unavailable("building")) }).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
    }

    #[test]
    fn wallet_prepares_custom_mints_under_a_configured_or_permissionless_authority() {
        use quil_execution::token_intrinsic::custom_mint::verify_authority_signature;
        use quil_types::crypto::{KeyType, Signer};
        let network = [63; 32];
        let application = [64; 32];
        let keys = sntrup761::Sntrup761KeyPair::generate();
        let wallet = RecipientWallet::from_keys(&network, &application, &keys.public, Zeroizing::new(keys.secret.clone())).unwrap();
        // Mint authorities are post-quantum only.
        let falcon = quil_crypto::FalconSigner::generate();
        let public = falcon.public_key().to_vec();
        let signer: std::sync::Arc<dyn Signer> = std::sync::Arc::new(falcon);
        let recipients = vec![(wallet.address().clone(), u128::MAX - 5), (wallet.address().clone(), 5)];
        let (statement, signature, relation) = wallet.prepare_custom_mint(Some(&signer), &recipients, Vec::new(), 2).unwrap();
        assert!(relation.validate_local_witness());
        assert_eq!(statement.amount, u128::MAX);
        assert_eq!(statement.authority_key_type, KeyType::Falcon512 as u32);
        assert_eq!(statement.authority_public_key, public);
        assert!(!statement.is_permissionless());
        let context = statement.context_bytes().unwrap();
        verify_authority_signature(statement.authority_key_type, &statement.authority_public_key, &context, &wallet.context, &signature).unwrap();
        assert!(verify_authority_signature(statement.authority_key_type, &statement.authority_public_key, &context, &[0; 32], &signature).is_err());
        // A classical authority is refused as a key type, never verified.
        let seed = [65u8; 57];
        let classical = quil_crypto::Ed448Signer::derive_public(&seed).unwrap();
        let classical = quil_crypto::Ed448Signer::from_bytes(&seed, &classical).unwrap();
        let classical: std::sync::Arc<dyn Signer> = std::sync::Arc::new(classical);
        let error = match wallet.prepare_custom_mint(Some(&classical), &recipients, Vec::new(), 2) {
            Ok(_) => panic!("a classical mint authority was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("post-quantum"), "{error}");
        // Fresh nonces separate otherwise identical issuances.
        let (again, _, _) = wallet.prepare_custom_mint(Some(&signer), &recipients, Vec::new(), 2).unwrap();
        assert_ne!(again.nonce, statement.nonce);
        // Recipients recover their outputs like any confidential coin.
        for ((_, amount), output) in recipients.iter().zip(&statement.outputs) {
            assert_eq!(open_output(&wallet.context, &wallet.kem_secret, &wallet.recipient, output).unwrap().amount, *amount);
        }
        // Permissionless statements carry no authority and no signature.
        let (open, empty, open_relation) = wallet.prepare_custom_mint(None, &recipients[..1], Vec::new(), 1).unwrap();
        assert!(open.is_permissionless() && empty.is_empty() && open_relation.validate_local_witness());
        assert!(wallet.prepare_custom_mint(Some(&signer), &recipients, Vec::new(), 1).is_err());
        assert!(wallet.prepare_custom_mint(Some(&signer), &[(wallet.address().clone(), 0)], Vec::new(), 2).is_err());
        assert!(wallet.prepare_custom_mint(Some(&signer), &[(wallet.address().clone(), u128::MAX), (wallet.address().clone(), 1)], Vec::new(), 2).is_err());
        let foreign = RecipientWallet::from_keys(&network, &[66; 32], &keys.public, Zeroizing::new(keys.secret.clone())).unwrap();
        assert!(wallet.prepare_custom_mint(Some(&signer), &[(foreign.address().clone(), 1)], Vec::new(), 2).is_err());
        let quil = RecipientWallet::from_keys(&network, &quil_execution::domains::QUIL_TOKEN, &keys.public, Zeroizing::new(keys.secret)).unwrap();
        assert!(quil.prepare_custom_mint(Some(&signer), &[(quil.address().clone(), 1)], Vec::new(), 2).is_err());
    }

    #[test]
    fn escrow_addresses_bind_recipient_and_falcon_authority() {
        use quil_types::crypto::Signer;
        let keys = sntrup761::Sntrup761KeyPair::generate();
        let wallet = RecipientWallet::from_keys(&[67; 32], &[68; 32], &keys.public, Zeroizing::new(keys.secret)).unwrap();
        let authority = quil_crypto::FalconSigner::generate();
        let encoded = encode_escrow_address(wallet.address(), authority.public_key()).unwrap();
        let (address, key) = parse_escrow_address(&encoded, &wallet.context).unwrap();
        assert_eq!(address.encode(), wallet.address().encode());
        assert_eq!(key.as_slice(), authority.public_key());
        assert!(encode_escrow_address(wallet.address(), &[0; 10]).is_err());
        assert!(parse_escrow_address(&encoded[..encoded.len() - 2], &wallet.context).is_err());
        assert!(parse_escrow_address(&encoded, &[69; 32]).is_err());
        assert!(parse_escrow_address(&format!("0x{}", hex::encode(wallet.address().encode())), &wallet.context).is_err());
    }

    #[test]
    fn split_and_merge_selection_respect_circuit_bounds_and_overflow() {
        assert_eq!(split_amounts(10, &[3], 2, 2).unwrap(), vec![3, 5]);
        assert_eq!(split_amounts(10, &[3, 5], 2, 2).unwrap(), vec![3, 5]);
        assert_eq!(split_amounts(u128::MAX, &[u128::MAX - 1], 0, 2).unwrap(), vec![u128::MAX - 1, 1]);
        assert!(split_amounts(10, &[3, 4], 2, 2).is_err()); // remainder needs a third output
        assert!(split_amounts(10, &[9], 2, 2).is_err());
        assert!(split_amounts(10, &[], 0, 2).is_err());
        assert!(split_amounts(10, &[0], 0, 2).is_err());
        assert!(split_amounts(u128::MAX, &[u128::MAX], 1, 2).is_err());
        let keys = sntrup761::Sntrup761KeyPair::generate();
        let wallet = RecipientWallet::from_keys(&[70; 32], &[71; 32], &keys.public, Zeroizing::new(keys.secret)).unwrap();
        let coins = |amounts: &[u128]| wallet.recover_page(amounts.iter().enumerate().map(|(i, amount)| {
            ([i as u8 + 1; 32], create_output(&wallet.context, wallet.address(), *amount).unwrap().output)
        }).collect()).unwrap();
        let (selected, total) = merge_selection(coins(&[5, 0, 9, 7, 1, 2]), &[], 4).unwrap();
        assert_eq!(selected.iter().map(|coin| *coin.amount).collect::<Vec<_>>(), vec![9, 7, 5, 2]);
        assert_eq!(total, 23);
        let (selected, total) = merge_selection(coins(&[5, 9, 7]), &[[1; 32], [3; 32]], 4).unwrap();
        assert_eq!(selected.iter().map(|coin| *coin.amount).collect::<Vec<_>>(), vec![5, 7]);
        assert_eq!(total, 12);
        assert!(merge_selection(coins(&[5, 9]), &[[1; 32], [9; 32]], 4).is_err());
        assert!(merge_selection(coins(&[5]), &[], 4).is_err());
        assert!(merge_selection(coins(&[1, 2, 3]), &[[1; 32], [2; 32], [3; 32]], 2).is_err());
        assert!(merge_selection(coins(&[u128::MAX, 1]), &[], 4).is_err());
    }

    #[test]
    fn coin_selection_handles_wide_totals_change_and_input_limits() {
        let keys = sntrup761::Sntrup761KeyPair::generate();
        let wallet = RecipientWallet::from_keys(&[61; 32], &[62; 32], &keys.public, Zeroizing::new(keys.secret)).unwrap();
        let coins = |amounts: &[u128]| wallet.recover_page(amounts.iter().enumerate().map(|(i, amount)| {
            ([i as u8 + 1; 32], create_output(&wallet.context, wallet.address(), *amount).unwrap().output)
        }).collect()).unwrap();
        let (selected, change) = select_coins(coins(&[1, 20, 3]), 11, 2, 1).unwrap();
        assert_eq!(selected.len(), 1); assert_eq!(*selected[0].amount, 20); assert_eq!(*change, 7);
        let (selected, change) = select_coins(coins(&[u128::MAX, u128::MAX]), u128::MAX, u128::MAX, 2).unwrap();
        assert_eq!(selected.len(), 2); assert_eq!(*change, 0);
        let (selected, change) = select_coins(coins(&[u128::MAX, 8]), u128::MAX, 2, 2).unwrap();
        assert_eq!(selected.len(), 2); assert_eq!(*change, 6);
        assert!(select_coins(coins(&[6, 6]), 10, 0, 1).is_err());
        assert!(select_coins(coins(&[7]), 8, 0, 4).is_err());
        assert!(select_coins(Vec::new(), 0, 0, 4).is_err());
        let output = create_output(&wallet.context, wallet.address(), 7).unwrap().output;
        let duplicate = wallet.recover_page(vec![([1; 32], output.clone()), ([2; 32], output)]).unwrap();
        assert!(select_coins(duplicate, 10, 0, 2).is_err());
    }
    #[test]
    fn wallet_prepares_pending_claims_from_authenticated_recovery_and_selected_authority() {
        use quil_lattice_ct::confidential::{memo::create_escrow_recovery,
            pending_claim::{ClaimBranch, EscrowPolicy, PendingClaim}};
        use quil_execution::token_intrinsic::escrow::{create_escrow, StoredEscrow};
        use quil_types::crypto::Signer;
        let network = [71; 32]; let application = quil_execution::domains::QUIL_TOKEN;
        let wallets: Vec<_> = (0..2).map(|_| {
            let keys = sntrup761::Sntrup761KeyPair::generate();
            RecipientWallet::from_keys(&network, &application, &keys.public, Zeroizing::new(keys.secret)).unwrap()
        }).collect();
        let signers = [quil_crypto::FalconSigner::generate(), quil_crypto::FalconSigner::generate()];
        let recovery = create_escrow_recovery(&wallets[0].context, wallets[0].address(), wallets[1].address(), u128::MAX).unwrap();
        let record = StoredEscrow { frame_number: 1,
            output: Output { commitment: recovery.commitment, owner: recovery.recipient.owner, memo: recovery.recipient.ciphertext },
            policy: EscrowPolicy { recipient: signers[0].public_key().try_into().unwrap(), refund: signers[1].public_key().try_into().unwrap(), refund_after_global_frame: 100 },
            refund_recovery: recovery.refund };
        let address = create_escrow(&wallets[0].context, record.frame_number, &record.output, &record.policy, &record.refund_recovery).unwrap().0;
        let response = quil_types::proto::node::GetVertexDataResponse {
            present: Some(true),
            raw_data: record.encode(&wallets[0].context).unwrap().1, entries: Vec::new(),
            set_type: "vertex".into(), phase_type: "adds".into(), shard_l2: application.to_vec(),
            shard_l1: quil_hypergraph::addressing::get_bloom_filter_indices(&application, 256, 3).to_vec(),
        };
        let scan_page = quil_types::proto::node::ListEscrowsResponse {
            network: network.to_vec(), snapshot_id: vec![3; 32],
            escrows: vec![quil_types::proto::node::Escrow { address: address.to_vec(), raw_data: record.encode(&wallets[0].context).unwrap().1 }],
            cursor: address.to_vec(), has_more: true,
        };
        let mut scan = CoinScan::new(2).unwrap();
        for mode in 0..3 {
            let mut bad = scan_page.clone();
            match mode {
                0 => bad.network[0] ^= 1,
                1 => bad.escrows[0].raw_data.push(0),
                _ => bad.escrows[0].address[0] ^= 1,
            }
            assert!(wallets[0].decode_escrow_page(&mut scan, bad).is_err());
            assert!(scan.snapshot_id.is_none()); assert_eq!(scan.remaining_pages, 2);
        }
        assert_eq!(wallets[0].decode_escrow_page(&mut scan, scan_page.clone()).unwrap()[0].0, address);
        let mut changed = scan_page.clone(); changed.snapshot_id[0] ^= 1;
        assert!(wallets[0].decode_escrow_page(&mut scan, changed).is_err());
        assert_eq!(scan.remaining_pages, 1);
        assert!(wallets[0].decode_escrow_page(&mut scan, scan_page).is_err());
        assert_eq!(wallets[0].decode_escrow_response(address, response.clone()).unwrap(), record);
        // GLOBAL commit records: presence decides, the shard must be GLOBAL.
        let global = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS;
        let mut record_response = response.clone();
        record_response.shard_l2 = global.to_vec();
        record_response.shard_l1 = quil_hypergraph::addressing::get_bloom_filter_indices(&global, 256, 3).to_vec();
        assert!(RecipientWallet::decode_global_record(record_response.clone()).unwrap().0);
        let mut missing = record_response.clone(); missing.present = Some(false); missing.raw_data.clear();
        assert_eq!(RecipientWallet::decode_global_record(missing.clone()).unwrap(), (false, Vec::new()));
        missing.present = None;
        assert!(RecipientWallet::decode_global_record(missing).is_err());
        let mut inconsistent = record_response.clone(); inconsistent.present = Some(false);
        assert!(RecipientWallet::decode_global_record(inconsistent).is_err());
        // An application-shard answer is not a GLOBAL record.
        assert!(RecipientWallet::decode_global_record(response.clone()).is_err());
        assert!(wallets[0].decode_escrow_response([0; 32], response.clone()).is_err());
        let mut altered = response.clone(); altered.raw_data.push(0);
        assert!(wallets[0].decode_escrow_response(address, altered).is_err());
        let mut altered = response.clone(); altered.raw_data.clear();
        assert!(wallets[0].decode_escrow_response(address, altered).is_err());
        let mut altered = response.clone(); altered.raw_data.resize(quil_execution::token_intrinsic::escrow::MAX_ESCROW_BLOB_BYTES + 1, 0);
        assert!(wallets[0].decode_escrow_response(address, altered).is_err());
        let mut altered = response.clone(); altered.shard_l2[0] ^= 1;
        assert!(wallets[0].decode_escrow_response(address, altered).is_err());
        let mut altered = response.clone(); altered.shard_l1[0] ^= 1;
        assert!(wallets[0].decode_escrow_response(address, altered).is_err());
        let mut altered = response.clone(); altered.phase_type = "removes".into();
        assert!(wallets[0].decode_escrow_response(address, altered).is_err());
        let mut altered = response.clone(); altered.set_type = "hyperedge".into();
        assert!(wallets[0].decode_escrow_response(address, altered).is_err());
        let mut altered = response; altered.entries.push(quil_types::proto::node::VertexDataEntry { key: vec![0], value: vec![0] });
        assert!(wallets[0].decode_escrow_response(address, altered).is_err());
        let outputs = [(wallets[0].address(), u128::MAX - 258), (wallets[1].address(), 256)];
        // The refund deadline (100) is judged at the anchor shards execute
        // at, GLOBAL_ANCHOR_SAFETY_MARGIN behind the head.
        let margin = quil_execution::token_intrinsic::constants::GLOBAL_ANCHOR_SAFETY_MARGIN;
        for (index, branch) in [ClaimBranch::Recipient, ClaimBranch::Refund].into_iter().enumerate() {
            let global = if index == 0 { None } else { Some(100 + margin) };
            let (statement, signature, relation) = wallets[index].prepare_pending_claim(address, &record, branch, global,
                &signers[index], &outputs, 2, 2).unwrap();
            assert!(relation.validate_local_witness());
            assert!(quil_crypto::falcon_verify(&signers[index].public_key(), &signature,
                &statement.context_bytes().unwrap(), &wallets[index].context));
            for (i, output) in statement.outputs.iter().enumerate() {
                assert_eq!(wallets[i].open(output).unwrap().amount, outputs[i].1);
            }
            assert!(wallets[index].prepare_pending_claim(address, &record, branch, global,
                &signers[1 - index], &outputs, 2, 2).is_err());
            assert!(wallets[index].prepare_pending_claim([0; 32], &record, branch, global,
                &signers[index], &outputs, 2, 2).is_err());
            assert!(wallets[index].prepare_pending_claim(address, &record, branch, global,
                &signers[index], &outputs, 1, 2).is_err());
            assert!(wallets[index].prepare_pending_claim(address, &record, branch, global,
                &signers[index], &outputs, 2, 1).is_err());
            // Submission checks framing/domain, not this placeholder proof.
            let mut proof = vec![0; 40]; proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
            let bytes = PendingClaim { statement, signature, proof }.encode().unwrap();
            let (destination, request) = wallets[index].prepare_submission(bytes.clone()).unwrap();
            assert_eq!(destination, application);
            assert_eq!(quil_execution::message_envelope::proto_message_request_to_canonical_inner_bytes(&request).unwrap(), bytes);
        }
        for global in [None, Some(99), Some(100), Some(99 + margin)] {
            assert!(wallets[1].prepare_pending_claim(address, &record, ClaimBranch::Refund, global, &signers[1], &outputs, 2, 2).is_err());
        }
        assert!(wallets[0].prepare_pending_claim(address, &record, ClaimBranch::Refund, Some(100 + margin), &signers[1], &outputs, 2, 2).is_err());
        let overflow = [(wallets[0].address(), u128::MAX), (wallets[1].address(), 1)];
        assert!(wallets[0].prepare_pending_claim(address, &record, ClaimBranch::Recipient, None, &signers[0], &overflow, 2, 2).is_err());
    }
    #[test]
    fn wallet_rejects_unchecked_or_malformed_reward_responses() {
        use quil_types::{crypto::Signer, proto::node::GetProverRewardWitnessResponse};
        let signer = quil_crypto::FalconSigner::generate();
        let public: [u8; 897] = signer.public_key().try_into().unwrap();
        let response = GetProverRewardWitnessResponse {
            found: true,
            value: 1u128.to_le_bytes().to_vec(),
            cited_frame: 7,
            reward_root: vec![8; 32],
            forest_proof: vec![1; 8],
        };
        assert!(RecipientWallet::decode_reward_claim(public, response.clone()).is_err());
        let mut missing = response.clone();
        missing.reward_root.clear();
        assert!(RecipientWallet::decode_reward_claim(public, missing)
            .unwrap_err()
            .to_string()
            .contains("checked root"));
        let mut width = response.clone();
        width.value.push(0);
        assert!(RecipientWallet::decode_reward_claim(public, width)
            .unwrap_err()
            .to_string()
            .contains("width"));
        let mut absent = response.clone();
        absent.found = false;
        assert!(RecipientWallet::decode_reward_claim(public, absent)
            .unwrap_err()
            .to_string()
            .contains("no claimable"));
        let mut oversized = response;
        oversized.forest_proof = vec![0; 32 * 1024 + 1];
        assert!(RecipientWallet::decode_reward_claim(public, oversized).is_err());
    }

    #[test]
    fn wallet_prepares_mint_with_bound_claimants_and_exact_balance() {
        use quil_lattice_ct::confidential::mint::{RewardClaim, MAX_REWARD_PROOF_BYTES};
        use std::sync::Arc;
        let keys = sntrup761::Sntrup761KeyPair::generate();
        let wallet = RecipientWallet::from_keys(
            &[1; 32],
            &quil_execution::domains::QUIL_TOKEN,
            &keys.public,
            Zeroizing::new(keys.secret),
        )
        .unwrap();
        let signers: Vec<Arc<dyn quil_types::crypto::Signer>> = (0..2)
            .map(|_| {
                Arc::new(quil_crypto::FalconSigner::generate())
                    as Arc<dyn quil_types::crypto::Signer>
            })
            .collect();
        let claims: Vec<_> = signers
            .iter()
            .zip([u128::MAX - 257, 257])
            .map(|(signer, value)| {
                let public_key: [u8; 897] = signer.public_key().try_into().unwrap();
                RewardClaim {
                    owner: quil_crypto::poseidon::hash_bytes_to_32(&public_key).unwrap(),
                    value,
                    public_key,
                    forest_proof: vec![1; 8],
                } // Structural fixture, not membership evidence.
            })
            .collect();
        let recipients = vec![
            (wallet.address().clone(), u128::MAX - 258),
            (wallet.address().clone(), 256),
        ];
        let prepare = |claims: &[RewardClaim], fee, max_claims, max_outputs| {
            wallet.prepare_mint(
                7,
                [8; 32],
                claims,
                &signers,
                &recipients,
                fee,
                max_claims,
                max_outputs,
            )
        };
        let (s, signatures, relation) = prepare(&claims, 2, 2, 2).unwrap();
        assert!(relation.validate_local_witness());
        // Transport fixture: signatures are real, the native proof is only a
        // framing placeholder. Submission construction must not claim admission.
        let mut placeholder = vec![0; 40];
        placeholder[..8].copy_from_slice(b"QPF6\0\0\0\0");
        let mint_bytes = quil_lattice_ct::confidential::mint::Mint {
            statement: s.clone(), signatures: signatures.clone(), proof: placeholder,
        }.encode().unwrap();
        let (destination, request) = wallet.prepare_submission(mint_bytes.clone()).unwrap();
        assert_eq!(destination, quil_execution::domains::GLOBAL);
        assert_eq!(quil_execution::message_envelope::proto_message_request_to_canonical_inner_bytes(&request).unwrap(), mint_bytes);
        let mut malformed = mint_bytes.clone();
        malformed.push(0);
        assert!(wallet.prepare_submission(malformed).is_err());
        let mut other_network = mint_bytes.clone();
        other_network[12] ^= 1;
        assert!(wallet.prepare_submission(other_network).is_err());
        let mut other_app = mint_bytes;
        other_app[44] ^= 1;
        assert!(wallet.prepare_submission(other_app).is_err());
        let claim_bytes = quil_lattice_ct::confidential::mint_claim::MintClaim {
            network: wallet.network, application: wallet.application, cited_global_frame: 9,
            global_root: [8; 32], receipt: [7; 32], fee: s.fee, outputs: s.outputs.clone(),
            forest_proof: vec![1],
        }.encode().unwrap();
        let (destination, request) = wallet.prepare_submission(claim_bytes.clone()).unwrap();
        assert_eq!(destination, wallet.application);
        assert_eq!(quil_execution::message_envelope::proto_message_request_to_canonical_inner_bytes(&request).unwrap(), claim_bytes);
        for (claim, signature) in claims.iter().zip(&signatures) {
            assert!(quil_crypto::falcon_verify(
                &claim.public_key,
                signature,
                &s.context_bytes().unwrap(),
                &wallet.context
            ));
            let mut changed = s.clone();
            changed.cited_frame += 1;
            assert!(!quil_crypto::falcon_verify(
                &claim.public_key,
                signature,
                &changed.context_bytes().unwrap(),
                &wallet.context
            ));
        }
        assert_eq!(wallet.open(&s.outputs[0]).unwrap().amount, u128::MAX - 258);
        assert_eq!(wallet.open(&s.outputs[1]).unwrap().amount, 256);
        for (fee, ci, co) in [(1, 2, 2), (3, 2, 2), (2, 1, 2), (2, 2, 1)] {
            assert!(prepare(&claims, fee, ci, co).is_err());
        }
        let mut changed = claims.clone();
        changed[0].owner = [99; 32];
        assert!(prepare(&changed, 2, 2, 2).is_err());
        let mut changed = claims.clone();
        changed[1].value += 1;
        assert!(prepare(&changed, 2, 2, 2).is_err());
        let mut changed = claims.clone();
        changed[0].forest_proof = vec![1; MAX_REWARD_PROOF_BYTES + 1];
        assert!(prepare(&changed, 2, 2, 2).is_err());
        let mut reversed = signers.clone();
        reversed.reverse();
        assert!(wallet
            .prepare_mint(7, [8; 32], &claims, &reversed, &recipients, 2, 2, 2)
            .is_err());
        assert!(wallet
            .prepare_mint(7, [8; 32], &claims, &[], &recipients, 2, 2, 2)
            .is_err());
    }

    #[test]
    fn wallet_prepares_shield_with_exact_balance_and_authorization() {
        let keys = sntrup761::Sntrup761KeyPair::generate();
        let wallet = RecipientWallet::from_keys(
            &[1; 32],
            &[2; 32],
            &keys.public,
            Zeroizing::new(keys.secret),
        )
        .unwrap();
        let keys = sntrup761::Sntrup761KeyPair::generate();
        let recipient = RecipientWallet::from_keys(
            &[1; 32],
            &[2; 32],
            &keys.public,
            Zeroizing::new(keys.secret),
        )
        .unwrap();
        let public = quil_crypto::Ed448Signer::derive_public(&[3; 57]).unwrap();
        let signer = quil_crypto::Ed448Signer::from_bytes(&[3; 57], &public).unwrap();
        let recipients = vec![
            (recipient.address().clone(), u128::MAX - 258),
            (wallet.address().clone(), 256),
        ];
        let (statement, signature, relation) = wallet
            .prepare_shield([4; 32], u128::MAX, &signer, &recipients, 2, 2)
            .unwrap();
        assert!(relation.validate_local_witness());
        assert!(quil_crypto::ed448_verify(
            &public,
            &statement.context_bytes().unwrap(),
            &signature
        ));
        assert_eq!(
            recipient.open(&statement.outputs[0]).unwrap().amount,
            u128::MAX - 258
        );
        assert_eq!(wallet.open(&statement.outputs[1]).unwrap().amount, 256);
        assert!(wallet.open(&statement.outputs[0]).is_err());
        assert!(wallet
            .prepare_shield([4; 32], u128::MAX, &signer, &recipients, 3, 2)
            .is_err());
        assert!(wallet
            .prepare_shield([4; 32], u128::MAX, &signer, &recipients, 1, 2)
            .is_err());
        assert!(wallet
            .prepare_shield([4; 32], u128::MAX, &signer, &recipients, 2, 1)
            .is_err());
        assert!(wallet
            .prepare_shield([4; 32], 0, &signer, &[], 0, 2)
            .is_err());
        let overflow = vec![
            (recipient.address().clone(), u128::MAX),
            (wallet.address().clone(), 1),
        ];
        assert!(wallet
            .prepare_shield([4; 32], 0, &signer, &overflow, 0, 2)
            .is_err());
        let keys = sntrup761::Sntrup761KeyPair::generate();
        let other = RecipientWallet::from_keys(
            &[9; 32],
            &[2; 32],
            &keys.public,
            Zeroizing::new(keys.secret),
        )
        .unwrap();
        assert!(wallet
            .prepare_shield([4; 32], 1, &signer, &[(other.address().clone(), 1)], 0, 1)
            .is_err());
        let mut changed = statement;
        changed.transparent_address[0] ^= 1;
        assert!(!quil_crypto::ed448_verify(
            &public,
            &changed.context_bytes().unwrap(),
            &signature
        ));
    }

    #[test]
    fn wallet_prepares_owned_transfer_and_rejects_invalid_selection() {
        use quil_lattice_ct::confidential::{
            coin_tree::{CoinRecord, CoinTree},
            transfer::CompileLimits,
        };
        let keys = sntrup761::Sntrup761KeyPair::generate();
        let wallet = RecipientWallet::from_keys(
            &[1; 32],
            &[2; 32],
            &keys.public,
            Zeroizing::new(keys.secret.clone()),
        )
        .unwrap();
        let other_keys = sntrup761::Sntrup761KeyPair::generate();
        let recipient = RecipientWallet::from_keys(
            &[1; 32],
            &[2; 32],
            &other_keys.public,
            Zeroizing::new(other_keys.secret),
        )
        .unwrap();
        // Aggregate exceeds u128; individual notes and fee are representable.
        let outputs: Vec<_> = [u128::MAX, 8]
            .iter()
            .map(|amount| {
                create_output(&wallet.context, wallet.address(), *amount)
                    .unwrap()
                    .output
            })
            .collect();
        let records: Vec<_> = outputs
            .iter()
            .enumerate()
            .map(|(i, output)| CoinRecord {
                address: [i as u8 + 1; 32],
                owner: output.owner,
                commitment: output.commitment.clone(),
                position: i as u64,
            })
            .collect();
        let tree = CoinTree::build(&wallet.context, &records, 1, 8).unwrap();
        let foreign = create_output(&wallet.context, recipient.address(), 9).unwrap().output;
        let mut page: Vec<_> = records.iter().zip(&outputs).map(|(record, output)| (record.address, output.clone())).collect();
        page.push(([3; 32], foreign));
        let recovered = wallet.recover_page(page).unwrap();
        assert_eq!(recovered.len(), 2);
        for (index, coin) in recovered.iter().enumerate() {
            assert_eq!(coin.address, records[index].address);
            assert_eq!(coin.output, outputs[index]);
            assert_eq!(*coin.amount, [u128::MAX, 8][index]);
            let opened = wallet.open(&outputs[index]).unwrap();
            assert_eq!(coin.image, MembershipKey::derive(&wallet.context).key_image(&opened.secrets.owner).identity_bytes().unwrap());
        }
        let root = tree.root_at_depth(1).unwrap();
        let paths: Vec<_> = records
            .iter()
            .map(|record| tree.auth_path(&record.address, 1).unwrap())
            .collect();
        let coins: Vec<_> = records
            .iter()
            .zip(&outputs)
            .map(|(record, output)| (record.address, output))
            .collect();
        let destinations = [(recipient.address(), u128::MAX), (wallet.address(), 6)];
        let limits = CompileLimits {
            max_inputs: 2,
            max_outputs: 2,
            max_depth: 1,
        };
        let (statement, relation) = wallet
            .prepare_transfer(&coins, &root, &paths, &destinations, 2, limits)
            .unwrap();
        assert!(relation.validate_local_witness());
        assert_eq!(
            recipient.open(&statement.outputs[0]).unwrap().amount,
            u128::MAX
        );
        assert_eq!(wallet.open(&statement.outputs[1]).unwrap().amount, 6);
        assert!(wallet.open(&statement.outputs[0]).is_err());
        assert_eq!(statement.fee, 2);
        assert_ne!(statement.images[0], statement.images[1]);
        {
            use quil_lattice_ct::confidential::{memo::{open_escrow_recovery, EscrowRecoveryMemo},
                pending_claim::EscrowPolicy, pending_create::PendingCreate};
            use quil_types::crypto::Signer;
            let to = quil_crypto::FalconSigner::generate();
            let back = quil_crypto::FalconSigner::generate();
            let mut escrow = EscrowDestination { recipient: recipient.address().clone(), refund: wallet.address().clone(),
                amount: u128::MAX, policy: EscrowPolicy { recipient: to.public_key().try_into().unwrap(),
                    refund: back.public_key().try_into().unwrap(), refund_after_global_frame: 100 } };
            // This fixture is a custom application, so its outflow fee is zero.
            let change = [(wallet.address(), 8)];
            let (pending, relation) = wallet.prepare_pending_create(&coins, &root, &paths, &escrow, &change, 0, limits).unwrap();
            assert!(relation.validate_local_witness());
            let (output, change_outputs) = pending.split_outputs().unwrap();
            assert_eq!(change_outputs.len(), 1);
            assert_eq!(wallet.open(&change_outputs[0]).unwrap().amount, 8);
            let to_recovery = EscrowRecoveryMemo { owner: output.owner, ciphertext: output.memo };
            for (party, recovery) in [(&recipient, &to_recovery), (&wallet, &pending.refund_recovery)] {
                let opened = open_escrow_recovery(&party.context, &party.kem_secret, &party.recipient, &output.commitment, recovery).unwrap();
                assert_eq!(opened.amount(), u128::MAX);
            }
            assert_eq!(pending.policy, escrow.policy);
            assert!(wallet.prepare_pending_create(&coins, &root, &paths, &escrow, &change, 1, limits).is_err());
            assert!(wallet.prepare_pending_create(&coins, &root, &paths, &escrow, &change, 0,
                CompileLimits { max_outputs: 1, ..limits }).is_err());
            assert!(wallet.prepare_pending_create(&[coins[0], coins[0]], &root, &paths, &escrow, &change, 0, limits).is_err());
            escrow.amount -= 1;
            assert!(wallet.prepare_pending_create(&coins, &root, &paths, &escrow, &change, 0, limits).is_err());
            let mut proof = vec![0; 40]; proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
            let bytes = PendingCreate { statement: pending, proof }.encode().unwrap();
            let (destination, request) = wallet.prepare_submission(bytes.clone()).unwrap();
            assert_eq!(destination, wallet.application);
            assert_eq!(quil_execution::message_envelope::proto_message_request_to_canonical_inner_bytes(&request).unwrap(), bytes);
        }
        assert!(wallet
            .prepare_transfer(&coins, &root, &paths, &destinations, 3, limits)
            .is_err());
        assert!(wallet
            .prepare_transfer(
                &[coins[0], coins[0]],
                &root,
                &paths,
                &destinations,
                2,
                limits
            )
            .is_err());
        assert!(recipient
            .prepare_transfer(&coins, &root, &paths, &destinations, 2, limits)
            .is_err());
        let mut wrong_root = root.clone();
        wrong_root.context = [0; 32];
        assert!(wallet
            .prepare_transfer(&coins, &wrong_root, &paths, &destinations, 2, limits)
            .is_err());
        wrong_root = root.clone();
        wrong_root.root = quil_lattice_ct::confidential::relation::membership::Node::zero();
        assert!(wallet
            .prepare_transfer(&coins, &wrong_root, &paths, &destinations, 2, limits)
            .is_err());
        let mut wrong_paths: Vec<_> = paths
            .iter()
            .map(
                |path| quil_lattice_ct::confidential::coin_tree::AuthPath {
                    siblings: path.siblings.clone(),
                    right: path.right.clone(),
                },
            )
            .collect();
        wrong_paths[0].right[0] = !wrong_paths[0].right[0];
        assert!(wallet
            .prepare_transfer(&coins, &root, &wrong_paths, &destinations, 2, limits)
            .is_err());
        assert!(wallet
            .prepare_transfer(
                &coins,
                &root,
                &paths,
                &destinations,
                2,
                CompileLimits {
                    max_inputs: 1,
                    ..limits
                }
            )
            .is_err());
    }

    #[test]
    fn coin_scan_validates_contents_and_preserves_state_on_bad_pages() {
        use quil_lattice_ct::confidential::coin_tree::CoinRecord;
        use quil_types::proto::node::{ListCoinsResponse, ConfidentialCoin};
        let keys = sntrup761::Sntrup761KeyPair::generate();
        let wallet = RecipientWallet::from_keys(
            &[1; 32],
            &[2; 32],
            &keys.public,
            Zeroizing::new(keys.secret),
        )
        .unwrap();
        let output = create_output(&wallet.context, wallet.address(), 17)
            .unwrap()
            .output;
        use quil_execution::token_intrinsic::coin_blocks;
        // A coin sits where staging puts it: the block its address selects,
        // at that block's first index. (Its identity does not cover the
        // position, so any position yields the same address.)
        let (address, _) = quil_execution::token_intrinsic::state::create_coin(
            &wallet.context,
            5,
            &output,
            0,
        )
        .unwrap();
        let width = coin_blocks::INITIAL_BLOCK_BITS;
        let block = coin_blocks::block_for_address(width, &address).unwrap();
        let position = coin_blocks::position(width, block, 0).unwrap();
        let shape = coin_blocks::shape(width).unwrap();
        let tree = quil_lattice_ct::confidential::sharded_tree::ShardedCoinTree::build(
            &wallet.context,
            shape,
            &[CoinRecord {
                address,
                owner: output.owner,
                commitment: output.commitment.clone(),
                position,
            }],
        )
        .unwrap();
        let root = tree.root_at_depth(shape.depth()).unwrap();
        let first = ListCoinsResponse {
            network: wallet.network.to_vec(),
            snapshot_id: vec![7; 32],
            root_record: root.encode().unwrap().to_vec(),
            coins: vec![ConfidentialCoin {
                address: address.to_vec(),
                frame_number: 5,
                position,
                owner: output.owner.to_vec(),
                commitment: output.commitment.to_bytes().to_vec(),
                memo: output.memo.to_vec(),
            }],
            cursor: address.to_vec(),
            has_more: true,
        };
        let mut scan = CoinScan::new(3).unwrap();
        let mut bad = first.clone();
        bad.coins[0].memo[0] ^= 1;
        assert!(wallet.decode_scan_page(&mut scan, bad).is_err());
        assert!(scan.snapshot_id.is_none());
        assert_eq!(scan.remaining_pages, 3);
        // A serving node cannot move a coin into a block its address does not
        // select: the identity no longer covers the position, so this check is
        // what refuses it — a dense position, and another block's region.
        let other_block = coin_blocks::block_id(width, (block & ((1 << width) - 1)) ^ 1).unwrap();
        for wrong in [0, coin_blocks::position(width, other_block, 0).unwrap()] {
            let mut moved = first.clone();
            moved.coins[0].position = wrong;
            let error = wallet.decode_scan_page(&mut scan, moved).unwrap_err();
            assert!(error.to_string().contains("does not belong to its address"), "{error}");
            assert!(scan.snapshot_id.is_none(), "a refused page leaves the scan untouched");
        }
        let coins = wallet.decode_scan_page(&mut scan, first.clone()).unwrap();
        assert_eq!(coins, vec![(address, output)]);
        assert_eq!(wallet.open(&coins[0].1).unwrap().amount, 17);
        assert!(!scan.finished());
        // No coins in a page does not imply completion: metadata still advances.
        let next = ListCoinsResponse {
            coins: Vec::new(),
            cursor: vec![255; 32],
            ..first.clone()
        };
        for case in 0..4 {
            let mut bad = next.clone();
            match case {
                0 => bad.snapshot_id[0] ^= 1,
                1 => bad.cursor = address.to_vec(),
                2 => bad.network[0] ^= 1,
                _ => bad.root_record[8] ^= 1,
            }
            assert!(wallet.decode_scan_page(&mut scan, bad).is_err());
            assert_eq!(scan.after, Some(address));
            assert_eq!(scan.remaining_pages, 2);
        }
        assert!(wallet
            .decode_scan_page(&mut scan, next.clone())
            .unwrap()
            .is_empty());
        assert!(!scan.finished());
        let final_page = ListCoinsResponse {
            has_more: false,
            ..next
        };
        assert!(wallet
            .decode_scan_page(&mut scan, final_page.clone())
            .unwrap()
            .is_empty());
        assert!(scan.finished());
        assert!(wallet.decode_scan_page(&mut scan, final_page).is_err());
        assert!(CoinScan::new(0).is_err());
        let mut limited = CoinScan::new(1).unwrap();
        wallet
            .decode_scan_page(&mut limited, first.clone())
            .unwrap();
        assert!(wallet.decode_scan_page(&mut limited, first).is_err());
    }

    #[test]
    fn keystore_recipient_derivation_reopens_real_memos_after_reload() {
        let key = sntrup761::Sntrup761KeyPair::generate();
        let wallet = RecipientWallet::from_keys(
            &[1; 32],
            &[2; 32],
            &key.public,
            Zeroizing::new(key.secret.clone()),
        )
        .unwrap();
        let reloaded = RecipientWallet::from_keys(
            &[1; 32],
            &[2; 32],
            &key.public,
            Zeroizing::new(key.secret.clone()),
        )
        .unwrap();
        assert_eq!(wallet.address(), reloaded.address());
        let context = parameter_context(&[1; 32], &[2; 32]);
        let public = RecipientAddress::decode(&wallet.address().encode(), &context).unwrap();
        for amount in [0, 1, u128::MAX] {
            let output = create_output(&context, &public, amount).unwrap().output;
            let opened = reloaded.open(&output).unwrap();
            assert_eq!(opened.amount, amount);
            assert_eq!(
                MembershipKey::derive(&context)
                    .owner_key(&opened.secrets.owner)
                    .identity_bytes()
                    .unwrap(),
                output.owner
            );
        }
        let other = RecipientWallet::from_keys(
            &[1; 32],
            &[3; 32],
            &key.public,
            Zeroizing::new(key.secret.clone()),
        )
        .unwrap();
        assert_ne!(wallet.address(), other.address());
        let output = create_output(&context, &public, 7).unwrap().output;
        assert!(other.open(&output).is_err());
        let wrong = sntrup761::Sntrup761KeyPair::generate();
        assert!(RecipientWallet::from_keys(
            &[1; 32],
            &[2; 32],
            &key.public,
            Zeroizing::new(wrong.secret)
        )
        .is_err());
        assert!(RecipientWallet::from_keys(
            &[1; 32],
            &[2; 32],
            &key.public,
            Zeroizing::new(vec![])
        )
        .is_err());
    }
    #[test]
    fn context_identifiers_require_exact_hex_width() {
        assert_eq!(
            identifier(&format!("0x{}", "ab".repeat(32))).unwrap(),
            [0xab; 32]
        );
        for value in ["", "ab", &"ab".repeat(33), &"zz".repeat(32)] {
            assert!(identifier(value).is_err());
        }
    }
    #[test]
    fn wallet_checks_rpc_paths_against_selected_coin_and_context() {
        use quil_lattice_ct::confidential::{
            coin_tree::{CoinRecord, CoinTree},
            relation::membership::Node,
        };
        use quil_types::proto::node::{
            GetCoinWitnessesResponse, CoinWitness,
        };
        let key = sntrup761::Sntrup761KeyPair::generate();
        let wallet =
            RecipientWallet::from_keys(&[1; 32], &[2; 32], &key.public, Zeroizing::new(key.secret))
                .unwrap();
        let output = create_output(&wallet.context, wallet.address(), 7)
            .unwrap()
            .output;
        let address = [3; 32];
        let tree = CoinTree::build(
            &wallet.context,
            &[CoinRecord {
                address,
                owner: output.owner,
                commitment: output.commitment.clone(),
                position: 0,
            }],
            1,
            4,
        )
        .unwrap();
        let root = tree.root_at_depth(1).unwrap();
        let path = tree.auth_path(&address, 1).unwrap();
        let response = GetCoinWitnessesResponse {
            network: vec![1; 32],
            root_record: root.encode().unwrap().to_vec(),
            witnesses: vec![CoinWitness {
                address: address.to_vec(),
                found: true,
                siblings: path
                    .siblings
                    .iter()
                    .map(|node| node.to_bytes().to_vec())
                    .collect(),
                right: path.right,
            }],
        };
        assert!(wallet
            .decode_witnesses(&[(address, &output)], response.clone())
            .is_ok());
        let mut bad = response.clone();
        bad.network[0] ^= 1;
        assert!(wallet.decode_witnesses(&[(address, &output)], bad).is_err());
        let mut bad = response.clone();
        bad.root_record[8] ^= 1;
        assert!(wallet.decode_witnesses(&[(address, &output)], bad).is_err());
        let mut bad = response.clone();
        bad.witnesses[0].right[0] = !bad.witnesses[0].right[0];
        assert!(wallet.decode_witnesses(&[(address, &output)], bad).is_err());
        let mut bad = response.clone();
        bad.witnesses[0].siblings[0] = Node::from_identity_bytes(&[7; IDENTITY_BYTES])
            .unwrap()
            .to_bytes()
            .to_vec();
        assert!(wallet.decode_witnesses(&[(address, &output)], bad).is_err());
        let mut bad = response.clone();
        bad.witnesses[0].found = false;
        assert!(wallet.decode_witnesses(&[(address, &output)], bad).is_err());
        let mut other = output.clone();
        other.owner[0] ^= 1;
        assert!(wallet
            .decode_witnesses(&[(address, &other)], response)
            .is_err());
    }

    /// Batches never span shards: each coin goes to the deepest live shard
    /// covering it, groups are cut at the batch size, and coins no shard
    /// covers are set aside.
    #[test]
    fn shield_batches_stay_inside_one_shard_each() {
        let coin = |top: u8, n: u8| { let mut a = [n; 32]; a[0] = top; (a, u128::from(n) + 1) };
        let coins = vec![
            coin(0x10, 1), coin(0x20, 2), coin(0x30, 3), // under 0
            coin(0x90, 4), coin(0xa0, 5),                // under 10
            coin(0xc0, 6), coin(0xd0, 7), coin(0xd0, 7), // under 11 (one repeated)
        ];
        // A split-away parent ([true]) still listed beside its children.
        let shards = vec![vec![false], vec![true], vec![true, false], vec![true, true]];
        let (batches, uncovered) = shield_batches(coins.clone(), &shards, 2);
        assert!(uncovered.is_empty());
        let sizes: Vec<usize> = batches.iter().map(Vec::len).collect();
        assert_eq!(sizes, vec![2, 1, 2, 2], "three under 0 cut at 2; the children of 1 apart");
        for batch in &batches {
            let top = batch[0].address[0] & 0xc0;
            assert!(batch.iter().all(|s| if top < 0x80 { s.address[0] < 0x80 } else { s.address[0] & 0xc0 == top }));
            assert!(batch.windows(2).all(|p| p[0].address < p[1].address));
        }
        assert_eq!(batches.iter().map(Vec::len).sum::<usize>(), 7, "the repeated coin once");
        let (only_low, left) = shield_batches(coins, &[vec![false]], 96);
        assert_eq!((only_low.len(), left.len()), (1, 4));
    }
}
