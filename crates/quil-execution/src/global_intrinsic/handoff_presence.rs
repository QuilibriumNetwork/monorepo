//! Presence reports: the notarize votes of an app-shard session's members,
//! carried to GLOBAL as evidence of who votes.
//!
//! A session below quorum finalizes nothing, so no certificate shows which of
//! its members are present. A notarize vote does: it signs a real proposal
//! (round, parent view and payload) under the session namespace, and the
//! payload is Poseidon of the frame's output, which binds the GLOBAL frame
//! anchoring the frame's storage beacon. A report carries the proposal's
//! header, so GLOBAL recomputes that output: a vote it accepts was signed
//! after its anchor, in the inclusion frame's epoch. A nullify vote signs only
//! a round and can be signed ahead for every view; it earns no credit. From
//! [`super::presence_exclusion_frame`] a report may carry nullify votes too
//! (version [`VERSION_NULLIFY`]): one proves that its signer's key followed
//! the session after it was authorized, since the session namespace binds
//! the authorization, and it protects the signer from exclusion
//! ([`protected`]), never more.
//!
//! GLOBAL validates reports from [`super::presence_report_frame`]. From
//! [`super::presence_credit_frame`] it also records them ([`apply`]): each
//! voter is marked present for the session and the inclusion epoch
//! ([`present`]), and its allocation on the session's filter is credited
//! activity at its vote's anchor. Before that frame an accepted report
//! changes no state.

use std::collections::BTreeSet;

use quil_cw_consensus::handoff::{
    put_bytes, Cursor, Session, SessionVotes, MAX_FILTER_BYTES, MAX_RECORD_BYTES,
};
use quil_types::error::{QuilError, Result};

use super::{
    head, presence_report_frame, read, session, status, write, Records, Status,
    TYPE_PRESENCE_REPORT,
};
use crate::global_intrinsic::frame_header::FrameHeader;
use crate::hypergraph_state::HypergraphState;

/// Proposals one report may carry.
pub const MAX_PRESENCE_PROPOSALS: usize = 4;

/// Votes one report may carry over all its proposals, whatever its session's
/// size. It also carries at most one vote per session member.
pub const MAX_PRESENCE_VOTES: usize = 64;

const VERSION: u8 = 1;
/// The version of a report that carries nullify votes, accepted from
/// [`super::presence_exclusion_frame`]. A report without them keeps
/// [`VERSION`] and its encoding.
pub const VERSION_NULLIFY: u8 = 3;
const SIGNATURE_BYTES: usize = quil_crypto::FALCON_SIGNATURE_LEN;

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("presence report: {message}"))
}

/// One member's notarize vote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotarizeVote {
    /// The member's index in the session's sorted members.
    pub signer: u32,
    /// Its Falcon signature of the proposal's notarize subject.
    pub signature: Vec<u8>,
}

/// One member's nullify vote: its Falcon signature of the round (the
/// session's generation, `view`) under the session namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NullifyVote {
    pub view: u64,
    /// The member's index in the session's sorted members.
    pub signer: u32,
    pub signature: Vec<u8>,
}

/// A proposal of the session and the notarize votes it received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresenceProposal {
    /// The proposed app frame, without its certificate and its storage
    /// attestation openings: neither enters the frame's output.
    pub header: FrameHeader,
    /// The Simplex round: the session generation, and the view, which is the
    /// header's rank.
    pub epoch: u64,
    pub view: u64,
    pub parent: u64,
    /// Poseidon of the header's output.
    pub payload: [u8; 32],
    /// In ascending signer order.
    pub votes: Vec<NotarizeVote>,
}

/// Votes of one session's members, the GLOBAL operation [`TYPE_PRESENCE_REPORT`].
///
/// Encoding: type prefix ‖ version ‖ session ID ‖ filter ‖ proposal count
/// (u32) ‖ per proposal: canonical header bytes ‖ epoch ‖ view ‖ parent ‖
/// payload ‖ vote count (u32) ‖ per vote: signer (u32) ‖ signature; then,
/// with version [`VERSION_NULLIFY`] only, nullify count (u32) ‖ per nullify:
/// view ‖ signer (u32) ‖ signature. Proposals are in ascending view order,
/// nullifies in ascending signer order, and each member votes at most once
/// per report, notarize or nullify. A version-1 report carries a proposal
/// and no nullify; a version-3 one carries a nullify and may carry no
/// proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresenceReport {
    pub session: [u8; 32],
    pub filter: Vec<u8>,
    pub proposals: Vec<PresenceProposal>,
    pub nullifies: Vec<NullifyVote>,
}

impl PresenceReport {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = TYPE_PRESENCE_REPORT.to_be_bytes().to_vec();
        out.push(if self.nullifies.is_empty() {
            VERSION
        } else {
            VERSION_NULLIFY
        });
        out.extend_from_slice(&self.session);
        put_bytes(&mut out, &self.filter)?;
        out.extend_from_slice(&(self.proposals.len() as u32).to_be_bytes());
        for proposal in &self.proposals {
            put_bytes(&mut out, &proposal.header.to_canonical_bytes()?)?;
            out.extend_from_slice(&proposal.epoch.to_be_bytes());
            out.extend_from_slice(&proposal.view.to_be_bytes());
            out.extend_from_slice(&proposal.parent.to_be_bytes());
            out.extend_from_slice(&proposal.payload);
            out.extend_from_slice(&(proposal.votes.len() as u32).to_be_bytes());
            for vote in &proposal.votes {
                out.extend_from_slice(&vote.signer.to_be_bytes());
                out.extend_from_slice(&vote.signature);
            }
            if out.len() > MAX_RECORD_BYTES {
                return Err(invalid("report exceeds size limit"));
            }
        }
        if !self.nullifies.is_empty() {
            out.extend_from_slice(&(self.nullifies.len() as u32).to_be_bytes());
            for vote in &self.nullifies {
                out.extend_from_slice(&vote.view.to_be_bytes());
                out.extend_from_slice(&vote.signer.to_be_bytes());
                out.extend_from_slice(&vote.signature);
            }
        }
        Ok(out)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(bytes)?;
        c.magic(&TYPE_PRESENCE_REPORT.to_be_bytes())?;
        let version = c.u8()?;
        if version != VERSION && version != VERSION_NULLIFY {
            return Err(invalid("unknown version"));
        }
        let session = c.array()?;
        let filter = c.bytes(MAX_FILTER_BYTES)?;
        let n = c.count(MAX_PRESENCE_PROPOSALS, 4 + 3 * 8 + 32 + 4)?;
        let mut proposals = Vec::with_capacity(n);
        for _ in 0..n {
            let encoded = c.bytes(MAX_RECORD_BYTES)?;
            let header = FrameHeader::from_canonical_bytes(&encoded)?;
            // The header decoder tolerates trailing and legacy layouts; a
            // report admits exactly one encoding of each header.
            if header.to_canonical_bytes()? != encoded {
                return Err(invalid("noncanonical frame header"));
            }
            let epoch = c.u64()?;
            let view = c.u64()?;
            let parent = c.u64()?;
            let payload = c.array()?;
            let m = c.count(MAX_PRESENCE_VOTES, 4 + SIGNATURE_BYTES)?;
            let mut votes = Vec::with_capacity(m);
            for _ in 0..m {
                let signer = c.u32()?;
                let signature = c.take(SIGNATURE_BYTES)?.to_vec();
                votes.push(NotarizeVote { signer, signature });
            }
            proposals.push(PresenceProposal {
                header,
                epoch,
                view,
                parent,
                payload,
                votes,
            });
        }
        let mut nullifies = Vec::new();
        if version == VERSION_NULLIFY {
            let m = c.count(MAX_PRESENCE_VOTES, 8 + 4 + SIGNATURE_BYTES)?;
            for _ in 0..m {
                let view = c.u64()?;
                let signer = c.u32()?;
                let signature = c.take(SIGNATURE_BYTES)?.to_vec();
                nullifies.push(NullifyVote {
                    view,
                    signer,
                    signature,
                });
            }
            // One encoding per report: version 3 only with a nullify.
            if nullifies.is_empty() {
                return Err(invalid("a nullify report carries no nullify"));
            }
        }
        c.finish()?;
        let report = Self {
            session,
            filter,
            proposals,
            nullifies,
        };
        report.validate()?;
        Ok(report)
    }

    /// The votes the report carries over all its proposals and nullifies.
    pub fn vote_count(&self) -> usize {
        self.proposals
            .iter()
            .map(|proposal| proposal.votes.len())
            .sum::<usize>()
            + self.nullifies.len()
    }

    fn validate(&self) -> Result<()> {
        if !(32..=MAX_FILTER_BYTES).contains(&self.filter.len()) {
            return Err(invalid("invalid full shard filter length"));
        }
        if (self.proposals.is_empty() && self.nullifies.is_empty())
            || self.proposals.len() > MAX_PRESENCE_PROPOSALS
        {
            return Err(invalid("proposal count out of range"));
        }
        if self
            .proposals
            .windows(2)
            .any(|pair| pair[0].view >= pair[1].view)
        {
            return Err(invalid("proposals must be in ascending view order"));
        }
        if self.vote_count() > MAX_PRESENCE_VOTES {
            return Err(invalid("too many votes"));
        }
        let mut signers = BTreeSet::new();
        for proposal in &self.proposals {
            if proposal.votes.is_empty() {
                return Err(invalid("proposal carries no votes"));
            }
            if !proposal.header.public_key_signature_bls48581.is_empty()
                || !proposal.header.storage_attestation.is_empty()
            {
                return Err(invalid("header carries a certificate or storage openings"));
            }
            for vote in &proposal.votes {
                if vote.signature.len() != SIGNATURE_BYTES {
                    return Err(invalid("vote signature has the wrong length"));
                }
                if !signers.insert(vote.signer) {
                    return Err(invalid("duplicate signer"));
                }
            }
            if proposal
                .votes
                .windows(2)
                .any(|pair| pair[0].signer >= pair[1].signer)
            {
                return Err(invalid("votes must be in ascending signer order"));
            }
        }
        for vote in &self.nullifies {
            if vote.signature.len() != SIGNATURE_BYTES {
                return Err(invalid("vote signature has the wrong length"));
            }
            if vote.view == 0 {
                return Err(invalid("nullify of view zero"));
            }
            if !signers.insert(vote.signer) {
                return Err(invalid("duplicate signer"));
            }
        }
        if self
            .nullifies
            .windows(2)
            .any(|pair| pair[0].signer >= pair[1].signer)
        {
            return Err(invalid("nullifies must be in ascending signer order"));
        }
        Ok(())
    }
}

/// A GLOBAL operation of type [`TYPE_PRESENCE_REPORT`]: a presence report
/// (version 1) or an excluded member's presence claim (version
/// [`super::exclusion::CLAIM_VERSION`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresenceOp {
    Report(PresenceReport),
    Claim(super::exclusion::PresenceClaim),
}

impl PresenceOp {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.starts_with(&TYPE_PRESENCE_REPORT.to_be_bytes())
            && bytes.get(4) == Some(&super::exclusion::CLAIM_VERSION)
        {
            return super::exclusion::PresenceClaim::from_canonical_bytes(bytes).map(Self::Claim);
        }
        PresenceReport::from_canonical_bytes(bytes).map(Self::Report)
    }

    /// Refuse the operation before its activation frame, as an older build
    /// refuses it, before any state is read: a report before
    /// [`presence_report_frame`], a claim before
    /// [`super::presence_exclusion_frame`].
    pub fn require_active(&self, frame: u64) -> Result<()> {
        match self {
            Self::Report(report) => {
                require_active(frame)?;
                require_nullifies_active(report, frame)
            }
            Self::Claim(_) => super::exclusion::require_claims_active(frame),
        }
    }
}

impl PresenceOp {
    /// Whether the operation uses an encoding of the presence exclusion
    /// frame: a claim, or a report carrying nullify votes.
    pub fn extended(&self) -> bool {
        match self {
            Self::Report(report) => !report.nullifies.is_empty(),
            Self::Claim(_) => true,
        }
    }
}

/// Whether `bytes` encode a [`PresenceOp`] admitted at GLOBAL frame
/// `frame`: the frame whose body carries them, on every consensus path
/// (decoding, body binding, processing, materialization, archive ingest).
/// Before [`super::presence_exclusion_frame`] only version 1 reports are
/// admitted, as a build without the exclusion frame admits them, so a
/// GLOBAL frame below it carrying a claim or a nullify report is rejected
/// by every build alike, whatever the decoding node has seen. With no frame
/// (gossip, the mempool and the wire codec of a node's own submissions)
/// they are admitted once the exclusion frame is scheduled; the mempool
/// refuses them before the frame by its own check
/// ([`PresenceOp::require_active`]).
pub fn check_encoding(bytes: &[u8], frame: Option<u64>) -> Result<()> {
    check_encoding_in(
        bytes,
        frame.map_or(EncodingGate::Admission, EncodingGate::Global),
    )
}

/// Where presence encodings are judged ([`check_encoding_in`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodingGate {
    /// The body of the GLOBAL frame with this number: claims and nullify
    /// reports from [`super::presence_exclusion_frame`] on.
    Global(u64),
    /// Gossip, the mempool and a node's own submissions: claims and nullify
    /// reports once the exclusion frame is scheduled.
    Admission,
    /// An application shard's frame or messages: never a claim or a nullify
    /// report, which are GLOBAL operations. A version 1 report keeps the
    /// treatment a build without them gives it, so application committees
    /// and archives of every build judge an application frame alike.
    App,
}

/// [`check_encoding`] under `gate`.
pub fn check_encoding_in(bytes: &[u8], gate: EncodingGate) -> Result<()> {
    let op = PresenceOp::from_canonical_bytes(bytes)?;
    let activation = super::presence_exclusion_frame();
    let admitted = match gate {
        EncodingGate::Global(frame) => frame >= activation,
        EncodingGate::Admission => activation != u64::MAX,
        EncodingGate::App => false,
    };
    if op.extended() && !admitted {
        return Err(invalid(
            "encoding not accepted here: a GLOBAL operation of the presence exclusion frame",
        ));
    }
    Ok(())
}

/// Refuse a report that carries nullify votes before
/// [`super::presence_exclusion_frame`].
pub fn require_nullifies_active(report: &PresenceReport, frame: u64) -> Result<()> {
    if !report.nullifies.is_empty() && frame < super::presence_exclusion_frame() {
        return Err(invalid(
            "nullify votes are not accepted before the presence exclusion frame",
        ));
    }
    Ok(())
}

/// Refuse every report before [`presence_report_frame`].
pub fn require_active(frame: u64) -> Result<()> {
    if frame < presence_report_frame() {
        return Err(invalid("not accepted before the presence report frame"));
    }
    Ok(())
}

/// Validate `report` for inclusion in GLOBAL frame `frame`, without writing.
///
/// `anchor_output` returns a GLOBAL frame's output from this node's clock
/// store. It is asked only for anchors already checked to be earlier frames
/// of `frame`'s epoch, which every node materializing `frame` holds: a report
/// must not make a node look up a frame it may lack, since a missing anchor
/// stops materialization rather than refusing the report.
pub fn verify(
    state: &impl Records,
    frame: u64,
    report: &PresenceReport,
    anchor_output: impl Fn(u64) -> Result<Vec<u8>>,
) -> Result<()> {
    require_active(frame)?;
    require_nullifies_active(report, frame)?;
    report.validate()?;
    let epoch = quil_types::consensus::epoch_for_frame(frame);
    for proposal in &report.proposals {
        let anchor = proposal.header.global_frame_number;
        if anchor == 0 || anchor >= frame || quil_types::consensus::epoch_for_frame(anchor) != epoch
        {
            return Err(invalid(
                "anchor is not an earlier frame of the inclusion epoch",
            ));
        }
    }
    let session = session(state, &report.session)?.ok_or_else(|| invalid("unknown session"))?;
    if session.filter != report.filter {
        return Err(invalid("session belongs to another filter"));
    }
    if head(state, &report.filter)?.as_ref() != Some(&session) {
        return Err(invalid("session is not the current head of its filter"));
    }
    // A closing session still votes until its seal or fence; a closed one
    // no longer does.
    if matches!(status(state, &report.session)?, Status::Closed(_)) {
        return Err(invalid("session is closed"));
    }
    if report.vote_count() > session.members.len() {
        return Err(invalid("more votes than session members"));
    }
    // Reports pay no fee: from the credit frame each must mark a member the
    // epoch's record lacks, so a session's reports per epoch are bounded by
    // its members. Checked before any signature.
    if !marks_new_member(state, frame, &session, report)? {
        return Err(invalid(
            "marks no member not already recorded present this epoch",
        ));
    }
    for proposal in &report.proposals {
        let header = &proposal.header;
        if header.address != session.filter {
            return Err(invalid("header belongs to another filter"));
        }
        if proposal.epoch != session.generation {
            return Err(invalid("round epoch is not the session generation"));
        }
        if header.rank != proposal.view || proposal.view == 0 || proposal.parent >= proposal.view {
            return Err(invalid(
                "proposal view differs from the header rank or follows no parent",
            ));
        }
        if header.frame_number <= session.base_frame {
            return Err(invalid("header frame is not above the session base"));
        }
    }
    // A nullify signs only its round and stays valid for the session's
    // life: one must name a view above every view recorded in an earlier
    // epoch, so an old one cannot protect its signer again.
    if !report.nullifies.is_empty() {
        let floor = nullify_floor(state, &session, epoch)?;
        if report.nullifies.iter().any(|vote| vote.view <= floor) {
            return Err(invalid(
                "nullify view is not above the views recorded in earlier epochs",
            ));
        }
    }
    // The votes that add a mark are verified first, each signature before
    // its proposal's output, which is checked once: a report whose new
    // marks are forged costs one signature check (about 12 µs), not an
    // output check (about 1.3 ms) or one check per vote it carries.
    let (recorded, covered) = recorded_marks(state, frame, &session)?;
    #[derive(Clone, Copy)]
    enum Check {
        Notarize(usize, usize),
        Nullify(usize),
    }
    let mut order: Vec<(bool, Check)> = report
        .proposals
        .iter()
        .enumerate()
        .flat_map(|(index, proposal)| {
            let recorded = &recorded;
            proposal.votes.iter().enumerate().map(move |(vote, cast)| {
                (marked(recorded, cast.signer), Check::Notarize(index, vote))
            })
        })
        .chain(report.nullifies.iter().enumerate().map(|(index, cast)| {
            (
                marked(&recorded, cast.signer) || marked(&covered, cast.signer),
                Check::Nullify(index),
            )
        }))
        .collect();
    order.sort_by_key(|(old, _)| *old);
    let votes = SessionVotes::new(&session)?;
    let mut output_checked = vec![false; report.proposals.len()];
    for (_, check) in order {
        match check {
            Check::Notarize(index, vote) => {
                let proposal = &report.proposals[index];
                let vote = &proposal.votes[vote];
                if !votes.verify_notarize(
                    proposal.epoch,
                    proposal.view,
                    proposal.parent,
                    proposal.payload,
                    vote.signer,
                    &vote.signature,
                ) {
                    return Err(invalid(
                        "vote is not a session member's notarize of the proposal",
                    ));
                }
                if !output_checked[index] {
                    let output = anchor_output(proposal.header.global_frame_number)?;
                    crate::global_intrinsic::prover_shard_update::verify_app_frame_output(
                        &proposal.header,
                        &output,
                    )
                    .map_err(|_| invalid("header output does not match its fields and anchor"))?;
                    if quil_crypto::poseidon::hash_bytes_to_32(&proposal.header.output)?
                        != proposal.payload
                    {
                        return Err(invalid("payload is not the digest of the header output"));
                    }
                    output_checked[index] = true;
                }
            }
            Check::Nullify(index) => {
                let vote = &report.nullifies[index];
                if !votes.verify_nullify(
                    session.generation,
                    vote.view,
                    vote.signer,
                    &vote.signature,
                ) {
                    return Err(invalid(
                        "vote is not a session member's nullify of a round of the session",
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Whether member `signer` is marked in `marks`.
fn marked(marks: &[bool], signer: u32) -> bool {
    marks.get(signer as usize).copied().unwrap_or(false)
}

/// The members of `session` recorded present and protected in `frame`'s
/// epoch, none before [`super::presence_credit_frame`].
fn recorded_marks(
    state: &impl Records,
    frame: u64,
    session: &Session,
) -> Result<(Vec<bool>, Vec<bool>)> {
    if frame < super::presence_credit_frame() {
        return Ok((Vec::new(), Vec::new()));
    }
    let epoch = quil_types::consensus::epoch_for_frame(frame);
    Ok((
        present(state, session, epoch)?.unwrap_or_default(),
        protected(state, session, epoch)?.unwrap_or_default(),
    ))
}

/// Notarize votes a proposal must carry for its voters to earn credit: one
/// more than the faults a committee of `members` tolerates (members less
/// its quorum). Of that many voters at least one is honest, and an honest
/// member notarizes only the proposal its view's leader made, once it has
/// verified it, in the view it is in. Fewer votes prove only that their
/// keys are alive: anyone may notarize a header it made up, for any view.
/// The count is of the votes one report carries: a report holds one vote
/// per member, so a later report that adds a member's vote to an already
/// reported proposal carries fewer, and that member is marked present but
/// not credited.
pub fn credited_votes(members: usize) -> usize {
    members.saturating_sub(members * 2 / 3 + 1) + 1
}

/// Kind of the handoff record of a filter's nullify view watermark.
const NULLIFY_FLOOR: &[u8] = b"nullify-floor";

/// The highest nullify views recorded for a filter's session: in `epoch`
/// (`top`) and before it (`floor`). One record per filter, replaced when
/// its head session changes.
struct Watermark {
    session: [u8; 32],
    epoch: u64,
    floor: u64,
    top: u64,
}

fn read_watermark(state: &impl Records, filter: &[u8]) -> Result<Option<Watermark>> {
    let mut key = Vec::new();
    put_bytes(&mut key, filter)?;
    let Some(bytes) = read(state, NULLIFY_FLOOR, &key)? else {
        return Ok(None);
    };
    let corrupt = || QuilError::Store("corrupt nullify watermark".into());
    let mut c = Cursor::new(&bytes).map_err(|_| corrupt())?;
    if c.u8().map_err(|_| corrupt())? != RECORD_VERSION {
        return Err(corrupt());
    }
    let session = c.array().map_err(|_| corrupt())?;
    let epoch = c.u64().map_err(|_| corrupt())?;
    let floor = c.u64().map_err(|_| corrupt())?;
    let top = c.u64().map_err(|_| corrupt())?;
    c.finish().map_err(|_| corrupt())?;
    Ok(Some(Watermark {
        session,
        epoch,
        floor,
        top,
    }))
}

/// The highest nullify view of `session` that GLOBAL recorded in an epoch
/// before `epoch`, 0 if none: a nullify of `epoch` must name a later view.
/// A session stuck at one view is therefore protected in the first epoch
/// its nullifies are reported, and judged at the next boundary.
pub fn nullify_floor(state: &impl Records, session: &Session, epoch: u64) -> Result<u64> {
    let id = session.id()?;
    Ok(match read_watermark(state, &session.filter)? {
        Some(mark) if mark.session == id && mark.epoch < epoch => mark.floor.max(mark.top),
        Some(mark) if mark.session == id => mark.floor,
        _ => 0,
    })
}

/// Record `view` as a nullify view of `session` recorded in `epoch`.
fn note_nullify_view(
    state: &HypergraphState,
    frame: u64,
    session: &Session,
    epoch: u64,
    view: u64,
) -> Result<()> {
    let id = session.id()?;
    let floor = nullify_floor(state, session, epoch)?;
    let top = match read_watermark(state, &session.filter)? {
        Some(mark) if mark.session == id && mark.epoch == epoch => mark.top,
        _ => 0,
    };
    let mut key = Vec::new();
    put_bytes(&mut key, &session.filter)?;
    let mut value = vec![RECORD_VERSION];
    value.extend_from_slice(&id);
    value.extend_from_slice(&epoch.to_be_bytes());
    value.extend_from_slice(&floor.to_be_bytes());
    value.extend_from_slice(&top.max(view).to_be_bytes());
    write(state, frame, NULLIFY_FLOOR, &key, &value)
}

/// Kind of the handoff record of a filter's presence marks in an epoch.
const PRESENCE: &[u8] = b"presence";

/// Version of a mark record's encoding ([`marks`]).
const RECORD_VERSION: u8 = 1;

/// Epoch slots a filter's mark records cycle through: the current epoch's
/// and the previous one's, which the epoch's first maintenance pass reads.
/// A write to a slot that holds an older epoch replaces it, so the records
/// stay bounded by the shard grid, with nothing to prune: a deletion would
/// leave both the record and a tombstone in GLOBAL state.
const SLOTS: u64 = 2;

/// Sessions of one filter one slot holds at most: a filter rarely has more
/// than two in an epoch.
const MAX_SLOT_SESSIONS: usize = 16;

fn slot_key(filter: &[u8], epoch: u64) -> Result<Vec<u8>> {
    let mut key = Vec::new();
    put_bytes(&mut key, filter)?;
    key.push((epoch % SLOTS) as u8);
    Ok(key)
}

/// The sessions and member bitmaps of `kind` recorded for `filter` in
/// `epoch`, by ascending session ID; empty when its slot holds no record
/// or another epoch's.
///
/// Encoding: version (1) ‖ epoch (u64) ‖ count (u32) ‖ per session: ID ‖
/// bitmap (u32 length ‖ ⌈members / 8⌉ bytes, member `i` at bit `i % 8` of
/// byte `i / 8`).
fn read_slot(
    state: &impl Records,
    kind: &[u8],
    filter: &[u8],
    epoch: u64,
) -> Result<Vec<([u8; 32], Vec<u8>)>> {
    let Some(bytes) = read(state, kind, &slot_key(filter, epoch)?)? else {
        return Ok(Vec::new());
    };
    let corrupt = || QuilError::Store("corrupt presence mark record".into());
    let mut c = Cursor::new(&bytes).map_err(|_| corrupt())?;
    if c.u8().map_err(|_| corrupt())? != RECORD_VERSION {
        return Err(corrupt());
    }
    if c.u64().map_err(|_| corrupt())? != epoch {
        return Ok(Vec::new());
    }
    let count = c.count(MAX_SLOT_SESSIONS, 32 + 4).map_err(|_| corrupt())?;
    let mut entries: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(count);
    for _ in 0..count {
        let id: [u8; 32] = c.array().map_err(|_| corrupt())?;
        let bitmap = c
            .bytes(quil_cw_consensus::handoff::MAX_MEMBERS.div_ceil(8))
            .map_err(|_| corrupt())?;
        if entries.last().is_some_and(|(last, _)| *last >= id) {
            return Err(corrupt());
        }
        entries.push((id, bitmap));
    }
    c.finish().map_err(|_| corrupt())?;
    Ok(entries)
}

fn decode_bitmap(bitmap: &[u8], members: usize) -> Result<Vec<bool>> {
    let corrupt = || QuilError::Store("corrupt presence mark record".into());
    if bitmap.len() != members.div_ceil(8) {
        return Err(corrupt());
    }
    let bits: Vec<bool> = (0..bitmap.len() * 8)
        .map(|i| (bitmap[i / 8] >> (i % 8)) & 1 == 1)
        .collect();
    if bits[members..].iter().any(|&bit| bit) {
        return Err(corrupt());
    }
    Ok(bits[..members].to_vec())
}

fn encode_bitmap(marks: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; marks.len().div_ceil(8)];
    for (i, &member) in marks.iter().enumerate() {
        if member {
            out[i / 8] |= 1u8 << (i % 8);
        }
    }
    out
}

/// The members of `session` marked in `kind`'s records for `epoch`, by
/// member index; `None` while none is.
pub(super) fn marks(
    state: &impl Records,
    kind: &[u8],
    session: &Session,
    epoch: u64,
) -> Result<Option<Vec<bool>>> {
    let id = session.id()?;
    read_slot(state, kind, &session.filter, epoch)?
        .into_iter()
        .find(|(entry, _)| *entry == id)
        .map(|(_, bitmap)| decode_bitmap(&bitmap, session.members.len()))
        .transpose()
}

/// Record `marks` as `session`'s members marked in `kind`'s records for
/// `epoch`, replacing its earlier marks of the epoch, and a slot holding an
/// older epoch.
pub(super) fn set_marks(
    state: &HypergraphState,
    frame: u64,
    kind: &[u8],
    session: &Session,
    epoch: u64,
    marks: &[bool],
) -> Result<()> {
    let id = session.id()?;
    let mut entries = read_slot(state, kind, &session.filter, epoch)?;
    let bitmap = encode_bitmap(marks);
    match entries.binary_search_by(|(entry, _)| entry.cmp(&id)) {
        Ok(index) => entries[index].1 = bitmap,
        Err(index) => entries.insert(index, (id, bitmap)),
    }
    if entries.len() > MAX_SLOT_SESSIONS {
        return Err(invalid(
            "too many sessions of the filter recorded this epoch",
        ));
    }
    let mut out = vec![RECORD_VERSION];
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (entry, bitmap) in &entries {
        out.extend_from_slice(entry);
        put_bytes(&mut out, bitmap)?;
    }
    write(state, frame, kind, &slot_key(&session.filter, epoch)?, &out)
}

/// The members of `session` that GLOBAL recorded present in `epoch`, by
/// member index: those whose notarize votes an accepted report included in
/// a frame of that epoch carried. `None` while no report of the session and
/// epoch was recorded ([`super::presence_credit_frame`]). Kept for the
/// current and the previous epoch only ([`SLOTS`]).
pub fn present(state: &impl Records, session: &Session, epoch: u64) -> Result<Option<Vec<bool>>> {
    marks(state, PRESENCE, session, epoch)
}

/// Kind of the handoff record of a filter's protection marks in an epoch:
/// members whose nullify votes a report carried ([`protected`]).
const PROTECTED: &[u8] = b"protected";

/// The members of `session` whose nullify votes an accepted report included
/// in a frame of `epoch` carried, by member index: they followed the
/// session, and are not excluded for absence, but earn no credit. `None`
/// while no such report was recorded. Kept for the current and the previous
/// epoch only.
pub fn protected(state: &impl Records, session: &Session, epoch: u64) -> Result<Option<Vec<bool>>> {
    marks(state, PROTECTED, session, epoch)
}

/// Whether member `member` of `session` is recorded present or protected in
/// `epoch`.
pub fn recorded(state: &impl Records, session: &Session, epoch: u64, member: u32) -> Result<bool> {
    Ok(
        marked(&present(state, session, epoch)?.unwrap_or_default(), member)
            || marked(
                &protected(state, session, epoch)?.unwrap_or_default(),
                member,
            ),
    )
}

/// Whether `report`, included in GLOBAL frame `frame`, adds a mark for
/// `frame`'s epoch: a notarize of a member not yet recorded present
/// ([`present`]), or a nullify of a member neither present nor protected
/// ([`protected`]). Always true before [`super::presence_credit_frame`],
/// when nothing is recorded. A signer index outside the session counts as
/// new here; its signature check refuses it.
pub fn marks_new_member(
    state: &impl Records,
    frame: u64,
    session: &Session,
    report: &PresenceReport,
) -> Result<bool> {
    if frame < super::presence_credit_frame() {
        return Ok(true);
    }
    let (recorded, covered) = recorded_marks(state, frame, session)?;
    let notarized = report
        .proposals
        .iter()
        .flat_map(|proposal| &proposal.votes)
        .any(|vote| !marked(&recorded, vote.signer));
    let nullified = report
        .nullifies
        .iter()
        .any(|vote| !marked(&recorded, vote.signer) && !marked(&covered, vote.signer));
    Ok(notarized || nullified)
}

/// What [`apply`] recorded for one report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Applied {
    /// Members the report marked present that were not marked before.
    pub marked: usize,
    /// Allocations whose activity the report raised.
    pub credited: usize,
    /// Members marked present in the epoch after the report.
    pub present: usize,
    /// Members the report's nullifies marked protected that were not before.
    pub protected: usize,
    /// The session's members.
    pub members: usize,
}

/// Execute `report` in GLOBAL frame `frame`: [`verify`] it and, from
/// [`super::presence_credit_frame`], record it. Before that frame an
/// accepted report writes nothing.
///
/// Every notarize marks its signer present for the report's session and
/// `frame`'s epoch ([`present`]). Reports only add marks, so the record is
/// the union of the epoch's reports, whatever their order. Each voter on a
/// proposal enough members notarized that one is honest ([`credited_votes`])
/// has the `LastActiveFrameNumber` of its allocation on the session's
/// filter raised to the proposal's anchor, never lowered: the anchor, not
/// `frame`, so a report that lands late does not make a member look fresher
/// than its vote. A verified notarize is fresh evidence: its payload digests
/// a header whose output binds an anchor earlier in `frame`'s epoch. A
/// member without an allocation on the filter is marked, not credited.
/// A nullify, which can be signed ahead for every view, is no evidence of
/// work: it only marks its signer protected ([`protected`]), from
/// [`super::presence_exclusion_frame`], and earns no credit.
pub fn apply(
    state: &HypergraphState,
    frame: u64,
    report: &PresenceReport,
    anchor_output: impl Fn(u64) -> Result<Vec<u8>>,
) -> Result<Applied> {
    verify(state, frame, report, anchor_output)?;
    if frame < super::presence_credit_frame() {
        return Ok(Applied::default());
    }
    super::atomic(state, || {
        let session = session(state, &report.session)?.ok_or_else(|| invalid("unknown session"))?;
        let epoch = quil_types::consensus::epoch_for_frame(frame);
        let mut applied = Applied {
            members: session.members.len(),
            ..Applied::default()
        };
        let mut marked =
            present(state, &session, epoch)?.unwrap_or_else(|| vec![false; session.members.len()]);
        for proposal in &report.proposals {
            let anchor = proposal.header.global_frame_number;
            // Credit only a proposal enough members notarized that one of
            // them is honest ([`credited_votes`]): any member can notarize
            // a header it made up, which proves its key alive but not that
            // it takes part in its committee.
            let led = proposal.votes.len() >= credited_votes(session.members.len());
            for vote in &proposal.votes {
                let index = vote.signer as usize;
                let member = session
                    .members
                    .get(index)
                    .ok_or_else(|| invalid("vote signer is not a session member"))?;
                if !marked[index] {
                    marked[index] = true;
                    applied.marked += 1;
                }
                if led && credit_activity(state, frame, member, &session.filter, anchor)? {
                    applied.credited += 1;
                }
            }
        }
        applied.present = marked.iter().filter(|&&member| member).count();
        if !report.proposals.is_empty() {
            set_marks(state, frame, PRESENCE, &session, epoch, &marked)?;
        }
        if !report.nullifies.is_empty() {
            let mut covered = protected(state, &session, epoch)?
                .unwrap_or_else(|| vec![false; session.members.len()]);
            for vote in &report.nullifies {
                let index = vote.signer as usize;
                if index >= covered.len() {
                    return Err(invalid("vote signer is not a session member"));
                }
                if !covered[index] && !marked[index] {
                    covered[index] = true;
                    applied.protected += 1;
                }
            }
            set_marks(state, frame, PROTECTED, &session, epoch, &covered)?;
            let highest = report
                .nullifies
                .iter()
                .map(|vote| vote.view)
                .max()
                .unwrap_or(0);
            note_nullify_view(state, frame, &session, epoch, highest)?;
        }
        tracing::info!(
            frame,
            epoch,
            filter = hex::encode(&report.filter),
            generation = session.generation,
            session = hex::encode(report.session),
            marked = applied.marked,
            present = applied.present,
            protected = applied.protected,
            members = applied.members,
            credited = applied.credited,
            "committee presence: report recorded session members present for the epoch",
        );
        Ok(applied)
    })
}

/// Raise `LastActiveFrameNumber` of `member`'s allocation on `filter` to
/// `anchor`. False, writing nothing, without such an allocation or when its
/// recorded activity is not older than `anchor`.
fn credit_activity(
    state: &HypergraphState,
    frame: u64,
    member: &[u8],
    filter: &[u8],
    anchor: u64,
) -> Result<bool> {
    use crate::global_schema::{read_field, write_field, GLOBAL_INTRINSIC_ADDRESS};
    const CLASS: &str = "allocation:ProverAllocation";
    let address = crate::global_intrinsic::materialize::allocation_address(member, filter)?;
    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
    let Some(blob) = state.get(&GLOBAL_INTRINSIC_ADDRESS[..], &address, &va_disc)? else {
        return Ok(false);
    };
    if blob.is_empty() {
        return Ok(false);
    }
    let mut allocation = crate::prover_registry::rebuild_vertex_tree_from_blob(&blob);
    let current = read_field(&allocation, CLASS, "LastActiveFrameNumber")
        .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
        .map_or(0, u64::from_be_bytes);
    if current >= anchor {
        return Ok(false);
    }
    write_field(
        &mut allocation,
        CLASS,
        "LastActiveFrameNumber",
        &anchor.to_be_bytes(),
    )?;
    state.set(
        &GLOBAL_INTRINSIC_ADDRESS[..],
        &address,
        &va_disc,
        frame,
        crate::prover_registry::vertex_tree_to_blob(&allocation),
    )?;
    Ok(true)
}
