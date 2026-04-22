use thiserror::Error;

#[derive(Error, Debug)]
pub enum QuilError {
    #[error("store error: {0}")]
    Store(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("consensus error: {0}")]
    Consensus(String),

    #[error("p2p error: {0}")]
    P2p(String),

    #[error("execution error: {0}")]
    Execution(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Sentinel: safety rules declined to vote for a proposal. This is an
    /// _expected_ outcome during normal consensus operation.
    #[error("no vote: {0}")]
    NoVote(String),

    /// Sentinel: safety rules declined to produce a timeout.
    #[error("no timeout: {0}")]
    NoTimeout(String),

    /// Sentinel: committee lookup returned "not a valid signer" (ejected /
    /// self-ejected / non-member).
    #[error("invalid signer: {0}")]
    InvalidSigner(String),

    /// Sentinel: a voter equivocated -- voted for two different states at
    /// the same rank. Carries Byzantine evidence.
    #[error("double vote: {0}")]
    DoubleVote(String),

    /// Sentinel: a vote was submitted to a cache/collector for the wrong rank.
    #[error("vote for incompatible rank: {0}")]
    IncompatibleRank(String),

    /// Sentinel: same voter submitted the same vote twice (identical
    /// identifier + source + signature).
    #[error("repeated vote: {0}")]
    RepeatedVote(String),

    /// Sentinel: a vote references a different state than the collector
    /// is working on.
    #[error("vote for incompatible state: {0}")]
    IncompatibleState(String),

    /// Sentinel: a vote has an invalid signature or signer.
    #[error("invalid vote: {0}")]
    InvalidVote(String),

    /// Sentinel: a signer has already been added to a signature aggregator.
    #[error("duplicated signer: {0}")]
    DuplicatedSigner(String),

    /// Sentinel: not enough signatures to aggregate a quorum.
    #[error("insufficient signatures: {0}")]
    InsufficientSignatures(String),

    /// Sentinel: cryptographic signature verification failed.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// Sentinel: a quorum certificate failed structural or signature validation.
    #[error("invalid quorum certificate: {0}")]
    InvalidQuorumCertificate(String),

    /// Sentinel: a timeout certificate failed structural or signature validation.
    #[error("invalid timeout certificate: {0}")]
    InvalidTimeoutCertificate(String),

    /// Sentinel: a timeout state failed structural or signature validation.
    #[error("invalid timeout: {0}")]
    InvalidTimeout(String),

    /// Sentinel: a proposal failed structural or signature validation.
    #[error("invalid proposal: {0}")]
    InvalidProposal(String),

    /// Sentinel: the requested rank isn't known to a rank-indexed store.
    #[error("rank unknown: {0}")]
    RankUnknown(String),

    /// Sentinel: a replica sent two different timeout states for the same rank.
    #[error("double timeout: {0}")]
    DoubleTimeout(String),

    /// Sentinel: same replica submitted an identical timeout state twice.
    #[error("repeated timeout: {0}")]
    RepeatedTimeout(String),
}

impl QuilError {
    pub fn is_no_vote(&self) -> bool {
        matches!(self, QuilError::NoVote(_))
    }

    pub fn is_no_timeout(&self) -> bool {
        matches!(self, QuilError::NoTimeout(_))
    }

    pub fn is_invalid_signer(&self) -> bool {
        matches!(self, QuilError::InvalidSigner(_))
    }

    pub fn is_double_vote(&self) -> bool {
        matches!(self, QuilError::DoubleVote(_))
    }

    pub fn is_repeated_vote(&self) -> bool {
        matches!(self, QuilError::RepeatedVote(_))
    }

    pub fn is_incompatible_rank(&self) -> bool {
        matches!(self, QuilError::IncompatibleRank(_))
    }

    pub fn is_incompatible_state(&self) -> bool {
        matches!(self, QuilError::IncompatibleState(_))
    }

    pub fn is_invalid_vote(&self) -> bool {
        matches!(self, QuilError::InvalidVote(_))
    }

    pub fn is_duplicated_signer(&self) -> bool {
        matches!(self, QuilError::DuplicatedSigner(_))
    }

    pub fn is_insufficient_signatures(&self) -> bool {
        matches!(self, QuilError::InsufficientSignatures(_))
    }

    pub fn is_invalid_signature(&self) -> bool {
        matches!(self, QuilError::InvalidSignature(_))
    }

    pub fn is_invalid_quorum_certificate(&self) -> bool {
        matches!(self, QuilError::InvalidQuorumCertificate(_))
    }

    pub fn is_invalid_timeout_certificate(&self) -> bool {
        matches!(self, QuilError::InvalidTimeoutCertificate(_))
    }

    pub fn is_invalid_timeout(&self) -> bool {
        matches!(self, QuilError::InvalidTimeout(_))
    }

    pub fn is_invalid_proposal(&self) -> bool {
        matches!(self, QuilError::InvalidProposal(_))
    }

    pub fn is_rank_unknown(&self) -> bool {
        matches!(self, QuilError::RankUnknown(_))
    }

    pub fn is_double_timeout(&self) -> bool {
        matches!(self, QuilError::DoubleTimeout(_))
    }

    pub fn is_repeated_timeout(&self) -> bool {
        matches!(self, QuilError::RepeatedTimeout(_))
    }
}

pub type Result<T> = std::result::Result<T, QuilError>;
