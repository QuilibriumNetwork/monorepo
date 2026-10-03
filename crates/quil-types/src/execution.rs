use crate::error::Result;
use crate::proto;
use num_bigint::BigInt;

/// Result of processing a message through an execution engine.
#[derive(Debug, Clone)]
pub struct ProcessMessageResult {
    /// Output messages to be included in the frame.
    pub messages: Vec<Vec<u8>>,
    /// Serialized state changes.
    pub state: Vec<u8>,
}

/// State change event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateChangeEvent {
    Initialize,
    Create,
    Update,
    Delete,
}

/// A single state change record in a changeset. The execution layer
/// accumulates these during `process_message` and commits them
/// atomically at the end of the frame.
#[derive(Debug, Clone)]
pub struct StateChange {
    /// The 32-byte domain (app address or GLOBAL).
    pub domain: Vec<u8>,
    /// The 32-byte data address within the domain.
    pub address: Vec<u8>,
    /// Discriminator distinguishing vertex adds/removes from hyperedge
    /// adds/removes. Poseidon hash of e.g. "vertex:adds".
    pub discriminator: Vec<u8>,
    /// The type of state change.
    pub state_change: StateChangeEvent,
    /// The serialized data payload for this change.
    pub value: Vec<u8>,
}

/// The data-address bit path of the shard a frame executes on, most
/// significant bit first. The empty path is a shard holding the whole
/// application; a longer path is a sub-shard holding only the addresses that
/// begin with it.
///
/// Derived from the frame's certified filter, so every replica of a shard —
/// and an archive re-executing that shard's frames — sees the same value.
/// That is what lets execution refuse an operation deterministically on a
/// sub-shard, rather than as an infrastructure fault that fails the frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardPath {
    bits: u64,
    len: u8,
}

impl ShardPath {
    /// A shard holding the whole application (and the global venue).
    pub const WHOLE: Self = Self { bits: 0, len: 0 };
    /// A shard whose filter could not be decoded. It is treated as covering
    /// only part of the application, so nothing that needs the whole of it
    /// runs there.
    pub const UNKNOWN: Self = Self { bits: 0, len: u8::MAX };
    /// Longest path a shard can carry.
    pub const MAX_BITS: usize = 64;

    /// The path of `bits`; [`Self::UNKNOWN`] if it is longer than can be held.
    pub fn from_bits(bits: &[bool]) -> Self {
        if bits.len() > Self::MAX_BITS {
            return Self::UNKNOWN;
        }
        let packed = bits.iter().enumerate().fold(0u64, |acc, (i, bit)| {
            if *bit { acc | (1u64 << (63 - i)) } else { acc }
        });
        Self { bits: packed, len: bits.len() as u8 }
    }

    /// Whether the shard holds the whole application.
    pub fn is_whole(&self) -> bool {
        self.len == 0
    }

    /// The path as nine bytes — length, then bits — for records and wire
    /// formats that must agree on it byte for byte.
    pub fn to_bytes(&self) -> [u8; 9] {
        let mut bytes = [0u8; 9];
        bytes[0] = self.len;
        bytes[1..].copy_from_slice(&self.bits.to_be_bytes());
        bytes
    }

    /// The path [`Self::to_bytes`] wrote, or `None` if the bytes are not one.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: [u8; 9] = bytes.try_into().ok()?;
        let len = bytes[0];
        let bits = u64::from_be_bytes(bytes[1..].try_into().unwrap());
        if usize::from(len) > Self::MAX_BITS {
            return (len == u8::MAX && bits == 0).then_some(Self::UNKNOWN);
        }
        // Only the named bits may be set: one path, one encoding.
        let used = if len == 0 { 0 } else { u64::MAX << (64 - u32::from(len)) };
        (bits & !used == 0).then_some(Self { bits, len })
    }

    /// Whether `address` (a data address of the application) lies in this
    /// shard's range: its leading bits are the path. Paths of one application's
    /// shards are prefix-free, so at most one shard covers an address; the whole
    /// application covers all of them and an undecodable shard covers none.
    pub fn covers(&self, address: &[u8]) -> bool {
        let len = usize::from(self.len);
        if len > Self::MAX_BITS || address.len() * 8 < len {
            return false;
        }
        (0..len).all(|i| {
            let bit = address[i / 8] & (0x80 >> (i % 8)) != 0;
            bit == (self.bits & (1u64 << (63 - i)) != 0)
        })
    }

    /// The path's bits, or `None` for [`Self::UNKNOWN`].
    pub fn bits(&self) -> Option<Vec<bool>> {
        if usize::from(self.len) > Self::MAX_BITS {
            return None;
        }
        Some((0..usize::from(self.len)).map(|i| self.bits & (1u64 << (63 - i)) != 0).collect())
    }
}

#[cfg(test)]
mod shard_path_bytes_tests {
    use super::ShardPath;

    #[test]
    fn exactly_one_shard_of_a_partition_covers_an_address() {
        let address = [0b1011_0000u8, 0xff];
        assert!(ShardPath::WHOLE.covers(&address));
        assert!(!ShardPath::UNKNOWN.covers(&address));
        let partition = [vec![false], vec![true, false, false], vec![true, false, true], vec![true, true]];
        let covering: Vec<_> = partition.iter().filter(|bits| ShardPath::from_bits(bits).covers(&address)).collect();
        assert_eq!(covering, vec![&vec![true, false, true]]);
        // A path longer than the address cannot be decided, so it does not cover.
        assert!(!ShardPath::from_bits(&[true; 9]).covers(&[0xff]));
        assert!(ShardPath::from_bits(&[true; 8]).covers(&[0xff]));
    }

    /// Every path round-trips through its nine bytes, and only the encoding it
    /// writes is accepted back.
    #[test]
    fn a_shard_path_round_trips_and_rejects_other_encodings() {
        for bits in [vec![], vec![false], vec![true], vec![true, false, true, true, false, true]] {
            let path = ShardPath::from_bits(&bits);
            assert_eq!(ShardPath::from_bytes(&path.to_bytes()), Some(path));
        }
        assert_eq!(ShardPath::from_bytes(&ShardPath::WHOLE.to_bytes()), Some(ShardPath::WHOLE));
        assert_eq!(ShardPath::from_bytes(&ShardPath::UNKNOWN.to_bytes()), Some(ShardPath::UNKNOWN));
        // Bits below the path's length are not part of it.
        let mut noncanonical = ShardPath::from_bits(&[true, false]).to_bytes();
        noncanonical[8] |= 1;
        assert_eq!(ShardPath::from_bytes(&noncanonical), None);
        assert_eq!(ShardPath::from_bytes(&[0; 8]), None);
        assert_eq!(ShardPath::from_bytes(&[65, 0, 0, 0, 0, 0, 0, 0, 0]), None);
    }
}

impl Default for ShardPath {
    fn default() -> Self {
        Self::WHOLE
    }
}

/// Frame identity and the global reference supplied by consensus execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameExecutionContext {
    pub frame_number: u64,
    /// Consensus-bound global reference. For an app frame this is its signed
    /// header anchor, not the app height or the node's latest local frame.
    /// None means the caller has not supplied an authenticated global bound.
    pub finalized_global_frame: Option<u64>,
    /// The shard this frame executes on. [`ShardPath::WHOLE`] for the global
    /// venue and for a shard holding its whole application.
    pub shard: ShardPath,
    /// The venue to execute in, overriding the engine's own: app-shard frames
    /// always execute in [`Venue::Application`], whichever node replays them
    /// (an archive's manager is otherwise a global-venue manager). `None`
    /// keeps the engine's configured venue.
    pub venue: Option<Venue>,
}

/// Where a frame executes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Venue {
    /// Global frames: serialized global execution.
    Global,
    /// App-shard frames.
    Application,
}

/// A shard execution engine that validates, processes, and proves messages.
pub trait ShardExecutionEngine: Send + Sync {
    /// Downcast hook for mutating concrete-type configuration after
    /// construction (e.g. installing optional intrinsic dependencies).
    /// Default: returns `None`, callers must check before
    /// downcasting. Implementations: `fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> { Some(self) }`.
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        None
    }

    /// Shared-reference downcast hook for read-only concrete-type access.
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        None
    }

    /// Human-readable engine name (e.g. "global", "token", "compute", "hypergraph").
    fn get_name(&self) -> &str;

    /// Validate a message before processing.
    fn validate_message(
        &self,
        frame_number: u64,
        address: &[u8],
        message: &[u8],
    ) -> Result<()>;

    /// Process a message against current state.
    fn process_message(
        &self,
        frame_number: u64,
        fee_multiplier: &BigInt,
        address: &[u8],
        message: &[u8],
    ) -> Result<ProcessMessageResult>;

    /// Process with the frame's global reference. Existing engines that do not
    /// consume global-state witnesses retain their ordinary execution behavior.
    fn process_message_with_context(
        &self,
        context: FrameExecutionContext,
        fee_multiplier: &BigInt,
        address: &[u8],
        message: &[u8],
    ) -> Result<ProcessMessageResult> {
        self.process_message(context.frame_number, fee_multiplier, address, message)
    }

    /// Produce a proof for a message.
    fn prove(
        &self,
        domain: &[u8],
        frame_number: u64,
        message: &[u8],
    ) -> Result<proto::global::MessageRequest>;

    /// Lock addresses for cross-shard transaction processing.
    fn lock(
        &self,
        frame_number: u64,
        address: &[u8],
        message: &[u8],
    ) -> Result<Vec<Vec<u8>>>;

    /// Release any locks held by the engine.
    fn unlock(&self) -> Result<()>;

    /// Estimate the cost of processing a message.
    fn get_cost(&self, message: &[u8]) -> Result<BigInt>;

    /// Capabilities advertised by this engine.
    fn get_capabilities(&self) -> Vec<proto::node::Capability>;
}

/// Circuit compiler interface for compute intrinsics. The actual QCL
/// compiler implementation is separate -- this trait defines the boundary.
pub trait CircuitCompiler: Send + Sync {
    /// Compile QCL source code into a circuit.
    fn compile(&self, source: &str, input_sizes: &[Vec<i32>]) -> Result<Vec<u8>>;

    /// Validate a compiled circuit from bytes.
    fn validate_circuit(&self, circuit: &[u8]) -> Result<()>;
}

#[cfg(test)]
mod shard_path_tests {
    use super::ShardPath;

    #[test]
    fn a_shard_path_round_trips_and_distinguishes_whole_from_partial() {
        assert!(ShardPath::WHOLE.is_whole());
        assert_eq!(ShardPath::WHOLE.bits(), Some(Vec::new()));
        assert_eq!(ShardPath::from_bits(&[]), ShardPath::WHOLE);
        let path = [true, false, true, true, false, false];
        let shard = ShardPath::from_bits(&path);
        assert!(!shard.is_whole());
        assert_eq!(shard.bits(), Some(path.to_vec()));
        // A one-bit split is partial — the case a 6-bit nibble prefix could
        // not tell apart from the whole application.
        assert!(!ShardPath::from_bits(&[false]).is_whole());
        // Leading zero bits are part of the path, not padding.
        assert_ne!(ShardPath::from_bits(&[false]), ShardPath::from_bits(&[false, false]));
        // Too long to hold, or undecodable: partial, never whole.
        assert_eq!(ShardPath::from_bits(&[true; 65]), ShardPath::UNKNOWN);
        assert!(!ShardPath::UNKNOWN.is_whole());
        assert_eq!(ShardPath::UNKNOWN.bits(), None);
    }
}
