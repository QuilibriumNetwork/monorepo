//! The heap a protobuf message's decode takes, counted from its encoding
//! before it is decoded, so a receiver can refuse a message whose decode
//! would take far more memory than its bytes.
//!
//! A repeated field's element costs the decoder the element's size
//! however few bytes encode it: an empty message is two bytes on the wire
//! and a slot of its struct's size in a `Vec`, which holds at least four
//! slots and doubles as it fills. [`DecodeCost::bytes`] follows that
//! growth for each repeated field, adds the contents of every `bytes` and
//! `string` field and a box for each recursive message, and stops once
//! the total passes a limit. The fields are read from the descriptors the
//! build embeds ([`crate::protojson::descriptor_pool`]), so a field added
//! to the schema is counted with no change here.

use std::collections::HashMap;

use prost_reflect::{FieldDescriptor, Kind, MessageDescriptor};

/// How deeply messages nest at most: the decoder's own limit.
const MAX_DEPTH: u32 = 100;

/// Repeated fields of one message counted slot by slot; the elements of
/// any further one are each charged four slots, what a `Vec` of them
/// takes at most while it grows.
const MAX_REPEATED: usize = 32;

/// Singular message fields of one message whose second occurrence in an
/// instance is noticed; any further one counts as occurring twice.
const MAX_SINGULAR: usize = 64;

/// What decoding a message takes, read from its descriptors.
#[derive(Debug)]
pub struct DecodeCost {
    /// The message and every message it reaches, the message first.
    messages: Vec<Plan>,
}

/// Why [`DecodeCost::bytes`] stopped short of a total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostRefusal {
    /// The decoder would refuse the encoding, as far as the walk reads it.
    Malformed,
    /// The decode would take more than the limit: at least this many bytes.
    Over(u64),
}

#[derive(Debug)]
struct Plan {
    name: String,
    /// At least the size of the message's struct.
    size: u64,
    /// By field number, ascending.
    fields: Vec<Field>,
}

#[derive(Debug, Clone, Copy)]
struct Field {
    number: u32,
    value: Value,
    count: Count,
}

/// How a field's occurrences are counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Count {
    /// A singular scalar, `bytes` or `string`: nothing to count.
    Once,
    /// A singular message, noticed when it occurs again (`MAX_SINGULAR`).
    Singular(Option<usize>),
    /// A repeated field's counter, or none (`MAX_REPEATED`).
    Repeated(Option<usize>),
}

#[derive(Debug, Clone, Copy)]
enum Value {
    /// A varint, decoded into this many bytes (`bool`, integers, enums).
    Varint(u64),
    Fixed32,
    Fixed64,
    /// `bytes` or `string`: its contents on the heap.
    Bytes,
    /// A message, boxed by the decoder when it can contain its parent.
    Message {
        plan: usize,
        boxed: bool,
    },
    /// A map's entry, held in a hash map.
    Entry {
        plan: usize,
    },
}

impl DecodeCost {
    /// The cost of decoding the message `full_name` (`package.Message`),
    /// or `None` if the embedded descriptors lack it.
    pub fn of(full_name: &str) -> Option<Self> {
        let root = crate::protojson::descriptor_pool().get_message_by_name(full_name)?;
        // Every message the root reaches, the root first.
        let mut descriptors = vec![root];
        let mut index = HashMap::new();
        index.insert(descriptors[0].full_name().to_owned(), 0);
        let mut next = 0;
        while let Some(message) = descriptors.get(next).cloned() {
            next += 1;
            for field in message.fields() {
                if let Kind::Message(nested) = field.kind() {
                    if !index.contains_key(nested.full_name()) {
                        index.insert(nested.full_name().to_owned(), descriptors.len());
                        descriptors.push(nested);
                    }
                }
            }
        }
        let mut messages: Vec<Plan> = descriptors
            .iter()
            .map(|message| plan(message, &index))
            .collect();
        let mut sizes = vec![None; messages.len()];
        for (at, plan) in messages.iter_mut().enumerate() {
            plan.size = struct_size(at, &descriptors, &index, &mut sizes);
        }
        Some(Self { messages })
    }

    /// Every message the decode reaches, by full name.
    pub fn messages(&self) -> impl Iterator<Item = &str> {
        self.messages.iter().map(|plan| plan.name.as_str())
    }

    /// The size this counts for the struct of the message `full_name`, at
    /// least its real size.
    pub fn struct_size(&self, full_name: &str) -> Option<u64> {
        self.messages
            .iter()
            .find(|plan| plan.name == full_name)
            .map(|plan| plan.size)
    }

    /// At least the most heap decoding `data` takes at once, without
    /// allocating; refused once that passes `limit`, or where the decoder
    /// would refuse the encoding. The struct the decode returns is not
    /// counted.
    pub fn bytes(&self, data: &[u8], limit: u64) -> Result<u64, CostRefusal> {
        let mut tally = Tally {
            held: 0,
            passing: 0,
            limit,
            merged: false,
        };
        match self.walk(0, data, 0, &mut tally) {
            // A singular message occurred twice in one instance and the
            // decoder merges the two: their `Vec`s grow on from where the
            // first left off, which the counts of one occurrence miss.
            // Counted again with every `Vec` at what a merge of any
            // number of occurrences can take.
            Err(Walk::Merged) => {
                tally = Tally {
                    held: 0,
                    passing: 0,
                    limit,
                    merged: true,
                };
                self.walk(0, data, 0, &mut tally).map_err(Walk::refusal)?;
            }
            other => other.map_err(Walk::refusal)?,
        }
        Ok(tally.peak())
    }

    fn walk(&self, at: usize, data: &[u8], depth: u32, tally: &mut Tally) -> Result<(), Walk> {
        if depth > MAX_DEPTH {
            return Err(Walk::Malformed);
        }
        let plan = &self.messages[at];
        let mut counts = [0u64; MAX_REPEATED];
        let mut seen = 0u64;
        let mut reader = Reader(data);
        while !reader.is_empty() {
            // A key past 32 bits is refused, as the decoder refuses it.
            let key = u32::try_from(reader.varint()?).map_err(|_| Walk::Malformed)?;
            let (number, wire) = (key >> 3, u64::from(key & 7));
            if number == 0 {
                return Err(Walk::Malformed);
            }
            let Ok(i) = plan.fields.binary_search_by_key(&number, |f| f.number) else {
                reader.skip(wire)?;
                continue;
            };
            let field = plan.fields[i];
            let repeated = matches!(field.count, Count::Repeated(_));
            let elements = match (field.value, wire) {
                (Value::Varint(_), 0) => {
                    reader.varint()?;
                    1
                }
                (Value::Fixed64, 1) => {
                    reader.take(8)?;
                    1
                }
                (Value::Fixed32, 5) => {
                    reader.take(4)?;
                    1
                }
                // Packed.
                (Value::Varint(_), 2) if repeated => {
                    let mut packed = Reader(reader.len_delimited()?);
                    let mut n = 0;
                    while !packed.is_empty() {
                        packed.varint()?;
                        n += 1;
                    }
                    n
                }
                (Value::Fixed32 | Value::Fixed64, 2) if repeated => {
                    let width = if matches!(field.value, Value::Fixed32) {
                        4
                    } else {
                        8
                    };
                    let packed = reader.len_delimited()?;
                    if packed.len() % width != 0 {
                        return Err(Walk::Malformed);
                    }
                    (packed.len() / width) as u64
                }
                (Value::Bytes, 2) => {
                    let len = reader.len_delimited()?.len() as u64;
                    if len > 0 {
                        // A `Vec<u8>` holds at least eight bytes; the
                        // decoder copies the contents once on the way.
                        tally.hold(len.max(8))?;
                        tally.pass(len)?;
                    }
                    1
                }
                (
                    Value::Message {
                        plan: nested,
                        boxed,
                    },
                    2,
                ) => {
                    let body = reader.len_delimited()?;
                    if let Count::Singular(slot) = field.count {
                        let bit = slot.map_or(u64::MAX, |slot| 1 << slot);
                        if seen & bit != 0 && !tally.merged {
                            return Err(Walk::Merged);
                        }
                        seen |= bit;
                    }
                    if boxed {
                        tally.hold(self.messages[nested].size)?;
                    }
                    self.walk(nested, body, depth + 1, tally)?;
                    1
                }
                (Value::Entry { plan: entry }, 2) => {
                    self.walk(entry, reader.len_delimited()?, depth + 1, tally)?;
                    1
                }
                _ => return Err(Walk::Malformed),
            };
            if let Count::Repeated(slot) = field.count {
                let element = match field.value {
                    Value::Varint(size) => size,
                    Value::Fixed32 => 4,
                    Value::Fixed64 => 8,
                    Value::Bytes => 24,
                    Value::Message { plan: nested, .. } => self.messages[nested].size,
                    // A hash map's bucket, a control byte, and as many
                    // buckets again for its spare capacity.
                    Value::Entry { plan: entry } => 2 * (self.messages[entry].size + 1),
                };
                match slot {
                    Some(slot) => {
                        let before = counts[slot];
                        counts[slot] = before.saturating_add(elements);
                        tally.grow(before, counts[slot], element)?;
                    }
                    None => tally.hold(elements.saturating_mul(4).saturating_mul(element))?,
                }
            }
        }
        Ok(())
    }
}

/// How the walk ended short of a total.
enum Walk {
    Malformed,
    Over(u64),
    /// A singular message occurred twice in one instance.
    Merged,
}

impl Walk {
    fn refusal(self) -> CostRefusal {
        match self {
            Self::Over(bytes) => CostRefusal::Over(bytes),
            Self::Malformed | Self::Merged => CostRefusal::Malformed,
        }
    }
}

/// The heap counted so far.
struct Tally {
    /// Held until the decode returns.
    held: u64,
    /// The most held at once only on the way: a copy of a field's
    /// contents, or a `Vec`'s buffer while it moves to a larger one.
    passing: u64,
    limit: u64,
    /// Whether singular messages may merge ([`DecodeCost::bytes`]).
    merged: bool,
}

impl Tally {
    fn peak(&self) -> u64 {
        self.held.saturating_add(self.passing)
    }

    fn check(&self) -> Result<(), Walk> {
        let peak = self.peak();
        if peak > self.limit {
            return Err(Walk::Over(peak));
        }
        Ok(())
    }

    fn hold(&mut self, bytes: u64) -> Result<(), Walk> {
        self.held = self.held.saturating_add(bytes);
        self.check()
    }

    fn pass(&mut self, bytes: u64) -> Result<(), Walk> {
        self.passing = self.passing.max(bytes);
        self.check()
    }

    /// A `Vec` of `element`-byte slots grew from `before` to `after`
    /// elements, one at a time.
    fn grow(&mut self, before: u64, after: u64, element: u64) -> Result<(), Walk> {
        if element == 0 {
            return Ok(());
        }
        // A `Vec` of one-byte elements holds at least eight, of larger
        // ones four, and doubles when full.
        let least = if element == 1 { 8 } else { 4 };
        let capacity = |len: u64| {
            if len == 0 {
                0
            } else {
                len.checked_next_power_of_two()
                    .unwrap_or(u64::MAX)
                    .max(least)
            }
        };
        let (from, to) = (capacity(before), capacity(after));
        if to == from {
            return Ok(());
        }
        if self.merged {
            // Merged occurrences share one `Vec`, of at most twice the
            // largest one's capacity, which moved from one of half that:
            // three times each occurrence's capacity covers both.
            return self.hold((to - from).saturating_mul(3).saturating_mul(element));
        }
        self.hold((to - from).saturating_mul(element))?;
        if to > least {
            self.pass((to / 2).saturating_mul(element))?;
        }
        Ok(())
    }
}

/// The plan of `message`'s fields; its size comes after.
fn plan(message: &MessageDescriptor, index: &HashMap<String, usize>) -> Plan {
    let mut fields = Vec::new();
    let (mut repeated, mut singular) = (0, 0);
    for field in message.fields() {
        let value = match field.kind() {
            Kind::Bool => Value::Varint(1),
            Kind::Int32 | Kind::Uint32 | Kind::Sint32 | Kind::Enum(_) => Value::Varint(4),
            Kind::Int64 | Kind::Uint64 | Kind::Sint64 => Value::Varint(8),
            Kind::Fixed32 | Kind::Sfixed32 | Kind::Float => Value::Fixed32,
            Kind::Fixed64 | Kind::Sfixed64 | Kind::Double => Value::Fixed64,
            Kind::String | Kind::Bytes => Value::Bytes,
            Kind::Message(nested) => {
                let plan = index[nested.full_name()];
                if field.is_map() {
                    Value::Entry { plan }
                } else {
                    Value::Message {
                        plan,
                        boxed: !field.is_list() && contains(&nested, message),
                    }
                }
            }
        };
        let count = if field.is_list() || field.is_map() {
            repeated += 1;
            Count::Repeated((repeated <= MAX_REPEATED).then_some(repeated - 1))
        } else if matches!(value, Value::Message { .. }) {
            singular += 1;
            Count::Singular((singular <= MAX_SINGULAR).then_some(singular - 1))
        } else {
            Count::Once
        };
        fields.push(Field {
            number: field.number(),
            value,
            count,
        });
    }
    fields.sort_by_key(|field| field.number);
    Plan {
        name: message.full_name().to_owned(),
        size: 0,
        fields,
    }
}

/// Whether `outer` holds `inner` (or is it) through singular message
/// fields: where the decoder boxes a field of type `outer` in `inner`.
fn contains(outer: &MessageDescriptor, inner: &MessageDescriptor) -> bool {
    let mut stack = vec![outer.clone()];
    let mut visited = vec![outer.full_name().to_owned()];
    while let Some(message) = stack.pop() {
        if message.full_name() == inner.full_name() {
            return true;
        }
        for field in message.fields() {
            if field.is_list() || field.is_map() {
                continue;
            }
            if let Kind::Message(nested) = field.kind() {
                if !visited.iter().any(|name| name == nested.full_name()) {
                    visited.push(nested.full_name().to_owned());
                    stack.push(nested);
                }
            }
        }
    }
    false
}

/// At least the size of message `at`'s struct: eight bytes for a scalar,
/// a `Vec`'s or `String`'s 24 for a repeated, `bytes` or `string` field,
/// 48 for a map, a nested message's own size and eight for its option
/// (eight for a box), and for a oneof its largest field and eight.
fn struct_size(
    at: usize,
    descriptors: &[MessageDescriptor],
    index: &HashMap<String, usize>,
    sizes: &mut [Option<u64>],
) -> u64 {
    if let Some(size) = sizes[at] {
        return size;
    }
    let message = &descriptors[at];
    let mut size = 0u64;
    let mut oneofs: HashMap<String, u64> = HashMap::new();
    for field in message.fields() {
        let slot = field_size(&field, message, descriptors, index, sizes);
        match field.containing_oneof() {
            Some(oneof) => {
                let largest = oneofs.entry(oneof.full_name().to_owned()).or_insert(0);
                *largest = (*largest).max(slot);
            }
            None => size += slot,
        }
    }
    size += oneofs.values().map(|largest| largest + 8).sum::<u64>();
    sizes[at] = Some(size);
    size
}

fn field_size(
    field: &FieldDescriptor,
    parent: &MessageDescriptor,
    descriptors: &[MessageDescriptor],
    index: &HashMap<String, usize>,
    sizes: &mut [Option<u64>],
) -> u64 {
    if field.is_map() {
        return 48;
    }
    if field.is_list() {
        return 24;
    }
    match field.kind() {
        Kind::String | Kind::Bytes => 24,
        Kind::Message(nested) if contains(&nested, parent) => 8,
        Kind::Message(nested) => {
            let at = index[nested.full_name()];
            struct_size(at, descriptors, index, sizes) + 8
        }
        _ => 8,
    }
}

/// A strict reader of protobuf wire format, which never allocates.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn varint(&mut self) -> Result<u64, Walk> {
        let bytes = self.0;
        let mut value = 0u64;
        for (i, byte) in bytes.iter().take(10).enumerate() {
            value |= u64::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                self.0 = &bytes[i + 1..];
                return Ok(value);
            }
        }
        Err(Walk::Malformed)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Walk> {
        if len > self.0.len() {
            return Err(Walk::Malformed);
        }
        let (taken, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(taken)
    }

    fn len_delimited(&mut self) -> Result<&'a [u8], Walk> {
        let len = usize::try_from(self.varint()?).map_err(|_| Walk::Malformed)?;
        self.take(len)
    }

    /// Skips an unknown field's value; a group is refused.
    fn skip(&mut self, wire: u64) -> Result<(), Walk> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 => {
                self.take(8)?;
            }
            2 => {
                self.len_delimited()?;
            }
            5 => {
                self.take(4)?;
            }
            _ => return Err(Walk::Malformed),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{application, compute, global, hypergraph, keys, token};
    use prost::Message;

    const APP_SHARD_FRAME: &str = "quilibrium.node.global.pb.AppShardFrame";

    /// The sizes of the structs of every message a shard frame reaches,
    /// by full name.
    fn frame_struct_sizes() -> Vec<(String, usize)> {
        macro_rules! sizes {
            ($($module:ident :: $name:ident = $proto:literal),* $(,)?) => {
                vec![$((
                    format!("quilibrium.node.{}.pb.{}", stringify!($module), $proto),
                    std::mem::size_of::<$module::$name>(),
                )),*]
            };
        }
        sizes![
            global::AppShardFrame = "AppShardFrame",
            global::FrameHeader = "FrameHeader",
            keys::Bls48581AggregateSignature = "BLS48581AggregateSignature",
            keys::Bls48581g2PublicKey = "BLS48581G2PublicKey",
            global::MessageBundle = "MessageBundle",
            global::MessageRequest = "MessageRequest",
            global::ProverJoin = "ProverJoin",
            keys::Bls48581SignatureWithProofOfPossession = "BLS48581SignatureWithProofOfPossession",
            global::SeniorityMerge = "SeniorityMerge",
            global::ProverLeave = "ProverLeave",
            keys::Bls48581AddressedSignature = "BLS48581AddressedSignature",
            global::ProverPause = "ProverPause",
            global::ProverResume = "ProverResume",
            global::ProverConfirm = "ProverConfirm",
            global::ConfirmLeafRoots = "ConfirmLeafRoots",
            global::LeafRootEntry = "LeafRootEntry",
            global::ReleaseInfo = "ReleaseInfo",
            global::ProverReject = "ProverReject",
            global::ProverKick = "ProverKick",
            application::TraversalProof = "TraversalProof",
            application::Multiproof = "Multiproof",
            application::TraversalSubProof = "TraversalSubProof",
            application::Path = "Path",
            global::ProverUpdate = "ProverUpdate",
            token::TokenDeploy = "TokenDeploy",
            token::TokenConfiguration = "TokenConfiguration",
            token::TokenMintStrategy = "TokenMintStrategy",
            token::Authority = "Authority",
            token::FeeBasis = "FeeBasis",
            token::TokenUpdate = "TokenUpdate",
            hypergraph::HypergraphDeploy = "HypergraphDeploy",
            hypergraph::HypergraphConfiguration = "HypergraphConfiguration",
            hypergraph::HypergraphUpdate = "HypergraphUpdate",
            hypergraph::VertexAdd = "VertexAdd",
            hypergraph::VertexRemove = "VertexRemove",
            hypergraph::HyperedgeAdd = "HyperedgeAdd",
            hypergraph::HyperedgeRemove = "HyperedgeRemove",
            compute::ComputeDeploy = "ComputeDeploy",
            compute::ComputeConfiguration = "ComputeConfiguration",
            compute::ComputeUpdate = "ComputeUpdate",
            compute::CodeDeployment = "CodeDeployment",
            compute::CodeExecute = "CodeExecute",
            compute::ExecuteOperation = "ExecuteOperation",
            compute::Application = "Application",
            compute::CodeFinalize = "CodeFinalize",
            compute::ExecutionResult = "ExecutionResult",
            compute::StateTransition = "StateTransition",
            global::AltShardUpdate = "AltShardUpdate",
            global::ProverSeniorityMerge = "ProverSeniorityMerge",
            global::ShardSplit = "ShardSplit",
            global::ShardMerge = "ShardMerge",
            token::TokenOperation = "TokenOperation",
            global::StorageAttestation = "StorageAttestation",
            global::StorageOpening = "StorageOpening",
        ]
    }

    /// A frame of `roots` empty state roots in its header.
    fn header_roots(roots: usize) -> Vec<u8> {
        global::AppShardFrame {
            header: Some(global::FrameHeader {
                state_roots: vec![Vec::new(); roots],
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// The size counted for each struct a shard frame decodes into is at
    /// least its real size, and every message the frame reaches is
    /// checked: a message the schema adds fails here until it is listed.
    #[test]
    fn struct_sizes_cover_every_message_of_a_frame() {
        let cost = DecodeCost::of(APP_SHARD_FRAME).unwrap();
        let sizes = frame_struct_sizes();
        let mut reached: Vec<_> = cost.messages().map(str::to_owned).collect();
        let mut listed: Vec<_> = sizes.iter().map(|(name, _)| name.clone()).collect();
        reached.sort();
        listed.sort();
        assert_eq!(
            reached, listed,
            "STRUCT-SIZES: the messages a frame reaches"
        );
        for (name, real) in sizes {
            let counted = cost.struct_size(&name).unwrap();
            assert!(
                counted >= real as u64,
                "STRUCT-SIZES: {name} counted {counted} bytes, its struct is {real}"
            );
        }
    }

    /// An empty encoding costs nothing; an encoding the decoder refuses is
    /// refused, never a panic.
    #[test]
    fn refuses_what_the_decoder_refuses() {
        let cost = DecodeCost::of(APP_SHARD_FRAME).unwrap();
        assert_eq!(cost.bytes(&[], u64::MAX), Ok(0));
        assert!(DecodeCost::of("no.such.Message").is_none());
        for bad in [
            // A group; field 0; a key past 32 bits; an endless varint.
            &[0x0b][..],
            &[0x00, 0x00],
            &[0x80, 0x80, 0x80, 0x80, 0x80, 0x01, 0x00],
            &[0xff; 11],
            // A message field (requests, 2) as a varint; a length past
            // the end; a bytes field (state_roots, 9) as a fixed32.
            &[0x10, 0x01],
            &[0x12, 0x05, 0x0a],
            &[0x0a, 0x05, 0x4d, 0x00, 0x00, 0x00, 0x00],
        ] {
            assert_eq!(
                cost.bytes(bad, u64::MAX),
                Err(CostRefusal::Malformed),
                "DECODER-REFUSES: {bad:?}"
            );
            assert!(global::AppShardFrame::decode(bad).is_err(), "{bad:?}");
        }
        let frame = global::AppShardFrame {
            header: Some(global::FrameHeader {
                state_roots: vec![vec![1; 32]; 3],
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec();
        for end in 0..frame.len() {
            let cut = &frame[..end];
            if cost.bytes(cut, u64::MAX).is_ok() {
                assert!(global::AppShardFrame::decode(cut).is_ok(), "{end}");
            }
        }
    }

    /// The `Vec` of a repeated field is counted as it grows: four slots
    /// for the first element, doubling when full, and the buffer it moves
    /// from on the way; contents at eight bytes at least, and their copy.
    #[test]
    fn counts_a_repeated_field_as_its_vec_grows() {
        let cost = DecodeCost::of(APP_SHARD_FRAME).unwrap();
        let counted = |roots| cost.bytes(&header_roots(roots), u64::MAX);
        assert_eq!(counted(0), Ok(0), "VEC-GROWTH");
        assert_eq!(counted(1), Ok(4 * 24), "VEC-GROWTH");
        assert_eq!(counted(4), Ok(4 * 24), "VEC-GROWTH");
        assert_eq!(counted(5), Ok(8 * 24 + 4 * 24), "VEC-GROWTH");
        assert_eq!(counted(9), Ok(16 * 24 + 8 * 24), "VEC-GROWTH");
        let roots = global::AppShardFrame {
            header: Some(global::FrameHeader {
                state_roots: vec![vec![1; 3], vec![1; 32]],
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec();
        assert_eq!(
            cost.bytes(&roots, u64::MAX),
            Ok(4 * 24 + 8 + 32 + 32),
            "VEC-GROWTH: contents"
        );
        // Stopped once past the limit.
        assert_eq!(
            cost.bytes(&header_roots(9), 100),
            Err(CostRefusal::Over(8 * 24))
        );
    }

    /// A singular message written twice is merged by the decoder, its
    /// `Vec`s growing on from the first occurrence: the walk counts them
    /// again at what any merge can take, never less than the decode.
    #[test]
    fn counts_merged_messages_at_least_as_the_decoder_holds_them() {
        let cost = DecodeCost::of(APP_SHARD_FRAME).unwrap();
        // 64 roots, then one more: one Vec of 65, a capacity of 128 that
        // moved from 64.
        let mut twice = header_roots(64);
        twice.extend_from_slice(&header_roots(1));
        let decoded = global::AppShardFrame::decode(twice.as_slice()).unwrap();
        assert_eq!(decoded.header.unwrap().state_roots.len(), 65);
        let counted = cost.bytes(&twice, u64::MAX).unwrap();
        assert!(counted >= (128 + 64) * 24, "MERGED: counted {counted}");
        assert_eq!(counted, 3 * (64 + 4) * 24);
    }
}
