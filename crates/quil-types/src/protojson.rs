//! Protobuf-JSON ("protojson") serialization, byte-compatible with Go's
//! `protojson.MarshalOptions{EmitUnpopulated: true}`.
//!
//! The Go explorer marshals a handful of protobuf messages with protojson:
//! lowerCamelCase field (json) names, `bytes` as standard base64, 64-bit
//! integers as JSON strings, enums as their string names, and — because of
//! `EmitUnpopulated` — every field present even when it holds its zero value.
//!
//! prost-generated Rust types carry none of that. Rather than hand-roll
//! serde for each message, we transcode through a [`DescriptorPool`] built
//! from the `FileDescriptorSet` emitted by `build.rs`: encode the prost
//! message to wire bytes, decode into a [`DynamicMessage`], and serialize it
//! with [`SerializeOptions`]. `skip_default_fields(false)` is the exact knob
//! that matches `EmitUnpopulated: true`; camelCase names, string 64-bit
//! ints, base64 bytes, and string enums are prost-reflect defaults that
//! already match protojson.

use once_cell::sync::Lazy;
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, SerializeOptions};

use crate::error::{QuilError, Result};

/// Fully-qualified protobuf message names for the types the explorer emits
/// via protojson. (Package = the proto `package` declaration.)
pub const GLOBAL_FRAME: &str = "quilibrium.node.global.pb.GlobalFrame";
pub const GLOBAL_PROPOSAL: &str = "quilibrium.node.global.pb.GlobalProposal";
pub const KEY_REGISTRY: &str = "quilibrium.node.keys.pb.KeyRegistry";

/// The descriptor set produced by `build.rs` (`file_descriptor_set_path`).
static DESCRIPTOR_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/descriptor.bin"));

static POOL: Lazy<DescriptorPool> = Lazy::new(|| {
    DescriptorPool::decode(DESCRIPTOR_BYTES)
        .expect("embedded protobuf descriptor set is valid")
});

/// Serialize a prost message to protojson bytes, matching Go's
/// `protojson.MarshalOptions{EmitUnpopulated: true}`.
///
/// `full_name` is the fully-qualified protobuf message name (e.g.
/// [`GLOBAL_FRAME`]); it must name the same message type as `M`.
pub fn to_protojson<M: Message>(full_name: &str, msg: &M) -> Result<Vec<u8>> {
    let descriptor = POOL.get_message_by_name(full_name).ok_or_else(|| {
        QuilError::Serialization(format!("protojson: unknown message type {full_name}"))
    })?;

    // prost message -> wire bytes -> dynamic message under the descriptor.
    let wire = msg.encode_to_vec();
    let dynamic = DynamicMessage::decode(descriptor, wire.as_slice()).map_err(|e| {
        QuilError::Serialization(format!("protojson: decode {full_name} into dynamic: {e}"))
    })?;

    // skip_default_fields(false) == Go EmitUnpopulated: emit zero-valued
    // fields too. The remaining protojson rules (camelCase json names,
    // base64 bytes, string 64-bit ints, string enum names) are defaults.
    let options = SerializeOptions::new().skip_default_fields(false);
    let mut buf = Vec::with_capacity(wire.len() * 2);
    let mut ser = serde_json::Serializer::new(&mut buf);
    dynamic
        .serialize_with_options(&mut ser, &options)
        .map_err(|e| QuilError::Serialization(format!("protojson: serialize {full_name}: {e}")))?;
    Ok(buf)
}

/// Borrow the shared descriptor pool (useful for tests / introspection).
pub fn descriptor_pool() -> &'static DescriptorPool {
    &POOL
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::global::{GlobalFrame, GlobalFrameHeader};

    #[test]
    fn global_frame_matches_protojson_rules() {
        // A header with a zero field (rank) and a bytes field, to exercise
        // EmitUnpopulated + base64 + string-64-bit-int.
        let frame = GlobalFrame {
            header: Some(GlobalFrameHeader {
                frame_number: 42,
                rank: 0,
                output: vec![1, 2, 3],
                ..Default::default()
            }),
            ..Default::default()
        };
        let bytes = to_protojson(GLOBAL_FRAME, &frame).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let header = &v["header"];
        // camelCase json name + 64-bit int as STRING.
        assert_eq!(header["frameNumber"], serde_json::json!("42"));
        // EmitUnpopulated: a zero field is present (as a string, since u64).
        assert_eq!(header["rank"], serde_json::json!("0"));
        // bytes -> standard base64.
        assert_eq!(header["output"], serde_json::json!("AQID"));
    }
}
