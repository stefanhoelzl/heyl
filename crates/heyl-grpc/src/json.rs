//! Canonical protobuf-JSON, in both directions.
//!
//! Not `serde` derives on the generated types: those would render every `bytes`
//! field as an array of integers and every enum as a bare `i32`, and this
//! schema is mostly bytes — sealed blobs, keys, signatures, commits. What comes
//! out here is the protobuf JSON mapping, which is base64 for bytes, names for
//! enums, camelCase `json_name` for fields and RFC 3339 for `Timestamp`. That
//! is the vocabulary `HEYLOGIN_SPEC.md` and heylogin's own client use, so what
//! you read matches what the spec says (DESIGN.md §4).
//!
//! Transcoding goes **through encoded bytes** rather than through
//! `prost-reflect`'s typed integration. That costs one round trip per call and
//! buys independence from which `prost` version `prost-reflect` happens to pull:
//! a `Vec<u8>` is a `Vec<u8>` across major versions.

use std::sync::OnceLock;

use prost::Message as _;
use prost_reflect::{DescriptorPool, DynamicMessage};

/// The schema, embedded.
///
/// The same artifact `heyl-proto` generates from and `tools/extract-protos.py`
/// produces — there is no second source of truth about what heylogin speaks.
const DESCRIPTORS: &[u8] = include_bytes!("../../../descriptors/heylogin.binpb");

/// Something the JSON layer could not do.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JsonError {
    /// The embedded descriptor set did not load. Cannot happen in a build that
    /// linked, which is why it is not worth a richer type.
    #[error("the embedded schema failed to load: {reason}")]
    Schema {
        /// What `prost-reflect` reported.
        reason: String,
    },

    /// The request body was not valid JSON for this message.
    #[error("{message_type} could not be read from JSON: {reason}")]
    Request {
        /// The protobuf message type, e.g. `domain.SyncRequest`.
        message_type: String,
        /// What went wrong.
        reason: String,
    },

    /// The response could not be rendered. Means our schema and the bytes
    /// disagree, which is a bug rather than bad input.
    #[error("{message_type} could not be rendered as JSON: {reason}")]
    Response {
        /// The protobuf message type.
        message_type: String,
        /// What went wrong.
        reason: String,
    },
}

/// The descriptor pool, built once.
///
/// # Errors
/// [`JsonError::Schema`] if the embedded descriptor set does not parse.
pub fn pool() -> Result<&'static DescriptorPool, JsonError> {
    static POOL: OnceLock<Result<DescriptorPool, String>> = OnceLock::new();
    POOL.get_or_init(|| DescriptorPool::decode(DESCRIPTORS).map_err(|e| e.to_string()))
        .as_ref()
        .map_err(|reason| JsonError::Schema {
            reason: reason.clone(),
        })
}

/// JSON → a typed message.
///
/// An empty body means the default message, so `heyl api ping` needs no
/// argument for an RPC whose request has no fields.
///
/// # Errors
/// [`JsonError::Request`] if the body is not valid JSON for `message_type`.
pub fn from_json<M: prost::Message + Default>(
    pool: &DescriptorPool,
    message_type: &str,
    body: &str,
) -> Result<M, JsonError> {
    let fail = |reason: String| JsonError::Request {
        message_type: message_type.to_owned(),
        reason,
    };
    let descriptor = pool
        .get_message_by_name(message_type)
        .ok_or_else(|| fail("not in the embedded schema".to_owned()))?;

    let body = body.trim();
    let dynamic = if body.is_empty() {
        DynamicMessage::new(descriptor)
    } else {
        let mut de = serde_json::Deserializer::from_str(body);
        DynamicMessage::deserialize(descriptor, &mut de).map_err(|e| fail(e.to_string()))?
    };

    M::decode(&*dynamic.encode_to_vec()).map_err(|e| fail(e.to_string()))
}

/// Raw protobuf bytes → JSON, given the message type.
///
/// What a migration needs: a recorded response body is bytes and a method
/// path, and only the descriptor set knows which message that is.
///
/// # Errors
/// [`JsonError::Response`] if the bytes are not that message.
pub fn bytes_to_json(
    pool: &DescriptorPool,
    message_type: &str,
    bytes: &[u8],
) -> Result<String, JsonError> {
    let fail = |reason: String| JsonError::Response {
        message_type: message_type.to_owned(),
        reason,
    };
    let descriptor = pool
        .get_message_by_name(message_type)
        .ok_or_else(|| fail("not in the embedded schema".to_owned()))?;

    let dynamic = DynamicMessage::decode(descriptor, bytes).map_err(|e| fail(e.to_string()))?;
    render(&dynamic, &fail)
}

/// A typed message → JSON.
///
/// # Errors
/// [`JsonError::Response`] if the message and the embedded schema disagree.
pub fn to_json<M: prost::Message>(
    pool: &DescriptorPool,
    message_type: &str,
    message: &M,
) -> Result<String, JsonError> {
    let fail = |reason: String| JsonError::Response {
        message_type: message_type.to_owned(),
        reason,
    };
    let descriptor = pool
        .get_message_by_name(message_type)
        .ok_or_else(|| fail("not in the embedded schema".to_owned()))?;

    let dynamic = DynamicMessage::decode(descriptor, &*message.encode_to_vec())
        .map_err(|e| fail(e.to_string()))?;
    render(&dynamic, &fail)
}

/// Serialize a dynamic message with the options both directions share.
fn render(
    dynamic: &DynamicMessage,
    fail: &impl Fn(String) -> JsonError,
) -> Result<String, JsonError> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::pretty(&mut buf);
    // `stringify_64_bit_integers` off: heylogin's own client reads these as
    // numbers, and a CLI that prints `"1234"` where the spec says `1234` is
    // lying about the wire.
    let options = prost_reflect::SerializeOptions::new()
        .stringify_64_bit_integers(false)
        .skip_default_fields(false);
    dynamic
        .serialize_with_options(&mut ser, &options)
        .map_err(|e| fail(e.to_string()))?;

    String::from_utf8(buf).map_err(|e| fail(e.to_string()))
}

/// A `SyncResponse` document → the domain snapshot, through the real mapping.
///
/// Lives here rather than in `heyl-cli` so the composition root still never
/// names a prost type: the dispatch and this are the only two ways JSON becomes
/// a message, and both are inside the one crate allowed to see `heyl-proto`
/// (DESIGN.md §4).
///
/// Deliberately the same [`crate::map::sync_update`] the port uses, so what a
/// caller walks is what `heyl doctor` would walk.
///
/// # Errors
/// [`JsonError`] if the document is not a `SyncResponse`; the mapping's
/// [`heyl_ports::ApiError`] if it carries no `syncUpdate` or a field the schema
/// requires is missing.
pub fn sync_snapshot(document: &str) -> Result<heyl_domain::SyncSnapshot, crate::DispatchError> {
    let pool = pool()?;
    let response: heyl_proto::SyncResponse = from_json(pool, "domain.SyncResponse", document)?;
    let update = response
        .sync_update
        .ok_or_else(|| heyl_ports::ApiError::MalformedResponse {
            what: "SyncResponse.sync_update".to_owned(),
        })?;
    Ok(crate::map::sync_update(&update)?)
}

/// A `ListCommits` document → the domain view, through the real mapping.
///
/// Here for the same reason as [`sync_snapshot`]: JSON becomes a prost type
/// only inside this crate.
///
/// # Errors
/// [`JsonError`] if the document is not a `ListCommitsResponse`; the mapping's
/// error if a required field is missing.
pub fn vault_commits(document: &str) -> Result<heyl_domain::VaultCommits, crate::DispatchError> {
    let pool = pool()?;
    let response: heyl_proto::ListCommitsResponse =
        from_json(pool, "domain.ListCommitsResponse", document)?;
    Ok(crate::map::vault_commits(&response)?)
}
