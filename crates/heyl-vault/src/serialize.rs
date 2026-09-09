//! `serialize.ts`: the first byte selects the format.

use serde_json::{Map, Value};

use crate::error::VaultError;

/// heymerge's content-descriptor version. A document at any other version is
/// not one we may write to (DESIGN.md §3).
pub const DESCRIPTOR_VERSION_HEYMERGE: u64 = 2;

/// Which framing the blob used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Format {
    /// `0x01` — Snappy raw block.
    Snappy,
    /// `0x7B` — uncompressed JSON, heymerge.
    Heymerge,
}

impl Format {
    /// How this format prints in `doctor`'s report.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Snappy => "snappy",
            Self::Heymerge => "json",
        }
    }
}

/// A decoded vault document: `{ type, version, content }`.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Document {
    /// How the blob was framed.
    pub format: Format,
    /// The document's declared `type`, e.g. a vault-content schema name.
    pub document_type: String,
    /// The content-descriptor version. Must be
    /// [`DESCRIPTOR_VERSION_HEYMERGE`] before anything may be written back.
    pub version: u64,
    /// The document body, with key order preserved.
    pub content: Map<String, Value>,
}

impl Document {
    /// Whether this document is one v1 would be allowed to write to.
    ///
    /// M2 never writes; the check lives here because it is a property of the
    /// document, and M5 needs it before its first commit.
    #[must_use]
    pub const fn is_writable_version(&self) -> bool {
        self.version == DESCRIPTOR_VERSION_HEYMERGE
    }

    /// How many top-level keys the content carries — `doctor`'s evidence that
    /// the document is real rather than merely well-framed.
    #[must_use]
    pub fn content_keys(&self) -> usize {
        self.content.len()
    }
}

/// Decode a decrypted commit blob.
///
/// # Errors
/// [`VaultError::LegacyAutomerge`] for a `0x5B` document, which v1 reports
/// rather than guesses at; [`VaultError::UnknownFormat`] for anything else;
/// [`VaultError::Decompression`] or [`VaultError::NotADocument`] if the payload
/// does not hold up.
pub fn decode(blob: &[u8]) -> Result<Document, VaultError> {
    let (&first, _) = blob.split_first().ok_or(VaultError::Empty)?;

    let (format, payload) = match first {
        0x01 => (
            Format::Snappy,
            snap::raw::Decoder::new()
                .decompress_vec(&blob[1..])
                .map_err(|_| VaultError::Decompression)?,
        ),
        // Uncompressed JSON keeps its opening brace: the byte is the format
        // marker *and* part of the payload.
        0x7B => (Format::Heymerge, blob.to_vec()),
        0x5B => return Err(VaultError::LegacyAutomerge),
        byte => return Err(VaultError::UnknownFormat { byte }),
    };

    let value: Value = serde_json::from_slice(&payload).map_err(|_| VaultError::NotADocument {
        what: "payload is not JSON",
    })?;
    let Value::Object(mut object) = value else {
        return Err(VaultError::NotADocument {
            what: "payload is not a JSON object",
        });
    };

    let document_type = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or(VaultError::NotADocument { what: "no `type`" })?
        .to_owned();
    let version =
        object
            .get("version")
            .and_then(Value::as_u64)
            .ok_or(VaultError::NotADocument {
                what: "no `version`",
            })?;
    let Some(Value::Object(content)) = object.remove("content") else {
        return Err(VaultError::NotADocument {
            what: "`content` is not an object",
        });
    };

    Ok(Document {
        format,
        document_type,
        version,
        content,
    })
}
