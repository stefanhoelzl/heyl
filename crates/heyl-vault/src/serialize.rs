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
    /// An empty document, for a vault that has no commits to fold.
    ///
    /// It carries no content, so a reader finds no elements in it — which is
    /// exactly what an empty vault is. The framing is the one every heymerge
    /// vault uses, so it would round-trip through [`encode`] if a caller ever
    /// wrote it, though a no-commit vault is only ever read.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            format: Format::Snappy,
            document_type: String::new(),
            version: DESCRIPTOR_VERSION_HEYMERGE,
            content: Map::new(),
        }
    }

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

/// Re-serialize a document into a commit blob, in the framing it arrived in.
///
/// The inverse of [`decode`], and the write half of DESIGN.md §3's
/// read-modify-write: a commit blob is the **full serialized state**, so a
/// caller edits the [`Document`] it decoded and hands the whole thing back.
/// Key order is preserved (`serde_json/preserve_order`), so keys we never
/// touched — including ones no schema of ours knows about — come back out in
/// the order heylogin wrote them.
///
/// # Errors
/// [`VaultError::NotWritableVersion`] unless the content descriptor is
/// [`DESCRIPTOR_VERSION_HEYMERGE`]; [`VaultError::Compression`] if snappy
/// refuses the payload.
pub fn encode(document: &Document) -> Result<Vec<u8>, VaultError> {
    if !document.is_writable_version() {
        return Err(VaultError::NotWritableVersion {
            version: document.version,
            expected: DESCRIPTOR_VERSION_HEYMERGE,
        });
    }

    let mut object = Map::new();
    object.insert(
        "type".to_owned(),
        Value::String(document.document_type.clone()),
    );
    object.insert("version".to_owned(), Value::from(document.version));
    object.insert(
        "content".to_owned(),
        Value::Object(document.content.clone()),
    );
    let payload =
        serde_json::to_vec(&Value::Object(object)).map_err(|_| VaultError::NotADocument {
            what: "document does not serialize as JSON",
        })?;

    Ok(match document.format {
        Format::Snappy => {
            let mut out = Vec::with_capacity(payload.len());
            out.push(0x01);
            out.extend_from_slice(
                &snap::raw::Encoder::new()
                    .compress_vec(&payload)
                    .map_err(|_| VaultError::Compression)?,
            );
            out
        }
        // The opening brace is the marker: the payload is already framed.
        Format::Heymerge => payload,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn document(format: Format, version: u64) -> Document {
        let mut content = Map::new();
        content.insert("sessions".to_owned(), Value::Object(Map::new()));
        content.insert("accountSettings".to_owned(), Value::Object(Map::new()));
        Document {
            format,
            document_type: "meta".to_owned(),
            version,
            content,
        }
    }

    #[test]
    fn round_trips_through_both_framings() {
        for format in [Format::Snappy, Format::Heymerge] {
            let original = document(format, DESCRIPTOR_VERSION_HEYMERGE);
            let blob = encode(&original).expect("encodes");
            assert_eq!(decode(&blob).expect("decodes"), original);
        }
    }

    #[test]
    fn snappy_output_carries_the_format_marker() {
        let blob = encode(&document(Format::Snappy, DESCRIPTOR_VERSION_HEYMERGE)).expect("encodes");
        assert_eq!(blob.first(), Some(&0x01));
    }

    #[test]
    fn uncompressed_output_is_its_own_marker() {
        let blob =
            encode(&document(Format::Heymerge, DESCRIPTOR_VERSION_HEYMERGE)).expect("encodes");
        assert_eq!(blob.first(), Some(&0x7B));
    }

    /// DESIGN.md §3: never write to a descriptor version we have not read.
    #[test]
    fn refuses_a_version_we_do_not_write() {
        let err = encode(&document(Format::Snappy, 3)).expect_err("refuses");
        assert!(matches!(
            err,
            VaultError::NotWritableVersion { version: 3, .. }
        ));
    }

    /// Keys we never touched keep their order, including unknown ones.
    #[test]
    fn preserves_unknown_keys_and_their_order() {
        let mut original = document(Format::Snappy, DESCRIPTOR_VERSION_HEYMERGE);
        original
            .content
            .insert("somethingWeDoNotKnow".to_owned(), Value::from(7));
        let decoded = decode(&encode(&original).expect("encodes")).expect("decodes");
        assert_eq!(
            decoded.content.keys().collect::<Vec<_>>(),
            original.content.keys().collect::<Vec<_>>()
        );
    }
}
