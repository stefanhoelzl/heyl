//! Errors raised while decoding a vault document.

/// Anything that can go wrong decoding a commit blob.
///
/// No variant carries plaintext: a vault document holds titles and usernames,
/// and while those are not passwords they are still the user's data.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum VaultError {
    /// The decrypted blob was empty, so there is no format byte.
    #[error("decrypted blob is empty")]
    Empty,

    /// The first byte is not one of the three formats `serialize.ts` emits.
    #[error("unknown serialization format: first byte is {byte:#04x}")]
    UnknownFormat {
        /// The byte we did not recognise.
        byte: u8,
    },

    /// A legacy automerge document.
    ///
    /// Reported rather than guessed at: `0x5B` documents are read-only and
    /// best-effort by design, and v1 does not implement automerge
    /// (DESIGN.md §4).
    #[error("this vault is a legacy automerge document, which heyl cannot read")]
    LegacyAutomerge,

    /// Snappy could not decompress the payload.
    #[error("snappy decompression failed")]
    Decompression,

    /// Snappy refused to compress a document we built.
    #[error("snappy compression failed")]
    Compression,

    /// The document is at a content-descriptor version v1 must not write to.
    ///
    /// A rail from DESIGN.md §3: writing a schema we have not read is how a
    /// vault gets corrupted by a client that meant well.
    #[error("refusing to write a version {version} document (heymerge is {expected})")]
    NotWritableVersion {
        /// What the document declared.
        version: u64,
        /// What we are willing to write.
        expected: u64,
    },

    /// The payload is not the `{type, version, content}` envelope.
    #[error("vault content is not a heymerge document: {what}")]
    NotADocument {
        /// Which part was wrong.
        what: &'static str,
    },
}
