//! The vault serialization format — **framing only**.
//!
//! `serialize.ts` picks the format from the first byte of the decrypted blob:
//!
//! | byte | meaning |
//! |---|---|
//! | `0x01` | Snappy-compressed (raw block), payload is `JSON.stringify(content)` |
//! | `0x5B` `[` | uncompressed JSON — **automerge**, legacy |
//! | `0x7B` `{` | uncompressed JSON — heymerge |
//!
//! What this crate does **not** do at M2: heymerge semantics, the
//! `LoginVaultContentV2` schema, and `ProtectedValue` decryption. Those are M3.
//! M2 needs exactly enough to turn "the blob decrypted" into "and it is
//! structurally a heylogin vault document", which is what makes `doctor`'s
//! report evidence rather than a byte check.
//!
//! `serde_json` is built with `preserve_order` because the content schemas use
//! `objectPassthrough`: unknown keys must survive a read-modify-write in their
//! original order, or M5's `SessionMetadata` commit would silently reorder every
//! key in the META vault (DESIGN.md §4).

pub mod error;
pub mod login;
pub mod merge;
pub mod meta;
pub mod serialize;
pub use error::VaultError;
pub use merge::fold;
pub use serialize::{DESCRIPTOR_VERSION_HEYMERGE, Document, Format, decode, encode};
