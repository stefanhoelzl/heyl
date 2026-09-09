//! Re-key a real recording into a committable fixture.
//!
//! # The problem this solves
//!
//! M2's confirmation is a live event against a real account. Keeping it alive
//! afterwards means committing something CI can replay — but the seed alone is
//! full account access (login is `sign(challenge, login_key(seed))`; the
//! recovery code is only a way to reach it), so committing the real seed would
//! burn the account.
//!
//! # What it does
//!
//! Decrypt the real recording once, locally, then re-encrypt **every layer**
//! under a synthetic test seed and recompute the published public keys to
//! match. The committed fixture keeps the real heylogin *plaintext* — genuine
//! `serialize` framing, genuine snappy, a genuine heymerge document — with
//! entirely synthetic key material, including a synthetic recovery code,
//! Argon2id salt and checksum, so the fixture exercises the whole path from a
//! typed code rather than from a seed.
//!
//! # What it cannot do
//!
//! Preserve evidence that our **context salts** match heylogin's. The re-keyed
//! ciphertexts are made with our own salts, so they prove the plumbing and
//! nothing about the agreement. That confirmation is live-only, by
//! construction: any artifact that proved it offline would be openable with a
//! committed key.

use std::path::Path;

/// Re-key a recording.
pub fn run(_out: &Path) -> Result<(), String> {
    Err("not implemented.\n\n\
         `rekey` needs a real recording to work from, which needs the live login path to \
         succeed first -- and that is blocked on `probe-signing` settling what CreateTokens \
         verifies. Run:\n\n    \
         secrets-env cargo run -p heyl-fixtures -- probe-signing\n\n\
         then implement the re-key against the recording it makes possible. The offline suite \
         in crates/heyl-app/tests/ already builds an equivalent fixture synthetically, so CI \
         is not blocked on this; what this adds is real heylogin document bytes in place of \
         the hand-written envelope."
        .to_owned())
}
