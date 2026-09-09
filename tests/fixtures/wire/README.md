# Wire fixture

`session.json` is a **real heylogin session** with every secret replaced.

It was captured by `heyl-fixtures record` during an actual recovery — including
the one shape no later recording can reproduce, a `CreateChallenge` that still
lists a push authenticator, because performing the recovery deletes it. Then
`heyl-fixtures rekey` opened the real chain once, locally, and rebuilt every
layer under synthetic material.

**What is real:** the vault documents. Genuine `serialize` framing, genuine
snappy, genuine heymerge — decrypted with the account's key and re-encrypted
with the test one, so the bytes a parser sees are heylogin's own.

**What is synthetic:** everything that is or verifies a secret. The recovery
code, the seed, `secretInfo.checksum` (it is `SHA512(seed)[:32]` — an offline
verifier, and publishing one would hand out an oracle for testing candidate
codes), `secretSalt`, the access token, the session key, and every sealed blob:
profile-seed locks, vault-key locks, the session unlock, every commit. Request
bodies are dropped entirely rather than re-keyed — they carried a signature and
a sealed seed, and what is not committed cannot leak.

Every published public key is re-derived from the synthetic chain, so
`doctor`'s derived-vs-published comparison still passes.

## The rule

**The fixture must open with the committed test code and with nothing else.**

`rekey` asserts both halves before writing: that the test code opens it, and
that the real one does not. The second half is what catches a layer the re-key
forgot — a fixture the account's own code still opens is one that still
contains it.

`meta` states the test code and the session seed, so a replay does not have to
guess which random values produced the fixture.

## What replays it

`crates/heyl-cli/tests/wire_replay.rs` feeds these bytes through the real
`heyl-grpc` adapter and runs the whole use case: recovery, then `doctor`. Both
defects M2 shipped lived in that adapter — a lock-mapping rule, and reading
`DomainError` from the wrong `tonic` API — and one passed green because the test
hand-built the `Status` the way the broken code read it. A port-level fake
cannot catch either, by construction.

## Regenerating

Needs a real account, and the recording step is destructive:

```sh
secrets-env -- cargo run -p heyl-fixtures -- record --out .work/recording.json
secrets-env -- cargo run -p heyl-fixtures -- rekey
```

`rekey` needs `HEYL_RECOVERY_CODE` because the commit blobs are encrypted with
the real vault key: preserving the real documents means opening them once. The
code never reaches the output.

`.work/` is gitignored and holds the raw recording, which **does** contain real
key material and a live token until `rekey` has run.
