# Development tools

Not shipped, not published, not on any user's machine. `tools/*` is a workspace
member so one `cargo fmt`/`clippy`/`test` pass covers it, and
`ci/check-dep-graph.sh` lets it depend on anything — exactly like `heyl-cli`.

## `extract-protos.py`

Regenerates and re-verifies `descriptors/heylogin.binpb`. The `.proto` sources
are derived output and are not committed; render them to read the schema:

```sh
python3 -m venv .venv && ./.venv/bin/pip install protobuf
./.venv/bin/python tools/extract-protos.py render      # -> proto/*.proto (gitignored)
```

## `heyl-fixtures`

Both subcommands need a real account, which is why they are here rather than in
the test suite. Run them under `secrets-env` so nothing reaches shell history:

```sh
secrets-env cargo run -p heyl-fixtures -- probe-signing
```

### `probe-signing`

Settles what `CreateTokens` actually verifies. `HEYLOGIN_SPEC.md` §5 reads as
`Ed25519.sign(challenge)`, but §2 says every signing operation is
context-prefixed and names no context for this one — so the signed bytes are
ambiguous between the challenge's UTF-8 and its base64 decoding under either
alphabet. A wrong choice produces a perfectly valid signature over the wrong
message, which the backend rejects with no diagnostic pointing at the cause.

M0 settled the transport by probing rather than reasoning; this does the same
for the signature. It paces its attempts, because each one submits a
deliberately wrong signature and heylogin's lockout behaviour on repeated
failures is unknown.

Three outcomes, all informative:

| result | means |
|---|---|
| exactly one accepted | that is the answer — make it the default and pin it in the offline suite's fake |
| a candidate ruled out with no network call | it cannot decode the challenge, which rules it out for free |
| none accepted | the hypothesis set is wrong; the next one is a context-prefixed variant, whose context string is not recoverable from the published bundles |

### `rekey`

Turns a real recorded exchange into a committable fixture whose key material is
entirely synthetic — a synthetic recovery code, Argon2id salt and checksum, and
every layer re-encrypted under the seed they derive — while keeping the real
heylogin *plaintext*: genuine `serialize` framing, genuine snappy, a genuine
heymerge document.

This exists because the seed alone is full account access (login is just
`sign(challenge, login_key(seed))`; the recovery code is only a way to reach
it), so committing the throwaway account's seed would burn it.

**Not yet implemented**: it needs a real recording, which needs the live login
path, which is blocked on `probe-signing`. CI is not waiting on it — the offline
suite in `crates/heyl-app/tests/` already builds an equivalent fixture
synthetically. What `rekey` adds is real heylogin document bytes in place of a
hand-written envelope.

**What no fixture can carry.** Evidence that our context salts match
heylogin's. Re-keyed ciphertexts are made with our own salts, so they prove the
plumbing and nothing about the agreement — and any artifact that *could* prove
it offline would, by construction, be openable with a committed key. That
confirmation is `heyl doctor` against a real account, and it is live-only.
