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
secrets-env cargo run -p heyl-fixtures -- record --out .work/session.json
```

### `probe-signing` — retired at M3

Gone. It existed to settle what `CreateTokens` actually verifies: `HEYLOGIN_SPEC.md`
§5 reads as `Ed25519.sign(challenge)`, but §2 says every signing operation is
context-prefixed and names no context for this one, so the signed bytes were
ambiguous between the challenge's UTF-8 and its base64 decoding. It probed that
by varying `client-type`, the authenticator id and the signature, on one RPC.

`heyl api` does all three as ordinary arguments, on any of the 123 RPCs:

```sh
cargo run -p heyl --features api -- api call CreateTokens '{…}' --client-type 100
```

The answer it found is UTF-8, and it is pinned in `heyl_domain::ChallengeEncoding`
and in the offline suite.

### `record`

Captures a whole session's gRPC-Web bytes in one pass — challenge, tokens, sync,
authenticator list, every `ListCommits`. One pass, because a recording is made
during a real destructive recovery and that opportunity does not repeat without
pairing a phone again.

The output holds **real key material and a live token**. It is input to `rekey`,
never something to commit.

### `rekey`

Turns a real recorded exchange into a committable fixture whose key material is
entirely synthetic — a synthetic recovery code, Argon2id salt and checksum, and
every layer re-encrypted under the seed they derive — while keeping the real
heylogin *plaintext*: genuine `serialize` framing, genuine snappy, a genuine
heymerge document.

This exists because the seed alone is full account access (login is just
`sign(challenge, login_key(seed))`; the recovery code is only a way to reach
it), so committing the throwaway account's seed would burn it.

It asserts both halves before writing: that the committed test code opens the
result, and that the real one does not. The second half is what catches a layer
the re-key forgot — a fixture the account's own code still opens is one that
still contains it.

**Operates on gRPC-Web frames today.** The corpus milestone moves it to typed
messages, where re-keying is rewriting fields rather than decoding, editing and
re-encoding frames — which is most of why it is 600 lines.

**What no fixture can carry.** Evidence that our context salts match
heylogin's. Re-keyed ciphertexts are made with our own salts, so they prove the
plumbing and nothing about the agreement — and any artifact that *could* prove
it offline would, by construction, be openable with a committed key. That
confirmation is `heyl doctor` against a real account, and it is live-only.
