# Development tools

Not shipped, not published, not on any user's machine. `tools/*` is a workspace
member so one `cargo fmt`/`clippy`/`test` pass covers it, and
`ci/check-dep-graph.sh` lets it depend on anything — exactly like `heyl-cli`.

## `--features dev` — the workbench

Three commands and one environment variable exist only in a build made with
`--features dev`. They are not in a release binary, and the reason is audience
rather than danger: each exists because someone is reverse-engineering a
protocol, not because a password-manager user needs it. **Point them at a
throwaway account.**

```sh
cargo build -p heyl --features dev
```

| | |
|---|---|
| `heyl api …` | heylogin's gRPC surface by hand, no guards. Every one of the 123 RPCs by name, and three pure functions that close a login. `api derive` prints seeds and vault keys. |
| `heyl doctor` | Derives every key and compares it against the public half heylogin publishes, then opens every vault. The oracle the reverse engineering is checked against (DESIGN.md §6). |
| `heyl recovery` | Account recovery with a recovery code. **Destructive** — the server deletes the push authenticator and its locks. It was how a session was reached before the phone swipe worked; a user who has lost their phone should recover in heylogin's own app. |
| `HEYL_ENDPOINT` | Point the binary at a recording proxy or the replay server instead of heylogin. There is no flag: a release build does not read the variable at all, so a shipped binary cannot be redirected by its environment. |

The feature also binds the scenario suite's two injected ports — a writable JSON
credential store and a scripted draw sequence — which is why a workbench build
must not be treated as a private one: its store is a file on disk (DESIGN.md §3).

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
cargo run -p heyl --features dev -- api call CreateTokens '{…}' --client-type 100
```

The answer it found is UTF-8, and it is pinned in `heyl_domain::ChallengeEncoding`
and in the offline suite.

### `record`

Fills in a scenario against a real account, in one command with four phases.

A scenario file starts as the list of invocations you wrote and nothing else:

```json
{
  "meta": { "code": "", "session_seed": "" },
  "steps": [
    { "argv": ["recovery", "--email", "you@example.com", "--confirm", "--format", "json"],
      "stdin": "1111-2222-3333-4444-5555-6666\n" },
    { "argv": ["doctor", "--format", "json"] }
  ]
}
```

```sh
cargo build -p heyl --features dev
HEYL_BINARY=target/debug/heyl secrets-env \
  cargo run -p heyl-fixtures -- record \
    --scenario crates/heyl-cli/tests/scenarios/recovery-then-doctor.json
```

1. **record** — each step runs as the real binary, pointed by `HEYL_ENDPOINT` at a **recording
   proxy** on loopback: it decodes each call, forwards it to the real backend, keeps what crossed,
   and encodes the reply back. The calls are heylogin's own, in the order the product actually asks
   for them, because it *is* the product asking — and the binary carries no recording code, only the
   `HEYL_ENDPOINT` variable a `--features dev` build reads. The proxy and the replay server are the same server over a
   different `HeyloginApi`. stdin is piped but stdout and stderr are inherited: `render_qr` tests
   *stdout* for a terminal while `is_interactive` tests *stdin*, so a pairing code draws for your
   phone while the binary still takes the branch a replay takes.
2. **rekey** — every secret becomes synthetic while the real heylogin *plaintext* stays: genuine
   `serialize` framing, genuine snappy, a genuine heymerge document. This exists because the seed
   alone is full account access (login is just `sign(challenge, login_key(seed))`; the recovery code
   is only a way to reach it), so committing the throwaway account's seed would burn it. It asserts
   both halves before writing — that the committed test code opens the result, and that the real one
   does not. The second half catches a layer the re-key forgot: a fixture the account's own code
   still opens is one that still contains it. It **operates on typed messages**, not frames, so a
   re-key is rewriting fields.
3. **replay** and 4. **expect** — the scenario suite itself, run with `HEYL_BLESS=1`, so there is one
   replay implementation rather than two that must agree:

```sh
HEYL_BLESS=1 cargo test -p heyl --features dev scenario::recovery_then_doctor
```

Expectations come from *that* run rather than the live one: the re-key moves identifiers, and live
output would carry the real account's. Replaying also proves the re-keyed scenario actually drives
the binary rather than merely parsing.

Between phases 1 and 2 the calls hold **real key material and a live token**. They stay in memory
and are never written — `--no-rekey` is the one path that writes them down, for debugging a
recording that went wrong, and it says so.

`recovery-then-doctor.json` was not produced this way: it was converted from the corpus M2 captured,
because that recording holds the one shape no later one can reproduce — a `CreateChallenge` that
still lists a push authenticator, which performing the recovery deletes. It carries no request
bodies for the same reason its predecessor did not, so its calls match on method and order alone.

**What no fixture can carry.** Evidence that our context salts match
heylogin's. Re-keyed ciphertexts are made with our own salts, so they prove the
plumbing and nothing about the agreement — and any artifact that *could* prove
it offline would, by construction, be openable with a committed key. That
confirmation is `heyl doctor` against a real account, and it is live-only.
