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

`record` needs a real account and your phone, which is why it is here rather
than in the test suite. It needs **no secrets**: pairing is a swipe, and
nothing is re-keyed afterwards.

### The recording account is a burner whose keys are published

A committed fixture carries the account's **seed** — it is in the pairing reply,
and `meta.first_draw` states the draw it is sealed to — and therefore its
profile seeds, its vault keys and its vault contents. That is deliberate: it is
what lets a scenario open with nothing but this repository, and it is why there
is no re-key. The alternative was five hundred lines rebuilding every layer
under synthetic keys, to protect an account that holds only fabricated
credentials.

**So the account may never hold anything real, and its keys must be retired
after every sitting, before publishing:**

1. **Reset the phone with the backup code.** The backup-code login makes the
   server delete the PUSH authenticator, and the phone re-enrols with a fresh
   seed, so the published seed's authenticator no longer exists and cannot log
   in. *On its own this rotates nothing* — measured: a recovery left every
   profile and vault generation unchanged.
2. **Regenerate the backup code in the app.** That deletes an authenticator
   through the client path, which regenerates every profile seed and rotates
   the vault keys — measured: four profiles and five vaults moved
   (`HEYLOGIN_SPEC.md` §7). *On its own this is useless*, because a surviving
   authenticator's published seed simply receives the new locks.

Neither half works without the other, and the order is reset-then-regenerate.
`record` prints both before it exits, because forgetting them is silent: no
test goes red, there is just a live account in a public repository.

Two vaults may come back `dirty: true` rather than rotated — they squash at the
next commit by a client with access, so open the app and touch them.

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

### Reading a real account without destroying it

`api derive` used to start at a recovery code, which meant the only way to reach
a seed by hand was the **destructive** login: `CreateTokens` with a
`BACKUP_CODE` signature disconnects the phone authenticator. That is fine when
the recovery *is* the subject, and wrong when you only want to look at a
document — which is most sittings, because the read path is designed against
what heylogin actually stores.

`api open-unlock` is the swipe-side counterpart of `sign-challenge`: the one
piece of arithmetic between a session and its seed, pure and offline.

```sh
export HEYL_STORE=$PWD/store.json          # a --features dev build writes here
cargo run -p heyl --features dev -- session create lab --unlock     # one swipe

TOKEN=$(jq -r '.secrets["heyl:lab/access_token"]'    "$HEYL_STORE")
KEY=$(jq   -r '.secrets["heyl:lab/session_priv_key"]' "$HEYL_STORE")

heyl api call Sync --token "$TOKEN" > sync.json
SEED=$(heyl api open-unlock --key "$KEY" \
         --blob "$(jq -r '.syncUpdate.sessionUnlock.encryptedSecret' sync.json)")

heyl api call AuthenticatorService/List --token "$TOKEN" > auths.json  # the only secretSalt source
heyl api call ListCommits '{"vaultId":"…","forceLocks":true}' --token "$TOKEN" > commits-1.json

heyl api derive --seed "$SEED" --salt "$SALT" --authenticator "$AUTH_ID" \
                --sync sync.json --commits commits-1.json
heyl api decode --blob "$BLOB" --key "$VAULT_SECRET"
```

Nothing here is destroyed: the phone stays paired, the recovery code is unspent,
and no fixture is written — so **the retirement ritual is not owed for a sitting
that only looks**. It is owed the moment a recording is committed.

A store key is `SecretKey::service()` + `/` + the item name — `heyl/access_token`
for the default slot, `heyl:<slot>/access_token` for a named one.

### `record`

Fills in a scenario against a real account, in one command.

A scenario file starts as the list of invocations you wrote and nothing else.
It is already a test at that point, and a **failing** one: `build.rs` turns every
file in `crates/heyl-cli/tests/scenarios/` into a `#[test]`, and one with no
recording fails with the command that finishes it. That is the point — an
invocation list nobody recorded is unfinished work, and a suite that stayed
green over it is what would let it be forgotten.

```json
{
  "meta": { "code": "", "first_draw": "" },
  "steps": [
    { "argv": ["session", "create", "ci", "--timeout", "1h"],
      "note": "scan the QR below with the heylogin app" },
    { "argv": ["session", "unlock", "ci"],
      "note": "approve the notification on your phone",
      "collapse": ["/domain.SyncService/Sync"] },
    { "argv": ["session", "get"], "env": { "HEYL_SESSION": "ci" } },
    { "argv": ["session", "list"] }
  ]
}
```

`note` is printed as a banner before its step runs, so the file is its own
runbook: a sitting that wants a swipe here, an approval there and a deliberate
*non*-approval somewhere else says so, and re-recording it a year later needs no
memory. `collapse` names the methods whose repeated identical answers are kept
once — the unlock poll asks `Sync` every second until you approve, and a replay
drives the same loop from one locked answer followed by the granted one. `env`
is what a step needs in its environment; the harness writes its own variables
afterwards, so a step can add `HEYL_SESSION` and cannot redirect the endpoint.
`--format json` is supplied by the recorder and the runner alike, and never
appears in argv.

`redact` blanks a value before comparing, for anything a replay cannot
reproduce. Nothing in a freshly recorded scenario needs it any more — the
recording's own first draw is committed, so even `session create`'s pairing URL
comes out the same on replay — but the field stays for the fixtures that were
re-keyed before this, whose committed output was printed with different key
material.

```sh
cargo run -p heyl-fixtures -- record --all          # everything that has no recording
cargo run -p heyl-fixtures -- record \               # or name them, in the order given
  --scenario crates/heyl-cli/tests/scenarios/session-lifecycle.json
```

`--all` records every scenario whose steps have no expected output — the same test the suite applies
— in alphabetical order, **except that a scenario driving `recovery` goes last**: the backup-code
login deletes the PUSH authenticator every other recording pairs with, so taking it first would
waste the sitting. Each file is written as it finishes, so a failure costs the file it was filling
and nothing before it.

It **builds `heyl --features dev` itself** and records that binary, because a
recording costs a phone swipe and a device on a real account, and the way to
waste one is to drive a `heyl` from last week. `HEYL_BINARY` overrides it, for
the case this cannot serve: recording against a binary that is deliberately not
the working tree's.

Each step runs as the real binary, pointed by `HEYL_ENDPOINT` at a **recording proxy** on loopback:
it decodes each call, forwards it to the real backend, keeps what crossed, and encodes the reply
back. The calls are heylogin's own, in the order the product actually asks for them, because it *is*
the product asking — and the binary carries no recording code, only the endpoint variable a
`--features dev` build reads. The proxy and the replay server are the same server over a different
`HeyloginApi`. What the step printed is kept too, and it is the expectation: stdout is captured while
stderr stays inherited, so the QR still draws for your phone.

`meta.first_draw` is set to the draw the run actually made, which is what lets a replay derive the
same ephemeral pairing key and open the seed the phone sent. Two values do not go in verbatim: the
**access token**, because a bearer token in a public repository is what secret scanners are built to
find, and the **email address**, because the account is published on purpose and a person's mailbox
is not part of that bargain. Everything else is exactly what heylogin sent.

The file is a test the moment `record` returns, and the next thing to run is the suite:

```sh
cargo test -p heyl --features dev scenario::session_lifecycle
```

Green means the corpus drives the binary to the same documents the live account did. `HEYL_BLESS=1`
exists for the other direction: when you change what a command prints *on purpose* and want the
expectations rewritten.

`recovery-then-doctor.json` predates all of this. It was converted from the corpus M2 captured,
because that recording holds the one shape no later one can reproduce — a `CreateChallenge` that
still lists a push authenticator, which performing the recovery deletes — and it is **re-keyed**,
carrying synthetic material rather than the account's. It still replays; nothing needs to be done to
it. It simply cannot be reproduced, so leave it alone.

Two scenarios need no account at all — `session-slot-exists` and `session-refusals` — because what
they pin is a refusal that never reaches the backend. They are hand-written, `calls` is `[]`, and
`meta.store` states the local state they start from. The suite tells those apart from an unrecorded
file by `stdout`: `[]` is "it printed nothing", absent is "nobody has run this yet".

**What no fixture can carry.** Evidence that our context salts match
heylogin's. A recording proves the plumbing — real framing, real snappy, a real
heymerge document, through the real mapping — but any artifact that could prove
the *agreement* offline would, by construction, be openable with a committed
key, which is precisely what these fixtures are. That confirmation is
`heyl doctor` against a real account, and it is live-only.
