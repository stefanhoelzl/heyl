# heyl

**Unofficial** command-line client for [heylogin](https://heylogin.com) — retrieve passwords,
TOTP codes and custom fields from your vault in a shell or a script.

> [!IMPORTANT]
> Not affiliated with, authorised by, or endorsed by heylogin. "heylogin" is a trademark of its
> respective owner. This is an independent reimplementation of the client protocol, built for
> interoperability, containing no code from heylogin's own clients. Do not report heylogin
> service issues here.

## Status

**Early implementation — M1 of 11 is done; nothing runs yet.** There is no
`heyl` binary, and there will not be one until M2 can log in.

| | |
|---|---|
| [`DESIGN.md`](DESIGN.md) | Architecture, security model, command surface, milestones M0–M11 |
| [`HEYLOGIN_SPEC.md`](HEYLOGIN_SPEC.md) | The protocol, reverse-engineered from published client bundles |
| [`crates/heyl-crypto/`](crates/heyl-crypto/) | §2 primitives, `deriveSecretFromSeed`, the context salts — deterministic, `mlock`ed, no `unsafe` |
| [`crates/heyl-domain/`](crates/heyl-domain/) | Identifiers, locks, heymerge-compatible timestamps, the authenticator → profile → vault key chain |
| [`descriptors/`](descriptors/) | The schema as a `FileDescriptorSet` — 19 services, 123 methods, extraction verified lossless |
| [`tests/fixtures/protocol/`](tests/fixtures/protocol/) | Recorded gRPC-Web exchanges: the happy path and three error shapes |
| [`tools/extract-protos.py`](tools/extract-protos.py) | Regenerates and re-verifies the schema in one command |

**What M1 does and does not establish.** The primitives are checked against
RFC 8032, RFC 4231 and FIPS 180-4 vectors. The heylogin-specific *composition* —
which context salt, concatenated in which order, truncated where — is **not**
verified against heylogin, and cannot be without an account: a mistyped context
produces stable, self-consistent, wrong keys and the suite stays green. That is
confirmed at M2, when the backend accepts a signature and one real vault
decrypts. The derivation snapshots are stored one per link so that when it
fails, the diff names the link.

The `.proto` sources are derived output and are not committed. To read the schema:

```sh
python3 -m venv .venv && ./.venv/bin/pip install protobuf
./.venv/bin/python tools/extract-protos.py render      # -> proto/*.proto (gitignored)
```

## What it will do

```sh
heyl get github.com --field password
heyl totp aws-prod
heyl list --format json | jq -r '.[].title'
heyl run --env-file .env.tpl -- terraform apply
```

Read-only by design: it never creates, edits or deletes logins. The single exception is
registering itself as a named, revocable device in your heylogin app.

## Security posture

The 32-byte seed that unlocks everything is **never stored at rest**. The keychain holds only a
session token and a session private key — neither decrypts anything on its own. Each invocation
fetches the backend's session-unlock blob, recovers the seed in memory, uses it, and zeroizes.

The backend stops serving that blob when the unlock expires, so heylogin's re-swipe control is
enforced server-side rather than trusted to this client. See [`DESIGN.md`](DESIGN.md) §3.

## License

[Apache-2.0](LICENSE). See [`NOTICE`](NOTICE).
