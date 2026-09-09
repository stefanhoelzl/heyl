# heyl

**Unofficial** command-line client for [heylogin](https://heylogin.com) — retrieve passwords,
TOTP codes and custom fields from your vault in a shell or a script.

> [!IMPORTANT]
> Not affiliated with, authorised by, or endorsed by heylogin. "heylogin" is a trademark of its
> respective owner. This is an independent reimplementation of the client protocol, built for
> interoperability, containing no code from heylogin's own clients. Do not report heylogin
> service issues here.

## Status

**Early implementation — M2 of 11 is built; the login path is not yet confirmed
against a live account.** There is a `heyl` binary, and it does two things:

```sh
heyl login recovery --email you@example.com   # HEYL_RECOVERY_CODE, or a hidden prompt
heyl doctor                                   # walk the key hierarchy, link by link
```

It is not usable as a password manager yet — reading logins is M3.

| | |
|---|---|
| [`DESIGN.md`](DESIGN.md) | Architecture, security model, command surface, milestones M0–M11 |
| [`HEYLOGIN_SPEC.md`](HEYLOGIN_SPEC.md) | The protocol, reverse-engineered from published client bundles |
| [`crates/heyl-crypto/`](crates/heyl-crypto/) | §2 primitives, `deriveSecretFromSeed`, the context salts — deterministic, `mlock`ed, no `unsafe` |
| [`crates/heyl-domain/`](crates/heyl-domain/) | Identifiers, locks, heymerge-compatible timestamps, the authenticator → profile → vault key chain |
| [`crates/heyl-ports/`](crates/heyl-ports/) | The port traits — the backend, keychain, terminal, clock, randomness |
| [`crates/heyl-app/`](crates/heyl-app/) | The use cases: login, unlock, doctor. No transport, no OS, no runtime |
| [`crates/heyl-grpc/`](crates/heyl-grpc/) | gRPC-Web adapter; the only crate that sees the generated types |
| [`crates/heyl-cli/`](crates/heyl-cli/) | The `heyl` binary and the composition root |
| [`descriptors/`](descriptors/) | The schema as a `FileDescriptorSet` — 19 services, 123 methods, extraction verified lossless |
| [`tests/fixtures/protocol/`](tests/fixtures/protocol/) | Recorded gRPC-Web exchanges: the happy path and three error shapes |
| [`tools/extract-protos.py`](tools/extract-protos.py) | Regenerates and re-verifies the schema in one command |

**What is and is not established.** The primitives are checked against RFC 8032,
RFC 4231 and FIPS 180-4 vectors, and the whole M2 path — typed recovery code →
Argon2id → seed → every link → a decrypted commit — runs offline in CI against a
synthetic account.

What none of that establishes is that the heylogin-specific **composition** —
which context salt, concatenated in which order, truncated where — agrees with
heylogin. A mistyped context produces stable, self-consistent, wrong keys and
the suite stays green, because the fixtures were built with those same contexts.
This is not a gap that can be closed offline: any artifact proving agreement
would, by construction, be openable with a committed key.

So it is confirmed live, once, against a real account — `heyl doctor` compares
every key it derives against the public half heylogin publishes, and reports
per link. Two things are still open until that run happens:

- **What `CreateTokens` actually verifies.** §5 reads as `Ed25519.sign(challenge)`,
  but §2 says every signing operation is context-prefixed and names no context
  for this one, so the signed bytes are ambiguous. `heyl-fixtures probe-signing`
  settles it empirically rather than by guessing.
- **Whether the derived keys match.** That is what `heyl doctor` is for.

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
