# heyl

**Unofficial** command-line client for [heylogin](https://heylogin.com) — retrieve passwords,
TOTP codes and custom fields from your vault in a shell or a script.

> [!IMPORTANT]
> Not affiliated with, authorised by, or endorsed by heylogin. "heylogin" is a trademark of its
> respective owner. This is an independent reimplementation of the client protocol, built for
> interoperability, containing no code from heylogin's own clients. Do not report heylogin
> service issues here.

## Status

**Design phase — there is no implementation yet.** What exists today:

| | |
|---|---|
| [`DESIGN.md`](DESIGN.md) | Architecture, security model, command surface, milestones M0–M11 |
| [`HEYLOGIN_SPEC.md`](HEYLOGIN_SPEC.md) | The protocol, reverse-engineered from published client bundles |
| [`proto/`](proto/) | 53 `.proto` files — 19 services, 123 methods — extraction verified lossless |
| [`tools/extract-protos.py`](tools/extract-protos.py) | Regenerates and re-verifies the schema in one command |

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
