# `sync-bad-token` — credentials present but invalid

`domain.SyncService/Sync` with `authorization: backend deadbeef`.

| field | value |
|---|---|
| `grpc-status` | 7 (`PERMISSION_DENIED`) |
| `grpc-message` | `invalid credentials` |
| `DomainError.code` | 30420 |
| `DomainError.user_title` | `Invalid credentials` |

**Why this differs from `sync-unauthenticated`.** The backend distinguishes *absent* from
*rejected* credentials, with different gRPC codes and different `DomainError` codes. The CLI
should too: 30100 means "no session, log in", 30420 means "session gone, log in again" —
which maps to exit code 4 (`unlock required / expired`) in DESIGN.md §5, whereas 30100 on a
command that expected a session is a different user-facing message.
