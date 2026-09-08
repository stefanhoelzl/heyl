# `sync-unauthenticated` — no credentials

`domain.SyncService/Sync` with a valid `client-type` but no `authorization` header.

| field | value |
|---|---|
| `grpc-status` | 16 (`UNAUTHENTICATED`) |
| `grpc-message` | `missing credentials` |
| `DomainError.code` | 30100 |
| `DomainError.user_title` | `Could not identify client` |

**Error envelope.** `grpc-status-details-bin` is base64 (standard alphabet, unpadded) of a
`google.rpc.Status`, whose `details[0]` is an `Any` with type URL
`type.googleapis.com/domain.DomainError` wrapping
`DomainError { code, user_title, user_detail, request_id }`.

`domain.Status` in `errors.proto` is structurally identical to `google.rpc.Status`, so the
schema decodes its own error envelope — no `google/rpc/status.proto` dependency needed.

`request_id` is per-request and will differ on re-capture; nothing else here is volatile.
