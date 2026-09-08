# Protocol fixtures

Four HTTP exchanges captured against `https://heylogin.app/api/v1` on 2026-09-08, during the
M0 spike. Each `.http` is the verbatim exchange — request line, headers, hex body, response
headers, base64 `grpc-status-details-bin`. Each `.md` decodes what it means, because a base64
trailer is unreadable and the point of keeping these is that a future reader gets the error
taxonomy without re-deriving it.

| fixture | proves |
|---|---|
| `ping-ok` | the backend serves a client identifying as `CLIENT_TYPE_CLI = 400` |
| `missing-client-type` | `client-type` is mandatory and enum-validated |
| `sync-unauthenticated` | error envelope shape; `DomainError` 30100 |
| `sync-bad-token` | absent vs rejected credentials are distinguished |

These are the inputs for DESIGN.md §6's "recorded request/response fixtures" test layer. Only
`request_id` and `date` are volatile; re-capturing changes nothing else.
