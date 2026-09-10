# `missing-client-type` — `client-type` is mandatory

The same `Ping`, with the `client-type` header omitted.

**What it proves.** `client-type` is required and validated against the `domain.ClientType`
enum. Omitting it, or sending a value not in the enum (`999`, `abc`), yields the same result.

| field | value |
|---|---|
| HTTP status | 200 (gRPC-Web reports errors in-band) |
| `grpc-status` | 13 (`INTERNAL`) |
| `grpc-message` | `bad request` |
| `DomainError.code` | 10400 `BAD_REQUEST` |
| `DomainError.user_title` | `Bad request` |

**The trap.** A client that silently drops this header gets a generic "bad request" with
nothing pointing at the cause. `connectrpc`'s `ClientConfig::with_default_header` silently
ignores headers it cannot convert, so assert the header landed rather than trusting it.
