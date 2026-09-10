# `ping-ok` — the happy path

`domain.HealthService/Ping` with the mandatory `client-type: 400` (`CLIENT_TYPE_CLI`).

**What it proves.** The backend serves an unofficial client identifying itself as the CLI.
No impersonation of `CLIENT_TYPE_WEB = 100` is required.

**Response body, decoded.** Two gRPC-Web frames:

| bytes | meaning |
|---|---|
| `00 00 00 00 00` | data frame: flag `0x00`, length `0`, empty `PingResponse` |
| `80 00 00 00 10` | trailer frame: flag `0x80` marks trailers, length `0x10` = 16 |
| `67 72 70 63 ... 0d 0a` | `grpc-status: 0\r\n` |

Note the trailers arrive **in the body**, not as HTTP trailers — that is what gRPC-Web is.
