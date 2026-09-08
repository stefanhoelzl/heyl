# heylogin protobuf schema

53 files, package `domain` (+ `domainerr`), recovered from the published Firefox
extension v1.15.813. Regenerate with `tools/extract-protos/`; the extraction is
verified lossless against the descriptors embedded in the shipped bundle.

| | |
|---|---|
| Services | 19 |
| Methods | 123 — 122 unary, 1 server-streaming, **0 client-streaming, 0 bidi** |
| Messages | 283 top-level |
| Enums | 33 |
| Well-known types | `timestamp.proto`, `wrappers.proto`, `any.proto` |

The streaming profile matters: the single streaming method is
`SyncService.StreamingSync` (server-streaming), so **gRPC-Web is sufficient for the
entire surface** — it only lacks client-streaming and bidirectional streaming.

`ClientType` already reserves `CLIENT_TYPE_CLI = 400`.

Comments are not recoverable — `protoc-gen-es` strips `source_code_info` before
embedding the descriptors.
