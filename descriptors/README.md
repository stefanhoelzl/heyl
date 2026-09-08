# heylogin protobuf schema

`heylogin.binpb` is a `FileDescriptorSet` recovered from the published Firefox extension
v1.15.813. It is the **sole committed schema artifact** and the input every code generator
reads — no `protoc`, no `buf`, on any machine. Regenerate with `tools/extract-protos.py`; the
extraction is verified lossless against the descriptors embedded in the shipped bundle.

| | |
|---|---|
| Files | 56 — 53 heylogin (`domain`, `domainerr`) + 3 embedded well-known types |
| Services | 19 |
| Methods | 123 — 122 unary, 1 server-streaming, **0 client-streaming, 0 bidi** |
| Messages | 283 top-level (359 including nested) |
| Enums | 33 |

The streaming profile matters: the single streaming method is `SyncService.StreamingSync`
(server-streaming), so **gRPC-Web is sufficient for the entire surface** — it only lacks
client-streaming and bidirectional streaming. That is not merely sufficient but necessary:
gRPC-Web is the *only* protocol the backend speaks (see `DESIGN.md` §4).

`ClientType` already reserves `CLIENT_TYPE_CLI = 400`, and the backend accepts it.

## Reading the schema

The `.proto` sources are derived output and are **not** committed. Render them on demand:

```sh
python3 -m venv .venv && ./.venv/bin/pip install protobuf
./.venv/bin/python tools/extract-protos.py render      # -> proto/*.proto (gitignored)
```

## Well-known types are embedded, deliberately

`protoc-gen-es` strips `FileDescriptorProto.dependency`, so `tools/extract-protos.py` rebuilds
the import lists. Naming `google/protobuf/timestamp.proto` as a dependency is not enough: a set
that declares an import without containing it is exactly what `protoc --include_imports` guards
against, and Rust codegen fails on the first unresolved type. The three referenced well-known
types (`any`, `timestamp`, `wrappers`) are therefore embedded in the set, ahead of the files
that import them. They are protoc's files, not heylogin's, so `render` skips them and `verify`
excludes them from the comparison.

Comments are not recoverable — `protoc-gen-es` strips `source_code_info` before embedding the
descriptors.
