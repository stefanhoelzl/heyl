# Vendored third-party crates

Upstream source, carried here only so a patch can be applied. Each keeps its
own `LICENSE`. Nothing here is our work, and nothing here is modified beyond
what this file records.

## `tonic-web` 0.14.6 — MIT

**One line changed**, in `src/call.rs`. Upstream drops gRPC-Web trailers when
they arrive in the same buffer as the final data frame, so any response over
roughly 4 KiB fails with `missing grpc-status trailer` on a response that in
fact arrived intact.

In the client decode path, `find_trailers` returns `Trailer(len)` when data and
trailers are buffered together. That arm stashes the trailers in `self.trailers`
and returns the data frame. The next poll sees an empty buffer, so
`find_trailers` returns `Done(0)` — and that arm was:

```rust
FindTrailers::Done(len) => Poll::Ready(match len {
    0 => None,                       // ends the body, dropping the trailers
    _ => Some(Ok(Frame::data(buf.split_to(len).freeze()))),
}),
```

`None` ends the body without ever emitting the stashed trailers. The `Trailer`
arm already performs this check; `Done` did not. The patch makes `Done(0)`
take and emit them.

**How it was diagnosed.** `heyl doctor` failed on the META vault every run and
on other vaults intermittently. Fetching the same request by hand with `curl`
showed the server's response was complete over HTTP/2 — a 4395-byte data frame
plus an intact 16-byte trailer frame — which ruled out the backend and the
proxy. Response size is what decides whether the two land in one buffer, which
is why the largest vault failed every time and smaller ones only sometimes.
With the patch, `doctor` goes from `36 passed, 1 failed` to `37 passed,
0 failed`, repeatably.

### This is not a permanent answer

`[patch.crates-io]` applies to **our** builds only. It is not carried to anyone
who installs `heyl` from crates.io, where the dependency resolves to unpatched
`tonic-web` and the bug returns. DESIGN.md §4 plans crates.io publication at
M8, so before then one of:

* upstream releases the fix (it should be sent to `hyperium/tonic`), or
* `heyl-grpc` stops relying on the upstream decode path — for unary calls it
  could buffer the response body and re-frame it itself.

Until one of those lands, a release built from this repository is correct and a
`cargo install heyl` is not.
