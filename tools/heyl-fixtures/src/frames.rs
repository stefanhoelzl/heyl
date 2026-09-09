//! gRPC-Web body framing.
//!
//! A body is a sequence of frames, each a 1-byte flag, a 4-byte big-endian
//! length, then that many bytes. Flag `0x00` is a message; `0x80` is the
//! trailer block, which is where `grpc-status` lives on a gRPC-Web response.
//!
//! Re-keying works on decoded protobuf rather than on bytes, so this exists
//! only to get in and out of that representation.

/// One frame of a gRPC-Web body.
#[derive(Debug, Clone)]
pub struct Frame {
    /// `0x00` for a message, `0x80` for trailers.
    pub flag: u8,
    /// The frame's payload.
    pub payload: Vec<u8>,
}

/// Split a body into its frames.
///
/// A truncated tail is dropped rather than erroring: it cannot be re-framed
/// meaningfully, and a recording that ends mid-frame is a recording bug worth
/// seeing as a missing message rather than a parse failure.
#[must_use]
pub fn split(body: &[u8]) -> Vec<Frame> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 5 <= body.len() {
        let flag = body[at];
        let len =
            u32::from_be_bytes([body[at + 1], body[at + 2], body[at + 3], body[at + 4]]) as usize;
        at += 5;
        if at + len > body.len() {
            break;
        }
        out.push(Frame {
            flag,
            payload: body[at..at + len].to_vec(),
        });
        at += len;
    }
    out
}

/// Reassemble frames into a body.
#[must_use]
pub fn join(frames: &[Frame]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in frames {
        out.push(f.flag);
        out.extend_from_slice(&u32::try_from(f.payload.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&f.payload);
    }
    out
}

/// The first message frame's payload, if there is one.
#[must_use]
pub fn first_message(frames: &[Frame]) -> Option<&Vec<u8>> {
    frames.iter().find(|f| f.flag == 0).map(|f| &f.payload)
}

/// Replace the first message frame's payload, keeping trailers as they were.
pub fn replace_message(frames: &mut [Frame], payload: Vec<u8>) {
    if let Some(f) = frames.iter_mut().find(|f| f.flag == 0) {
        f.payload = payload;
    }
}
