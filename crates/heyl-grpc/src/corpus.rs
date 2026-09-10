//! Recording and replaying at the API boundary.
//!
//! The wire fixture this replaces could only ever be played through the
//! transport, so everything above it — the mapping, the use cases — was tested
//! against a hand-built account instead. Recording one layer up, in prost
//! messages, means `heyl-app` can run against **real heylogin data through the
//! real mapping**, which is what the hand-built account could never be.
//!
//! Records are *pre-mapping*: they hold what the backend sent, not what we
//! understood it to mean. So a mapping change does not invalidate the corpus,
//! and a record can be re-read as understanding improves (DESIGN.md §6).
//!
//! # What is recorded
//!
//! One file per scenario, structured by step:
//!
//! ```text
//! crates/heyl-cli/tests/scenarios/recovery-then-doctor.json
//!   meta:  the synthetic code and the seed a replay must draw first
//!   steps: [ { argv, stdin, exit, calls: [ … ], stdout } , … ]
//! ```
//!
//! Half of it is hand-written and half generated: the `argv`/`stdin`/`exit` of
//! each step say what to run, and `record` fills in the rest. Grouping calls
//! under the step that made them is what lets a replay reject a call that
//! arrives during the wrong invocation.
//!
//! **No token is ever written.** The bearer token is metadata on a
//! [`crate::Request`] like any other, so a recorder sees it; it is dropped here
//! rather than redacted later, because a redaction step that runs after the
//! fact is a step that can be forgotten.

use std::{fs, path::Path, sync::Mutex};

use heyl_ports::ApiError;
use prost::Message;

use crate::{HeyloginApi, json};

/// A whole scenario: a list of `heyl` invocations and the traffic they made.
///
/// One file, because nothing derives from anything any more. The layout that
/// preceded this — `_meta.json`, one numbered file per call, and expectations
/// beside them — existed so `diff -r base <situation>` showed how a situation
/// differed from reality. Every scenario is now recorded independently, so
/// there is no sibling to diff against and the numbering carried meaning
/// nothing else could see.
///
/// **Structured by step**, so a replay knows which invocation a call belongs
/// to. An out-of-step call then fails where it happens rather than quietly
/// matching a record meant for a later command.
///
/// Half the file is hand-written and half is generated: `argv`, `stdin`,
/// `exit` and `redact` state what to run, and `record` fills in `meta`,
/// `calls` and `stdout`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Scenario {
    /// What a replay needs that is not in the calls.
    pub meta: Meta,
    /// The invocations, in order.
    pub steps: Vec<Step>,
}

impl Scenario {
    /// Read a scenario file.
    ///
    /// # Errors
    /// [`CorpusError`] if it cannot be read or does not parse.
    pub fn load(path: &Path) -> Result<Self, CorpusError> {
        let raw = fs::read_to_string(path).map_err(|e| CorpusError::Io {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
        serde_json::from_str(&raw).map_err(|e| CorpusError::Malformed {
            path: path.display().to_string(),
            reason: e.to_string(),
        })
    }

    /// Write a scenario file, pretty-printed so `git diff` is readable.
    ///
    /// # Errors
    /// [`CorpusError::Io`] if it cannot be written.
    pub fn write(&self, path: &Path) -> Result<(), CorpusError> {
        let io = |e: &std::io::Error| CorpusError::Io {
            path: path.display().to_string(),
            reason: e.to_string(),
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| io(&e))?;
        }
        let body = serde_json::to_string_pretty(self).map_err(|e| CorpusError::Malformed {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
        fs::write(path, body + "\n").map_err(|e| io(&e))
    }

    /// The seed a replay must draw first, decoded.
    ///
    /// # Errors
    /// [`CorpusError::Malformed`] if it is not 32 base64 bytes.
    pub fn session_seed(&self) -> Result<[u8; 32], CorpusError> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(&self.meta.session_seed)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| CorpusError::Malformed {
                path: "meta.session_seed".to_owned(),
                reason: "not 32 base64-encoded bytes".to_owned(),
            })
    }
}

/// One `heyl` invocation, and what it did.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Step {
    /// The arguments after `heyl`. Hand-written.
    pub argv: Vec<String>,

    /// What to write to the process's stdin. Hand-written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,

    /// The exit code it must return. Hand-written; defaults to success.
    #[serde(default)]
    pub exit: i32,

    /// JSON pointers into `stdout` to blank before comparing. Hand-written.
    ///
    /// The rule is to prefer server-provided values, which are stable because
    /// they come from the recording; this is the escape hatch for the ones
    /// that are genuinely local.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redact: Vec<String>,

    /// The calls this step made, in order. Recorded.
    #[serde(default)]
    pub calls: Vec<Record>,

    /// The JSON this step must print. Written from the replay, not the live
    /// run: `rekey` moves identifiers, and live output would carry the real
    /// account's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout: Option<serde_json::Value>,
}

/// What a replay needs to know that is not in the calls.
///
/// A scenario that requires the reader to guess which random values produced
/// it is coupled to whatever generated it. This states them instead.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Meta {
    /// The synthetic recovery code the scenario was re-keyed onto.
    pub code: String,

    /// The 32-byte seed the session encryption key is derived from, base64.
    ///
    /// A recovery draws this from `RandomSource` and derives the session key
    /// with it, so the unlock blob is sealed to whatever the replay's random
    /// source yields first. Stating it lets a test supply exactly that.
    pub session_seed: String,

    /// Anything a reader needs to know that the file cannot show.
    ///
    /// JSON has no comments, and one scenario is not a recording at all:
    /// `token_refresh_needed` is set by the backend as a token ages, and
    /// `CreateTokensRequest` has no lifetime field, so nothing can ask for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// One recorded call.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Record {
    /// The gRPC method path, e.g. `/domain.SyncService/Sync`.
    pub method: String,

    /// The request message, as protobuf-JSON.
    ///
    /// `None` for a record migrated from the wire fixture: `rekey` dropped
    /// request bodies there because they carried a signature and a sealed
    /// seed, and what was never recorded cannot be recovered. A record with no
    /// request matches on method and order alone.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<serde_json::Value>,

    /// The response messages, as protobuf-JSON. One for a unary call.
    pub responses: Vec<serde_json::Value>,

    /// The backend's refusal, when that is what happened.
    ///
    /// A situation like "the backend refuses this session type" is a recorded
    /// *error*, and a corpus that could only hold successes would push those
    /// tests back onto a hand-built fake.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RecordedError>,
}

/// A backend refusal, kept in the corpus.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecordedError {
    /// The gRPC status code.
    pub status: i32,
    /// heylogin's `DomainError.code`, when it sent one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_code: Option<i32>,
    /// `grpc-message`, or the domain error's user-facing title.
    pub message: String,
}

impl RecordedError {
    /// The error a replay should raise.
    fn to_api_error(&self) -> ApiError {
        match self.status {
            16 => ApiError::Unauthenticated {
                domain_code: self.domain_code,
            },
            7 => ApiError::PermissionDenied {
                domain_code: self.domain_code,
            },
            3 => ApiError::BadRequest {
                domain_code: self.domain_code,
                message: self.message.clone(),
            },
            status => ApiError::Backend {
                status,
                domain_code: self.domain_code,
                message: self.message.clone(),
                detail: String::new(),
            },
        }
    }
}

/// Something the corpus could not do.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CorpusError {
    /// The directory could not be read or written.
    #[error("{path}: {reason}")]
    Io {
        /// Which path.
        path: String,
        /// What the OS said.
        reason: String,
    },

    /// A record file did not parse.
    #[error("{path} is not a record: {reason}")]
    Malformed {
        /// Which file.
        path: String,
        /// What went wrong.
        reason: String,
    },

    /// A message could not be transcoded.
    #[error(transparent)]
    Json(#[from] json::JsonError),
}

impl From<CorpusError> for ApiError {
    fn from(e: CorpusError) -> Self {
        Self::Transport {
            reason: e.to_string(),
        }
    }
}

/// Wraps any API and keeps what crossed it.
///
/// The generated implementation forwards all 123 methods and hands the unary
/// ones here.
pub struct RecordingApi<A> {
    pub(crate) inner: A,
    records: Mutex<Vec<Record>>,
}

impl<A: HeyloginApi> RecordingApi<A> {
    /// Wrap an API.
    pub fn new(inner: A) -> Self {
        Self {
            inner,
            records: Mutex::new(Vec::new()),
        }
    }

    /// Everything recorded so far, in call order.
    ///
    /// # Panics
    /// Never in practice: only a panic while recording could poison the lock.
    pub fn records(&self) -> Vec<Record> {
        self.records.lock().expect("not poisoned").clone()
    }

    /// Keep one exchange. Called by the generated forwarders.
    ///
    /// # Errors
    /// [`ApiError`] if a message cannot be rendered, which means our schema and
    /// the bytes disagree.
    ///
    /// # Panics
    /// Never in practice: only a panic while recording could poison the lock.
    pub fn keep<Req: Message, Res: Message>(
        &self,
        method: &str,
        request_type: &str,
        response_type: &str,
        request: &Req,
        outcome: &Result<Res, ApiError>,
    ) -> Result<(), ApiError> {
        let pool = json::pool().map_err(CorpusError::from)?;
        let render = |ty: &str, m: &dyn ErasedMessage| -> Result<serde_json::Value, ApiError> {
            let rendered = m.to_json(pool, ty)?;
            serde_json::from_str(&rendered).map_err(|e| ApiError::MalformedResponse {
                what: format!("{ty} rendered unreadable JSON: {e}"),
            })
        };

        let record = Record {
            method: method.to_owned(),
            request: Some(render(request_type, &Erased(request))?),
            responses: match outcome {
                Ok(response) => vec![render(response_type, &Erased(response))?],
                Err(_) => Vec::new(),
            },
            error: match outcome {
                Ok(_) => None,
                Err(e) => Some(recorded_error(e)),
            },
        };
        self.records.lock().expect("not poisoned").push(record);
        Ok(())
    }
}

/// Answers from a corpus.
pub struct RecordedApi {
    records: Vec<Record>,
    consumed: Mutex<Vec<bool>>,
}

impl RecordedApi {
    /// Replay records already in hand.
    #[must_use]
    pub fn new(records: Vec<Record>) -> Self {
        let consumed = Mutex::new(vec![false; records.len()]);
        Self { records, consumed }
    }

    /// Which records were never used.
    ///
    /// A situation file nothing reaches is either a test that stopped early or
    /// a record that no longer belongs, and both are worth failing on.
    ///
    /// # Panics
    /// Never in practice: only a panic mid-replay could poison the lock.
    #[must_use]
    pub fn unused(&self) -> Vec<&str> {
        let consumed = self.consumed.lock().expect("not poisoned");
        self.records
            .iter()
            .zip(consumed.iter())
            .filter_map(|(record, used)| (!used).then_some(record.method.as_str()))
            .collect()
    }

    /// Find the record answering this call.
    ///
    /// **Exact request match first, then call order.** Both are needed: a
    /// session makes five `ListCommits` calls that differ only by `vaultId`,
    /// and the records migrated from the wire fixture have no request at all,
    /// because `rekey` dropped request bodies that carried a signature and a
    /// sealed seed.
    ///
    /// # Panics
    /// Never in practice: only a panic mid-replay could poison the lock.
    fn take(&self, method: &str, request: Option<&serde_json::Value>) -> Option<&Record> {
        let mut consumed = self.consumed.lock().expect("not poisoned");

        let candidates = || {
            self.records
                .iter()
                .enumerate()
                .filter(|(i, r)| !consumed[*i] && r.method == method)
        };

        let chosen = request
            .and_then(|wanted| {
                candidates().find(|(_, r)| r.request.as_ref().is_some_and(|got| got == wanted))
            })
            .or_else(|| candidates().next())?;

        consumed[chosen.0] = true;
        Some(chosen.1)
    }

    /// Answer one unary call from the corpus. Called by the generated stub.
    ///
    /// # Errors
    /// [`ApiError::Unimplemented`] if the corpus has no record left for this
    /// method, or the recorded error if that is what was recorded.
    pub fn replay<Req: Message, Res: Message + Default>(
        &self,
        method: &'static str,
        request_type: &str,
        response_type: &str,
        request: &Req,
    ) -> Result<Res, ApiError> {
        let pool = json::pool().map_err(CorpusError::from)?;
        let rendered = Erased(request).to_json(pool, request_type)?;
        let wanted: Option<serde_json::Value> = serde_json::from_str(&rendered).ok();

        let record = self
            .take(method, wanted.as_ref())
            .ok_or(ApiError::Unimplemented { method })?;

        if let Some(error) = &record.error {
            return Err(error.to_api_error());
        }
        let response = record
            .responses
            .first()
            .ok_or_else(|| ApiError::MalformedResponse {
                what: format!("{method} record has no response"),
            })?;

        let document =
            serde_json::to_string(response).map_err(|e| ApiError::MalformedResponse {
                what: format!("{method} record is unreadable: {e}"),
            })?;
        Ok(json::from_json(pool, response_type, &document).map_err(CorpusError::from)?)
    }

    /// Answer the one server-streaming call from the corpus.
    ///
    /// # Errors
    /// [`ApiError::Unimplemented`] if the corpus has no record for it.
    pub fn replay_stream<Req: Message, Res: Message + Default + Send + 'static>(
        &self,
        method: &'static str,
        response_type: &str,
        _request: &Req,
    ) -> Result<crate::MessageStream<Res>, ApiError> {
        let pool = json::pool().map_err(CorpusError::from)?;
        let record = self
            .take(method, None)
            .ok_or(ApiError::Unimplemented { method })?;

        let messages: Vec<Result<Res, ApiError>> = record
            .responses
            .iter()
            .map(|value| {
                let document = serde_json::to_string(value).unwrap_or_default();
                json::from_json(pool, response_type, &document)
                    .map_err(|e| ApiError::from(CorpusError::from(e)))
            })
            .collect();

        Ok(Box::pin(tokio_stream::iter(messages)))
    }
}

/// How an error was reported, for the corpus.
fn recorded_error(e: &ApiError) -> RecordedError {
    match e {
        ApiError::Unauthenticated { domain_code } => RecordedError {
            status: 16,
            domain_code: *domain_code,
            message: e.to_string(),
        },
        ApiError::PermissionDenied { domain_code } => RecordedError {
            status: 7,
            domain_code: *domain_code,
            message: e.to_string(),
        },
        ApiError::BadRequest {
            domain_code,
            message,
        } => RecordedError {
            status: 3,
            domain_code: *domain_code,
            message: message.clone(),
        },
        ApiError::Backend {
            status,
            domain_code,
            message,
            ..
        } => RecordedError {
            status: *status,
            domain_code: *domain_code,
            message: message.clone(),
        },
        other => RecordedError {
            status: 2,
            domain_code: None,
            message: other.to_string(),
        },
    }
}

/// Render a message without naming its type.
///
/// `keep` and `replay` are generic over the message, but the JSON layer needs
/// a concrete `encode_to_vec`; this is the one-line bridge.
trait ErasedMessage {
    fn to_json(&self, pool: &prost_reflect::DescriptorPool, ty: &str) -> Result<String, ApiError>;
}

struct Erased<'a, M>(&'a M);

impl<M: Message> ErasedMessage for Erased<'_, M> {
    fn to_json(&self, pool: &prost_reflect::DescriptorPool, ty: &str) -> Result<String, ApiError> {
        Ok(json::to_json(pool, ty, self.0).map_err(CorpusError::from)?)
    }
}

// The generated forwarders and lookups: 123 methods each. See `build.rs`.
#[allow(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    unreachable_pub,
    rustdoc::all
)]
mod generated {
    use heyl_ports::ApiError;

    use crate::HeyloginApi;

    include!(concat!(env!("OUT_DIR"), "/corpus.rs"));
}
