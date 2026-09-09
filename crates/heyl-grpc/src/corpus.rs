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
//! One file per call, ordered, under a directory per situation:
//!
//! ```text
//! tests/fixtures/api/base/
//!   01-create-challenge.json
//!   02-create-tokens.json
//!   03-sync.json
//!   …
//! ```
//!
//! `diff -r base/ expired-unlock/` is then the whole difference between a
//! situation and reality, which is the review property that made full records
//! preferable to a base plus patches.
//!
//! **No token is ever written.** The bearer token is metadata on a
//! [`crate::Request`] like any other, so a recorder sees it; it is dropped here
//! rather than redacted later, because a redaction step that runs after the
//! fact is a step that can be forgotten.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use heyl_ports::ApiError;
use prost::Message;

use crate::{HeyloginApi, json};

/// What a replay needs to know that is not in the records.
///
/// A corpus that requires the reader to guess which random values produced it
/// is coupled to whatever generated it. This states them instead.
///
/// Lives in `_meta.json`; the leading underscore is what keeps it out of the
/// record listing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Meta {
    /// The synthetic recovery code the corpus was re-keyed onto.
    pub code: String,
    /// The 32-byte seed the session encryption key is derived from, base64.
    ///
    /// A recovery draws this from `RandomSource` and derives the session key
    /// with it, so the unlock blob is sealed to whatever the replay's random
    /// source yields first. Stating it lets a test supply exactly that.
    pub session_seed: String,
}

impl Meta {
    /// Read `_meta.json` from a corpus directory.
    ///
    /// # Errors
    /// [`CorpusError`] if it is missing or does not parse.
    pub fn load(dir: &Path) -> Result<Self, CorpusError> {
        let path = dir.join("_meta.json");
        let raw = fs::read_to_string(&path).map_err(|e| CorpusError::Io {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
        serde_json::from_str(&raw).map_err(|e| CorpusError::Malformed {
            path: path.display().to_string(),
            reason: e.to_string(),
        })
    }

    /// Write `_meta.json` into a corpus directory.
    ///
    /// # Errors
    /// [`CorpusError::Io`] if it cannot be written.
    pub fn write(&self, dir: &Path) -> Result<(), CorpusError> {
        let path = dir.join("_meta.json");
        let body = serde_json::to_string_pretty(self).map_err(|e| CorpusError::Malformed {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
        fs::create_dir_all(dir).map_err(|e| CorpusError::Io {
            path: dir.display().to_string(),
            reason: e.to_string(),
        })?;
        fs::write(&path, body + "\n").map_err(|e| CorpusError::Io {
            path: path.display().to_string(),
            reason: e.to_string(),
        })
    }
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

/// Load every record in a directory, in filename order.
///
/// Filenames are `NN-<method>.json`, so lexical order is call order — which is
/// what disambiguates the five `ListCommits` calls a session makes, none of
/// which the wire fixture recorded a request for.
///
/// # Errors
/// [`CorpusError`] if the directory cannot be read or a file does not parse.
pub fn load(dir: &Path) -> Result<Vec<Record>, CorpusError> {
    let io = |path: &Path, e: &std::io::Error| CorpusError::Io {
        path: path.display().to_string(),
        reason: e.to_string(),
    };

    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| io(dir, &e))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        // `_meta.json` states the code and session seed; it is not a call.
        .filter(|p| {
            !p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with('_'))
        })
        .collect();
    paths.sort();

    paths
        .iter()
        .map(|path| {
            let raw = fs::read_to_string(path).map_err(|e| io(path, &e))?;
            serde_json::from_str(&raw).map_err(|e| CorpusError::Malformed {
                path: path.display().to_string(),
                reason: e.to_string(),
            })
        })
        .collect()
}

/// Write a record as `NN-<method>.json`.
///
/// # Errors
/// [`CorpusError::Io`] if the file cannot be written.
pub fn write(dir: &Path, index: usize, record: &Record) -> Result<PathBuf, CorpusError> {
    let io = |path: &Path, e: &std::io::Error| CorpusError::Io {
        path: path.display().to_string(),
        reason: e.to_string(),
    };
    fs::create_dir_all(dir).map_err(|e| io(dir, &e))?;

    let slug = record
        .method
        .rsplit('/')
        .next()
        .unwrap_or(&record.method)
        .chars()
        .flat_map(|c| {
            if c.is_uppercase() {
                vec!['-', c.to_ascii_lowercase()]
            } else {
                vec![c]
            }
        })
        .collect::<String>();
    let path = dir.join(format!("{:02}{slug}.json", index + 1));

    let body = serde_json::to_string_pretty(record).map_err(|e| CorpusError::Malformed {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;
    fs::write(&path, body + "\n").map_err(|e| io(&path, &e))?;
    Ok(path)
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
    /// Replay a directory of records.
    ///
    /// # Errors
    /// [`CorpusError`] if the directory cannot be read or a file does not parse.
    pub fn load(dir: &Path) -> Result<Self, CorpusError> {
        Ok(Self::new(load(dir)?))
    }

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
