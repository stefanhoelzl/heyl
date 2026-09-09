//! Situations, materialised from the base corpus.
//!
//! A situation is a *whole* corpus, not a patch applied at load time: what a
//! test sees is what is on disk. But hand-authoring one is not realistic —
//! every record has to stay crypto-consistent, or the first decryption in the
//! test fails for the wrong reason. So each situation is the base copied and
//! edited, and this is the edit.
//!
//! The review property that full records give up — seeing at a glance how a
//! situation differs from reality — comes back as `diff -r`:
//!
//! ```sh
//! diff -r tests/fixtures/api/base tests/fixtures/api/expired-unlock
//! ```
//!
//! Which is why the files are numbered and the layout is one call per file.

use std::path::Path;

use heyl_grpc::corpus::RecordedError;

/// One edit to a record.
pub enum Edit {
    /// Set a JSON pointer inside a response to a value.
    Set {
        /// Which record, by filename prefix (`03`, or `sync`).
        target: String,
        /// An RFC 6901 pointer into the response, e.g. `/syncUpdate/sessionUnlock`.
        pointer: String,
        /// The JSON to put there. `null` removes the key.
        value: serde_json::Value,
    },
    /// Replace a record's response with a backend refusal.
    Fail {
        /// Which record.
        target: String,
        /// The gRPC status code.
        status: i32,
        /// heylogin's `DomainError.code`.
        domain_code: Option<i32>,
        /// The message.
        message: String,
    },
    /// Keep only the first `n` records.
    Truncate(usize),
}

/// Parse `NN:/pointer=<json>`.
///
/// # Errors
/// A message naming what could not be parsed.
pub fn parse_set(raw: &str) -> Result<Edit, String> {
    let (target, rest) = raw
        .split_once(':')
        .ok_or_else(|| format!("--set wants <record>:<pointer>=<json>, got {raw:?}"))?;
    let (pointer, value) = rest
        .split_once('=')
        .ok_or_else(|| format!("--set wants <record>:<pointer>=<json>, got {raw:?}"))?;
    Ok(Edit::Set {
        target: target.to_owned(),
        pointer: pointer.to_owned(),
        value: serde_json::from_str(value).map_err(|e| format!("{value:?} is not JSON: {e}"))?,
    })
}

/// Parse `NN:status[:domain_code[:message]]`.
///
/// # Errors
/// A message naming what could not be parsed.
pub fn parse_fail(raw: &str) -> Result<Edit, String> {
    let mut parts = raw.split(':');
    let target = parts
        .next()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| format!("--fail wants <record>:<status>, got {raw:?}"))?;
    let status = parts
        .next()
        .ok_or_else(|| format!("--fail wants <record>:<status>, got {raw:?}"))?
        .parse()
        .map_err(|e| format!("status is not a number: {e}"))?;
    let domain_code = parts.next().and_then(|c| c.parse().ok());
    let message = parts.next().unwrap_or("recorded refusal").to_owned();
    Ok(Edit::Fail {
        target: target.to_owned(),
        status,
        domain_code,
        message,
    })
}

/// Copy `base` to `out`, applying `edits`.
///
/// # Errors
/// A message describing what could not be read, edited or written.
pub fn run(base: &Path, out: &Path, edits: &[Edit]) -> Result<(), String> {
    let mut records = heyl_grpc::corpus::load(base).map_err(|e| e.to_string())?;
    let names = filenames(base)?;

    for edit in edits {
        match edit {
            Edit::Truncate(n) => records.truncate(*n),
            Edit::Set {
                target,
                pointer,
                value,
            } => {
                let at = find(&names, target)?;
                let response = records[at]
                    .responses
                    .first_mut()
                    .ok_or_else(|| format!("{} has no response to edit", names[at]))?;
                set(response, pointer, value.clone())?;
            }
            Edit::Fail {
                target,
                status,
                domain_code,
                message,
            } => {
                let at = find(&names, target)?;
                records[at].responses.clear();
                records[at].error = Some(RecordedError {
                    status: *status,
                    domain_code: *domain_code,
                    message: message.clone(),
                });
            }
        }
    }

    if out.exists() {
        std::fs::remove_dir_all(out).map_err(|e| format!("cannot clear {}: {e}", out.display()))?;
    }
    for (index, record) in records.iter().enumerate() {
        let path = heyl_grpc::corpus::write(out, index, record).map_err(|e| e.to_string())?;
        println!("  {}", path.display());
    }

    // A situation is a whole corpus, so it carries its own meta.
    heyl_grpc::corpus::Meta::load(base)
        .and_then(|meta| meta.write(out))
        .map_err(|e| e.to_string())
}

/// The record filenames, in the order `load` returns them.
fn filenames(dir: &Path) -> Result<Vec<String>, String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|e| e == "json"))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        // `_meta.json` states the code and session seed; it is not a call.
        .filter(|name| !name.starts_with('_'))
        .collect();
    names.sort();
    Ok(names)
}

/// Which record a target names — a filename prefix, or any substring of it.
fn find(names: &[String], target: &str) -> Result<usize, String> {
    let matches: Vec<usize> = names
        .iter()
        .enumerate()
        .filter(|(_, name)| name.starts_with(target) || name.contains(target))
        .map(|(i, _)| i)
        .collect();
    match matches.as_slice() {
        [one] => Ok(*one),
        [] => Err(format!("no record matches {target:?}; have {names:?}")),
        many => Err(format!(
            "{target:?} matches {:?}",
            many.iter().map(|i| &names[*i]).collect::<Vec<_>>()
        )),
    }
}

/// Set a JSON pointer, creating intermediate objects; `null` removes the key.
fn set(
    root: &mut serde_json::Value,
    pointer: &str,
    value: serde_json::Value,
) -> Result<(), String> {
    let segments: Vec<&str> = pointer.trim_start_matches('/').split('/').collect();
    let (last, parents) = segments
        .split_last()
        .ok_or_else(|| "an empty pointer sets nothing".to_owned())?;

    let mut at = root;
    for segment in parents {
        at = at
            .get_mut(*segment)
            .ok_or_else(|| format!("{pointer} has no {segment}"))?;
    }
    let object = at
        .as_object_mut()
        .ok_or_else(|| format!("{pointer} does not name a field"))?;

    if value.is_null() {
        object.remove(*last);
    } else {
        object.insert((*last).to_owned(), value);
    }
    Ok(())
}
