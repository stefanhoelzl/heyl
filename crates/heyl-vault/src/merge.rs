//! Folding a vault's commits into its current state.
//!
//! # Commits are deltas, not snapshots
//!
//! DESIGN.md §4 and `HEYLOGIN_SPEC.md` §7 read as though a commit blob were the
//! full serialized state. It is not: each commit carries **only the elements it
//! touched**, and the current state is every commit folded in order. Measured
//! on a real account — a login vault's fourth commit held one login, not the
//! four that existed — and confirmed against heylogin's own `heymerge` package
//! (`mergeVaults` → `mergeListsByTimestamp` → `chooseByUpdateTime`). A reader
//! that took `commits.last()` would see one edit and call it the whole vault.
//!
//! # The merge, exactly
//!
//! A vault document's `content` is a map of **list name → heymerge list**, and
//! a heymerge list is a map of **element id → element**, every element carrying
//! an `updateTime`. `mergeVaults` unions the list names; for a name in both
//! commits it merges the two lists element by element, unioning ids and, for an
//! id in both, keeping the element with the newer `updateTime`. Neither level
//! throws data away: a name or an id present in only one commit is carried
//! through, and tombstones (`isDeleted`) stay in the list — filtering them is
//! the reader's job, not the merge's.
//!
//! # The one place we diverge, and why it does not matter
//!
//! heylogin breaks an exact `updateTime` tie with `hash(left) < hash(right)`
//! over an `object-hash` of the two elements. We break it in favour of the
//! **later commit**, because these are folded in server-creation order and that
//! is the order the backend itself assigns. An exact tie requires the *same*
//! element id written at the *same* millisecond by two clients whose commits
//! then landed adjacently — `guardMinUpdateTime` makes a single client's
//! successive edits strictly increasing, so it cannot arise from one writer —
//! and both values are equally valid current state. Reproducing `object-hash`
//! byte-for-byte to pick between two live-equal values is cost without a reader
//! that could tell the difference.

use serde_json::{Map, Value};

use crate::{Document, VaultError};

/// The key every heymerge element carries, and the merge orders on.
const UPDATE_TIME: &str = "updateTime";

/// Fold a vault's commits, oldest first, into its current state.
///
/// The commits must be given in the order the backend created them —
/// `VaultCommits.commits` already is. Framing, `type` and `version` are taken
/// from the newest commit; every commit of one vault agrees on them, and the
/// newest is the authority if a migration ever moved them.
///
/// # Errors
/// [`VaultError::Empty`] if `commits` is empty — a vault with no commits has no
/// state to fold, and the caller decides whether that is a failure or an empty
/// document.
pub fn fold(commits: &[Document]) -> Result<Document, VaultError> {
    let newest = commits.last().ok_or(VaultError::Empty)?;

    // Fold oldest→newest so the newest commit's elements win a tie, matching
    // the order the backend created them.
    let mut content = Map::new();
    for commit in commits {
        merge_content(&mut content, &commit.content);
    }

    Ok(Document {
        format: newest.format,
        document_type: newest.document_type.clone(),
        version: newest.version,
        content,
    })
}

/// Merge one commit's content into the accumulator.
///
/// A list name absent from the accumulator is taken whole; one present in both
/// is merged element by element.
fn merge_content(acc: &mut Map<String, Value>, next: &Map<String, Value>) {
    for (name, list) in next {
        match acc.get_mut(name) {
            Some(existing) => merge_list(existing, list),
            None => {
                acc.insert(name.clone(), list.clone());
            }
        }
    }
}

/// Merge one heymerge list into another, in place.
///
/// Both should be objects (`id → element`). If either is not — a shape no
/// heylogin vault produces — the later commit's value replaces the earlier, the
/// same last-write-wins the element merge applies one level down.
fn merge_list(acc: &mut Value, next: &Value) {
    let (Some(acc_map), Some(next_map)) = (acc.as_object_mut(), next.as_object()) else {
        *acc = next.clone();
        return;
    };

    for (id, element) in next_map {
        match acc_map.get(id) {
            Some(current) if update_time(current) > update_time(element) => {}
            _ => {
                acc_map.insert(id.clone(), element.clone());
            }
        }
    }
}

/// An element's `updateTime`, or the empty string when it has none.
///
/// A missing `updateTime` sorts oldest, so a well-formed element with a real
/// timestamp always wins against one without. ISO-8601 UTC timestamps compare
/// correctly as plain strings, which is the comparison heymerge itself uses.
fn update_time(element: &Value) -> &str {
    element
        .get(UPDATE_TIME)
        .and_then(Value::as_str)
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Format;

    fn doc(content: &Value) -> Document {
        Document {
            format: Format::Snappy,
            document_type: "login".to_owned(),
            version: crate::DESCRIPTOR_VERSION_HEYMERGE,
            content: content.as_object().expect("object").clone(),
        }
    }

    fn logins(folded: &Document) -> &Map<String, Value> {
        folded.content["logins"].as_object().expect("logins object")
    }

    #[test]
    fn a_single_commit_folds_to_itself() {
        let only = doc(&serde_json::json!({
            "logins": { "a": { "title": "one", "updateTime": "2026-01-01T00:00:00.000Z" } }
        }));
        let folded = fold(std::slice::from_ref(&only)).expect("folds");
        assert_eq!(folded.content, only.content);
    }

    #[test]
    fn no_commits_is_empty_not_a_panic() {
        assert_eq!(fold(&[]).unwrap_err(), VaultError::Empty);
    }

    #[test]
    fn later_commits_add_elements_without_dropping_earlier_ones() {
        // The bug this whole module exists for: the last commit holds only `b`,
        // and a reader that took it alone would lose `a`.
        let commits = [
            doc(&serde_json::json!({
                "logins": { "a": { "title": "one", "updateTime": "2026-01-01T00:00:00.000Z" } }
            })),
            doc(&serde_json::json!({
                "logins": { "b": { "title": "two", "updateTime": "2026-01-02T00:00:00.000Z" } }
            })),
        ];
        let folded = fold(&commits).expect("folds");
        assert_eq!(logins(&folded).len(), 2);
        assert_eq!(logins(&folded)["a"]["title"], "one");
        assert_eq!(logins(&folded)["b"]["title"], "two");
    }

    #[test]
    fn the_newer_update_time_wins_regardless_of_commit_order() {
        // `a` is edited in commit 0 but a *newer* updateTime for it sits in an
        // earlier position of commit 1; updateTime, not position, decides.
        let commits = [
            doc(&serde_json::json!({
                "logins": { "a": { "title": "new", "updateTime": "2026-02-01T00:00:00.000Z" } }
            })),
            doc(&serde_json::json!({
                "logins": { "a": { "title": "old", "updateTime": "2026-01-01T00:00:00.000Z" } }
            })),
        ];
        let folded = fold(&commits).expect("folds");
        assert_eq!(logins(&folded)["a"]["title"], "new");
    }

    #[test]
    fn an_equal_update_time_is_broken_towards_the_later_commit() {
        let stamp = "2026-01-01T00:00:00.000Z";
        let commits = [
            doc(
                &serde_json::json!({ "logins": { "a": { "title": "first", "updateTime": stamp } } }),
            ),
            doc(
                &serde_json::json!({ "logins": { "a": { "title": "second", "updateTime": stamp } } }),
            ),
        ];
        let folded = fold(&commits).expect("folds");
        assert_eq!(logins(&folded)["a"]["title"], "second");
    }

    #[test]
    fn a_tombstone_survives_the_fold() {
        // Deletion is a later commit that stamps the element `isDeleted`; the
        // fold must keep it so the reader can rank or filter it (get, §get).
        let commits = [
            doc(&serde_json::json!({
                "logins": { "a": { "title": "one", "updateTime": "2026-01-01T00:00:00.000Z" } }
            })),
            doc(&serde_json::json!({
                "logins": { "a": { "title": "one", "isDeleted": true, "isArchived": true,
                                   "updateTime": "2026-01-02T00:00:00.000Z" } }
            })),
        ];
        let folded = fold(&commits).expect("folds");
        assert_eq!(logins(&folded)["a"]["isDeleted"], true);
    }

    #[test]
    fn distinct_list_names_are_all_carried() {
        // META has `sessions` and `accountSettings`; a commit touching one must
        // not erase the other.
        let commits = [
            doc(&serde_json::json!({
                "sessions": { "s": { "updateTime": "2026-01-01T00:00:00.000Z" } }
            })),
            doc(&serde_json::json!({
                "accountSettings": { "k": { "updateTime": "2026-01-02T00:00:00.000Z" } }
            })),
        ];
        let folded = fold(&commits).expect("folds");
        assert!(folded.content.contains_key("sessions"));
        assert!(folded.content.contains_key("accountSettings"));
    }

    #[test]
    fn an_element_missing_an_update_time_loses_to_one_that_has_it() {
        let commits = [
            doc(
                &serde_json::json!({ "logins": { "a": { "title": "timestamped",
                                                       "updateTime": "2026-01-01T00:00:00.000Z" } } }),
            ),
            doc(&serde_json::json!({ "logins": { "a": { "title": "no timestamp" } } })),
        ];
        // Later commit, but its element has no updateTime (empty string), so the
        // timestamped earlier one wins.
        let folded = fold(&commits).expect("folds");
        assert_eq!(logins(&folded)["a"]["title"], "timestamped");
    }
}
