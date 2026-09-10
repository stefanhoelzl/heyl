//! The end-to-end suite: every scenario, against the real binary.
//!
//! There is no list of scenarios here, and deliberately so. `build.rs` reads
//! `tests/scenarios/` and emits one `#[test]` per file, so dropping a recording
//! into that directory *is* the act of adding a scenario. A hand-maintained
//! list has one failure mode worth designing out: forget the second edit, and a
//! recording that cost a destructive live session never runs and never says so.
//!
//! Each test is named for its file, so `cargo test scenario::recovery_then_doctor`
//! runs one, and a failure names the scenario rather than a line number.

mod harness;

include!(concat!(env!("OUT_DIR"), "/scenarios.rs"));
