# Prose gate — derivation snapshots

The eight files under `crates/heyl-domain/tests/snapshots/` are the **only**
regression detector the key hierarchy has.

M2 added an offline suite that runs the whole path — typed recovery code →
Argon2id → seed → every link → a decrypted commit — and it does **not** replace
this gate. That suite builds its fixtures with the same context salts the code
derives with, so it is self-consistent by construction: change a context and
both sides move together and the suite stays green. What actually detects a
wrong context is `heyl doctor`, which compares each derived key against the
public half heylogin publishes — and that is a live run against a real account,
from a `--features dev` build, not something CI can do.

So until such a run is recorded in the repo, a moved derivation key still means
one of two things — an intentional fix, or a silent regression — and `gates.sh`
cannot tell them apart. It can only report that a `.snap` changed. That
judgment is what this file asks for.

## Check

Does this diff modify any file under `crates/heyl-domain/tests/snapshots/`?

**No** → pass, nothing to evaluate.

**Yes** → for each changed snapshot, establish both:

1. **What moved it.** The diff must also change something that plausibly
   changes that derivation — a context constant, the KDF, a key type, the
   fixed test inputs in `hierarchy_snapshots.rs`. A snapshot that moved with no
   such change in the diff is a regression, not a new baseline.
2. **Why.** The reason must be stated somewhere a reviewer will read it: the PR
   body, or the commit message.

## Pass condition

Every changed snapshot has both a cause visible in the diff and a stated
reason.

## Abort

Any changed snapshot that has neither. List each one and what is missing.

Abort too when a snapshot changed and the only explanation offered is that
`cargo insta review` accepted it — that describes the mechanism, not the cause.

Abort when a snapshot changed and the justification is that the offline suite
in `crates/heyl-app/tests/` still passes. It would: see above.
