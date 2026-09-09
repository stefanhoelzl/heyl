# Prose gate — derivation snapshots

The eight files under `crates/heyl-domain/tests/snapshots/` are the **only**
regression detector the key hierarchy has. Nothing has confirmed them against
heylogin, and nothing can until M2: `CreateTokens` accepting our signature
confirms the login limb, and M2's single vault decrypt confirms the profile and
vault limbs (DESIGN.md §6).

Until then a moved derivation key means one of two things — an intentional fix,
or a silent regression — and `gates.sh` cannot tell them apart. It can only
report that a `.snap` changed. That judgment is what this file asks for.

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
