# Decision record — including what was deliberately **not** built

## D1 — Rules must be anchored to an official quote, or they are not rules

**Decision:** every rule carries `officialQuote` (verbatim) and `sourceUrl`
(an official `docs.minepi.com` page). The test suite asserts both, and asserts
that each high-severity rule is `documented` rather than `derived`.

**Reason:** a rule without a source is an opinion dressed as a finding. Anchoring
every rule to a quote makes each finding **checkable against Pi's own words**.

**Alternative rejected:** a set of "general security best practices". Those are
not Pi-specific, cannot be quoted from Pi's docs, and would make the tool claim
authority it does not have.

## D2 — Severity means rule-directness, never exploitability

**Decision:** severity is defined as *how directly the matched text contradicts
the recorded official rule*. It is explicitly **not** a risk score.

**Reason:** a static text match cannot know whether the pattern is reachable,
exploitable, or guarded elsewhere. Calling it a risk score would be a claim the
tool cannot support. See [`HTTP-AND-LIMITS.md`](HTTP-AND-LIMITS.md).

## D3 — `unknown` file kind, rather than guessing `client`

**Decision:** a file whose path cannot be classified is reported as `unknown`.
It is never defaulted to `client` (which would over-report the key rule) nor to
`server` (which would under-report).

**Reason:** guessing a classification would silently change which rules apply.
An `unknown` label tells the reader the scanner could not tell, which is honest.

## D4 — Commented-out code is not a finding

**Decision:** lines whose code portion is a comment are skipped.

**Reason:** reporting code a developer has already disabled produces false
findings and trains readers to ignore the tool. Comment stripping is a heuristic
and is labelled as one.

## D5 — Suppression is visible, never silent

**Decision:** the `// pi-scan-ignore` pragma is **per-line**. A suppressed match
is still produced and is reported as **SUPPRESSED**, with the reason. There is no
file-wide and no rule-wide disable.

**Reason:** a scanner that can be silenced wholesale, silently, cannot be trusted
to have run. Making suppression visible keeps the human decision on the record.

## D6 — The scanner never executes or fetches

**Decision:** the scanner reads text only. It contains no `fetch`, no
`child_process`, no `eval`, and no `new Function`. The test suite asserts the
absence of execution and network primitives in the engine modules.

**Reason:** scanning untrusted code must not itself be a risk. A scanner that
runs the code it scans is a different (and much larger) undertaking, and one this
tool deliberately avoids.

## D7 — No data-flow, dependency or CVE analysis was **declined**

**Decision:** the tool does **not** attempt taint tracking, interprocedural
analysis, dependency auditing, or CVE lookup. These are recorded as explicit
boundaries rather than left as omissions.

**Reason:** each of these either needs a network (CVE data), a real parser and
type system (interprocedural analysis), or a much larger scope than a rule set
anchored to documented mistakes. Keeping the scope to "match documented
anti-patterns in text" is what makes every finding auditable against a quote.

**If revisited:** it would be a different tool, with its own claim discipline,
not a quiet expansion of this one.

## D8 — The rule set is tied to the eight official numbered mistakes

**Decision:** the test suite maps official Mistake 1…8 to a specific rule
(PSC-009, 002, 003, 004, 005, 006, 007, 008 respectively) and asserts each rule
exists. PSC-001 is separately anchored to the Platform API page.

**Reason:** this ties the rule set to the source page as it stands, so that a
future change to that page is a discoverable difference rather than a silent
drift.

## D9 — No signed or attested output

**Decision:** the scanner produces a plain report. It does not produce signed
evidence, and it does not attest that an app passed anything.

**Reason:** "signed by whom" is unanswerable here, and an attestation would imply
an authority this project does not have. See also the sibling repository
`pi-contract-simulator`, whose decision record declines the same shape for the
same reason.
