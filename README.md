# pi-app-security-scanner

**A static, read-only scan of Pi app source for documented Pi SDK anti-patterns.**

> **What this is.** A tiny, dependency-free tool that reads your source files and
> reports lines that match anti-patterns **Pi's own documentation** warns about.
> Every rule carries the exact official quote it is built on, and the URL of the
> page it came from.
>
> **What this is not.** It does **not** prove your app is secure, and it does **not**
> prove it is insecure. It is a **static text scan**: it runs nothing, contacts
> nothing, and follows nothing from one file into another. A clean run is **not a
> pass**.

---

## The one distinction this tool exists to keep

| A finding means | A finding does **not** mean |
|---|---|
| a documented anti-pattern was matched in your text | that your app is insecure |
| a specific line is worth a human reading | that the pattern is exploitable |
| the official rule (quoted) applies to that line | that Pi reviewed or endorsed anything |

That distinction is printed next to **every** finding, and it is asserted by the
test suite.

> **Silence is not approval.** No findings means "no documented anti-pattern
> matched the text". It is **not** evidence that the app is secure, and it is
> **not** a substitute for a review.

## Quick start

```bash
node scan-cli.mjs --rules          # the 9 rules, each with its official quote
node scan-cli.mjs --scan DIR       # scan a directory (read-only)
node scan-cli.mjs --scan DIR --json
node scan-cli.mjs --boundaries     # what this scan cannot do
node scan-cli.mjs --severity       # how severity is defined (and what it is not)
node scan-cli.mjs --sources        # official sources, by rule
node scan-cli.mjs --ignore         # the suppression model
node test/run.mjs                  # offline invariant suite
```

Run it against the shipped examples to see it work:

```bash
node scan-cli.mjs --scan examples/vulnerable   # every rule fires; exit 1
node scan-cli.mjs --scan examples/corrected    # zero findings; exit 0
```

## The rules, and where each comes from

Each rule cites the official page it is built on. The primary source is Pi's own
troubleshooting page, which lists **eight numbered mistakes**; the ninth rule
comes from the Platform API's Server API Key warning.

| Rule | Severity | Matches | Official anchor |
|---|---|---|---|
| **PSC-001** | high | a **Server API Key** in client-reachable code | Platform API: *"must not be sent to clients … a serious security breach"* |
| **PSC-002** | high | the client `user` object trusted as identity, with no `accessToken` verification | Mistake 2: *"the frontend user object can be spoofed"* |
| **PSC-003** | high | a feature granted before server-side completion | Mistake 3: *"granting the feature … at Phase 1"* |
| **PSC-004** | low | payment callback paths worth cross-checking | Mistake 4: *"returns 404 and the payment stalls"* |
| **PSC-005** | medium | a user-specific call with no `Authorization` header | Mistake 5: *"current_user is nil"* |
| **PSC-006** | high | a rewarded-ad reward granted on the client result alone | Mistake 6: *"The Pi SDK client response can be spoofed"* |
| **PSC-007** | medium | `accessToken` read from a non-public internal property | Mistake 7: *"typically return undefined or an empty string"* |
| **PSC-008** | medium | completion called with empty/fabricated `paymentId`/`txid` | Mistake 8: *"reject the request"* |
| **PSC-009** | low | `Pi.authenticate`/`createPayment` with no visible `Pi.init()` | Mistake 1: *"Pi.init() was never called"* |

Full quotes, URLs and reasoning: [`docs/RULES.md`](docs/RULES.md) or
`node scan-cli.mjs --rules`.

## Tested against the documented "Correct" forms

The rules are **not** allowed to fire on code Pi's documentation calls correct.
The test suite includes the documented correct snippets and asserts **no
high-severity finding** matches them. If a rule cries wolf on documented-correct
code, the suite fails.

## Design choices you can check

- **Static only.** Reads text. Executes nothing. No network. Writes nothing.
- **`unknown` is a real answer.** A file whose path cannot be classified is
  reported as `unknown`, never guessed as `client`.
- **Commented-out code is not a finding.** Lines whose code portion is a comment
  are skipped, so the scanner does not report code you already disabled.
- **Suppression is visible.** A line marked `// pi-scan-ignore` is reported as
  **SUPPRESSED**, not silently dropped. There is no file-wide or rule-wide disable.
- **Exit code.** Any active finding → exit `1`. No findings → exit `0`.

## What it deliberately does not contain

- **No data-flow analysis.** It cannot follow a value across functions or files,
  so it may miss a key that is consumed on a later line. That is a documented limit.
- **No dependency or CVE analysis.** It has no network and no vulnerability
  database, so it says nothing about your packages.
- **No secret-validity check.** It flags the *shape* of a leaked key. It never
  contacts a service to test whether a key is live.
- **No exploitability claim.** A match is a line worth reading, not a demonstrated
  vulnerability.

See [`docs/HTTP-AND-LIMITS.md`](docs/HTTP-AND-LIMITS.md) and
[`docs/DECISIONS.md`](docs/DECISIONS.md).

## Documentation

- [`docs/INDEX.md`](docs/INDEX.md) — index of everything
- [`docs/RULES.md`](docs/RULES.md) — every rule, its official quote and URL
- [`docs/BOUNDARIES.md`](docs/BOUNDARIES.md) — what the scan cannot do, in full
- [`docs/HTTP-AND-LIMITS.md`](docs/HTTP-AND-LIMITS.md) — static-analysis limits (no data flow, no CVEs)
- [`docs/DECISIONS.md`](docs/DECISIONS.md) — decision record, including what was not built
- [`docs/SOURCES.md`](docs/SOURCES.md) — official sources, by rule
- [`docs/VERIFICATION.md`](docs/VERIFICATION.md) — reproduce every claim yourself
- [`llms.txt`](llms.txt) — one-line answers for agent consumption

## License

MIT.
