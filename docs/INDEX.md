# Index

| Document | What it answers |
|---|---|
| [`../README.md`](../README.md) | What this is, what it refuses to claim, quick start |
| [`RULES.md`](RULES.md) | Every rule, its exact official quote, its URL, and its reasoning |
| [`BOUNDARIES.md`](BOUNDARIES.md) | What this scan cannot do, in full |
| [`HTTP-AND-LIMITS.md`](HTTP-AND-LIMITS.md) | The static-analysis limits: no data flow, no CVEs, no execution |
| [`DECISIONS.md`](DECISIONS.md) | Decision record, including what was **not** built and why |
| [`SOURCES.md`](SOURCES.md) | Official sources, by claim kind |
| [`VERIFICATION.md`](VERIFICATION.md) | Reproduce every claim yourself |

## Commands

| Command | Does |
|---|---|
| `node scan-cli.mjs --rules` | the rule set, each with its official quote |
| `node scan-cli.mjs --scan DIR` | scan a directory (read-only) |
| `node scan-cli.mjs --scan DIR --json` | machine-readable output |
| `node scan-cli.mjs --boundaries` | what this scan cannot do |
| `node scan-cli.mjs --severity` | how severity is defined, and what it is not |
| `node scan-cli.mjs --sources` | official sources, by rule |
| `node scan-cli.mjs --ignore` | the suppression model |
| `node test/run.mjs` | offline invariant suite |

## At a glance

| Concept | Value |
|---|---|
| Mode | static, read-only (reads text only) |
| Rule count | 9 (PSC-001 … PSC-009) |
| Claim kinds | documented · derived · external · not-claimed |
| Severities | high · medium · low · info (defined as rule directness, **not** exploitability) |
| Finding means | a documented anti-pattern matched in text |
| Finding does NOT mean | the app is insecure, or the match is exploitable |
| Clean run means | nothing matched — **not** a pass |
| Suppression | per-line `// pi-scan-ignore`, reported as SUPPRESSED |
| Exit code | `1` on any active finding, `0` otherwise |
| Network | none |
| Writes | none |
| Engine | [`../scan.mjs`](../scan.mjs) · renderer [`../render.mjs`](../render.mjs) |
