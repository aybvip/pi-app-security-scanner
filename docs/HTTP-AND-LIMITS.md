# Static-analysis limits, and how severity is defined

## 1. Why "static" is the whole story

A static scanner reads text. Everything it can and cannot do follows from that
one fact:

| Because it reads text | it can | it cannot |
|---|---|---|
| no execution | match patterns reliably and deterministically | observe runtime behaviour |
| no data flow | look at one line and its immediate statement | follow a value across functions or files |
| no network | run offline, with no keys and no telemetry | check a CVE database or test a key's validity |
| no server | flag client-side signals of server intent | confirm what the server actually does |

## 2. The two questions severity is *not* answering

It is common to read a "severity" as risk. Here it is **not** risk. It is
**directness**:

| Severity | Means | Does not mean |
|---|---|---|
| **high** | the matched text contradicts an explicit, unconditional **MUST** in the documentation | that the app is exploitable |
| **medium** | the matched text omits a required step, or uses a non-public API the docs warn against | that the omission is fatal |
| **low** | a documentation-listed mistake whose consequence depends on the rest of the app | that it is trivial |
| **info** | a likely-unintentional leftover with no documented security consequence | that it is harmless |

> **Severity is how directly the matched text contradicts the recorded official
> rule. It is not how severe an exploit would be, and not whether one exists.**

## 3. What "high" is reserved for

By construction, a rule is **high** only when it rests on a **documented,
unconditional MUST** — e.g. the Server API Key MUST stay on the server
(PSC-001), the client `user` object is spoofable so `/me` is the only trusted
source (PSC-002), the feature MUST be delivered only after Phase 3 (PSC-003), the
`adId` MUST always be verified server-side (PSC-006). The test suite asserts that
every high-severity rule is `documented`, never `derived`.

## 4. What the scanner does not do, in analysis terms

- **No taint tracking.** A secret read on line 10 and sent on line 90 is not
  connected unless both are visible in the same statement window.
- **No interprocedural analysis.** A helper that approves a payment is not traced
  from its call site.
- **No type or build awareness.** It does not compile the code, and it does not
  know your module graph.
- **No dependency resolution.** It does not read `package.json` to reason about
  third-party code.

Each of these is a **limit**, not a bug. They are listed here so that a reader
understands the scanner's reach rather than inferring it.

## 5. How to read a scan result

1. Read the matched **line**, not the count.
2. Read the **official quote** attached to the rule.
3. Decide whether the rule applies to your app.
4. If it does not, add `// pi-scan-ignore` **and say why** — the scan will report
   the suppression visibly, so a reviewer can see the judgement.

## 6. Reproduce

```bash
node scan-cli.mjs --severity    # this page's severity model, offline
node scan-cli.mjs --boundaries  # the full boundary list
```
