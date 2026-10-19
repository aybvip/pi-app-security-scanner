# Verification — reproduce every claim yourself

Everything this repository claims is either **reproducible offline** or
**checkable against an official quote**. This page lists how to confirm each.

---

## 1. The test suite passes

```bash
node test/run.mjs
```

Asserts, offline and with no network:

- exactly the four claim kinds, and the forbidden-claims list;
- every rule has an official quote and an official `docs.minepi.com` URL;
- every high-severity rule is `documented`, not `derived`;
- each official Mistake 1…8 maps to its rule;
- file classification never defaults `unknown` to `client`;
- commented-out code is not a finding;
- **each rule fires on its fixture** and **does not fire** on the documented
  correct form;
- the shipped `examples/corrected` file produces **zero** findings of any
  severity;
- the shipped `examples/vulnerable` file triggers every demonstrated rule;
- a suppressed match is reported as **SUPPRESSED**, not dropped;
- the rendered report contains the "does NOT mean" line for findings and the
  "not a pass" line for a clean run;
- the engine modules contain no `fetch`, no `child_process`, no `eval`, no
  `new Function`;
- the sources are all official `docs.minepi.com` URLs.

## 2. The scanner finds what it says it finds

```bash
node scan-cli.mjs --scan examples/vulnerable
```

Expect **exit code 1** and findings for every rule family the example
demonstrates. Each finding prints the matched line, the rule, its official
source URL, and a "DOES NOT MEAN" line.

```bash
node scan-cli.mjs --scan examples/corrected
```

Expect **exit code 0** and `NO ACTIVE FINDINGS`, followed by the sentence that a
clean run is **not** a pass.

## 3. Each rule matches Pi's own words

```bash
node scan-cli.mjs --rules
```

Every rule prints the verbatim quote and the page it came from. Open the URL and
confirm the quote is present on that page.

## 4. Severity is directness, not risk

```bash
node scan-cli.mjs --severity
```

Confirms the definition and the disclaimer attached to every report.

## 5. The boundaries are asserted, not just written

```bash
node test/run.mjs
```

The suite asserts each boundary statement exists: no execution, no data flow, no
CVE analysis, no network, and that absence of findings is not evidence of
security.

## 6. Nothing is transmitted

```bash
node scan-cli.mjs --scan examples --json > /dev/null   # (or > NUL on Windows)
```

The scanner reads files and prints a result. There is no network call in the
engine or the CLI; the suite asserts this. Nothing leaves your machine.

---

## What you **cannot** verify here, by design

- Whether your app is secure. That is not claimed.
- Whether a specific match is exploitable. That is not claimed.
- Whether your backend verifies tokens. The scanner cannot see it, and does not
  claim to.
