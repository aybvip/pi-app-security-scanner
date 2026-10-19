# Boundaries — what this scan cannot do

> This page exists so that **silence is never mistaken for approval**. The tool
> reports what it matched. It says nothing about what it did not look for.

---

## 1. It is static, and only static

It reads text. It never runs the code it scans, never imports it, and never
executes a fragment of it to "see what happens". Therefore it cannot observe
runtime behaviour, and any claim about what the code *does at run time* is out of
scope.

## 2. No data-flow analysis

The scanner matches **patterns in lines**, with a small amount of same-file,
same-statement context. It cannot follow a value:

- from one function into another,
- from one file into another,
- through an object stored and read later.

**Consequence:** a leaked key may be *used* on a line far from where it is
*defined*, and the scanner may not connect them. A rule firing means "this line is
worth reading", not "this is the whole story".

## 3. No dependency or vulnerability-database analysis

There is **no network access** and **no CVE database**. The scanner says nothing
about your `package.json`, your `node_modules`, or the versions of anything you
depend on. Dependency auditing is a different tool.

## 4. No secret-validity check

It flags the **shape** of a secret (e.g. a `Key …` header or a key-shaped
literal). It never contacts any service to test whether a key is live, and it
never transmits the matched text anywhere.

## 5. No exploitability claim — ever

A finding is a matched anti-pattern. Whether a given match is exploitable depends
on the rest of your app, your server, and your deployment. The scanner does **not
know** that, and does not say it.

## 6. No completeness claim

**Absence of findings is not evidence that the app is secure.** The rule set is
finite and anchored to Pi's documented mistakes. It does not cover every way an
app can be wrong, and it was never intended to.

## 7. No server-side visibility

It cannot see your backend. It cannot confirm that your server:
- verifies the `accessToken` against `/me`,
- keeps the Server API Key out of client code,
- checks `mediator_ack_status` before granting a reward.

Those checks appear in the rules only as *client-side signals of intent*.

## 8. Heuristics are labelled as heuristics

Where a rule uses a lightweight parser (comment stripping, statement grouping,
callback-body spans), that is stated in [`RULES.md`](RULES.md) rather than
presented as a real parser. If a heuristic misfires, that is expected, and the
suppression mechanism is the honest response — see §9.

## 9. Suppression is visible

A line marked with the `// pi-scan-ignore` pragma is **still evaluated**. If it
matches, it is reported as **SUPPRESSED** with the reason, not silently dropped.
There is no file-wide and no rule-wide disable, so you can never turn the scanner
off wholesale while believing it ran.

---

## The one sentence to remember

> **No findings means no documented anti-pattern matched the text. It does NOT
> mean the application is secure, and it is NOT a substitute for a review.**

## Reproduce

```bash
node scan-cli.mjs --boundaries   # this page, offline
node test/run.mjs                # asserts each boundary statement above exists
```
