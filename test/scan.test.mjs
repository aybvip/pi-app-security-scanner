// test/scan.test.mjs — offline invariants for pi-app-security-scanner.
// No network. No personal data. No writes. Runs in-process.

import {
  CLAIM_KINDS, FORBIDDEN_CLAIMS, FINDING_PRINCIPLE, SEVERITIES, SEVERITY_MEANING,
  RULES, ruleById, rulesBySeverity, FILE_KINDS, makeFinding, BOUNDARIES, CLEAN_RUN_MEANING,
  FORBIDDEN_OPERATIONS, IGNORE_PRAGMA, IGNORE_MODEL, FIXTURES, FIXTURE_NOTE, SOURCES,
} from "../lib.mjs";
import { classifyPath, isClientPath, stripComment, buildFileContext, statements, scanText, buildScanReport } from "../scan.mjs";
import { renderReport, renderBoundaries, toJSON, REPORT_DISCLAIMER, sortFindings } from "../render.mjs";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

let pass = 0, fail = 0;
const failures = [];
function ok(cond, label) { if (cond) { pass++; return; } fail++; failures.push(label); }
function eq(a, b, label) {
  const A = JSON.stringify(a), B = JSON.stringify(b);
  if (A === B) { pass++; return; }
  fail++; failures.push(`${label}\n    expected: ${B}\n    actual:   ${A}`);
}
const ids = (fs) => fs.map((f) => f.ruleId).sort();

// --- claim discipline --------------------------------------------------------
eq(CLAIM_KINDS.map((c) => c.id), ["documented", "derived", "external", "not-claimed"],
  "exactly four claim kinds");
ok(FORBIDDEN_CLAIMS.some((f) => /app is insecure/i.test(f)), "forbids claiming an app is insecure");
ok(FORBIDDEN_CLAIMS.some((f) => /app is secure/i.test(f)), "forbids claiming an app is secure");
ok(FORBIDDEN_CLAIMS.some((f) => /exploitable/i.test(f)), "forbids claiming exploitability");
ok(FORBIDDEN_CLAIMS.some((f) => /Pi approved/i.test(f)), "forbids claiming Pi approval");
ok(FORBIDDEN_CLAIMS.some((f) => /we are first/i.test(f)), "forbids a 'we are first' claim");
ok(/does not mean the application is insecure/i.test(FINDING_PRINCIPLE),
  "the finding principle states what a finding does NOT mean");

// --- severity is defined, and is explicitly not exploitability ---------------
eq(SEVERITIES.map((s) => s.id), ["high", "medium", "low", "info"], "four severities in order");
ok(/directly/i.test(SEVERITY_MEANING.is), "severity is defined as how directly the rule applies");
ok(/exploit/i.test(SEVERITY_MEANING.isNot), "severity is explicitly NOT exploitability");

// --- every rule is anchored to an official quote + URL -----------------------
ok(RULES.length >= 9, "at least nine rules");
for (const r of RULES) {
  ok(/^PSC-\d{3}$/.test(r.id), `rule id is stable-shaped: ${r.id}`);
  ok(typeof r.officialQuote === "string" && r.officialQuote.length > 30,
    `rule ${r.id} carries a substantial official quote`);
  ok(/^https:\/\/docs\.minepi\.com\//.test(r.sourceUrl),
    `rule ${r.id} cites an official minepi.com docs URL`);
  ok(["documented", "derived"].includes(r.claimKind),
    `rule ${r.id} is documented or derived (never opinion)`);
  ok(SEVERITIES.some((s) => s.id === r.severity), `rule ${r.id} has a valid severity`);
  ok(typeof r.detect === "function", `rule ${r.id} has a detector`);
}
eq(new Set(RULES.map((r) => r.id)).size, RULES.length, "rule ids are unique");
eq(ruleById("PSC-999"), null, "an unknown rule id returns null");
ok(rulesBySeverity("high").length >= 3, "at least three high-severity rules");
ok(rulesBySeverity("high").every((r) => r.claimKind === "documented"),
  "high-severity rules rest on documentation, not inference");

// --- the rule set covers the eight official numbered mistakes ----------------
// Each official Mistake 1..8 must map to at least one rule; this ties the rule
// set to the source page rather than to our imagination.
const mistakeMap = {
  1: "PSC-009", 2: "PSC-002", 3: "PSC-003", 4: "PSC-004",
  5: "PSC-005", 6: "PSC-006", 7: "PSC-007", 8: "PSC-008",
};
for (const [n, id] of Object.entries(mistakeMap)) {
  ok(ruleById(id) !== null, `official Mistake ${n} is covered by ${id}`);
}
// PSC-001 comes from the Platform API page, not the mistakes page.
eq(ruleById("PSC-001").sourceUrl, "https://docs.minepi.com/api-reference/PlatformAPI",
  "PSC-001 is anchored to the Platform API page's Server API Key warning");
ok(/serious security breach/i.test(ruleById("PSC-001").officialQuote),
  "PSC-001 quotes the 'serious security breach' wording verbatim");

// --- file classification is conservative; 'unknown' is a real answer ---------
eq(FILE_KINDS.map((k) => k.id), ["client", "server", "unknown"], "three file kinds, unknown included");
eq(classifyPath("public/app.js"), "client", "a public/ path is client");
eq(classifyPath("src/client/pi.ts"), "client", "a client/ path is client");
eq(classifyPath("server/index.js"), "server", "a server/ path is server");
eq(classifyPath(".env"), "server", "a .env file is server-side config");
eq(classifyPath("index.html"), "client", "an HTML file is client");
eq(classifyPath("lib/whatever.js"), "unknown", "an unclassifiable path stays unknown");
ok(!isClientPath("lib/whatever.js"), "unknown is NOT treated as client");
ok(!isClientPath("server/app.js"), "server is not client");

// --- comment stripping: commented-out code is not a finding ------------------
eq(stripComment("// fetch(x)"), "", "a full-line comment yields no code");
eq(stripComment("  * doc"), "", "a docblock line yields no code");
eq(stripComment("# comment"), "", "a hash comment yields no code");
eq(stripComment("fetch(x); // note"), "fetch(x); ", "a trailing comment is cut");
ok(/fetch/.test(stripComment("fetch(x)")), "real code survives stripping");

// --- each rule FIRES on its fixture -----------------------------------------
// Fixtures are synthetic. We assert the rule matches, and nothing else claims it.
const fixtureFile = "src/client/pay.ts";
const fire = (ruleId, line, file = fixtureFile) => {
  const f = scanText(file, line).filter((x) => x.ruleId === ruleId);
  return f;
};

ok(fire("PSC-001", "headers: { Authorization: 'Key ' + PI_API_KEY }").length === 1,
  "PSC-001 fires on a Key Authorization header");
ok(fire("PSC-001", "const serverApiKey = 'abcdef123456';").length === 1,
  "PSC-001 fires on a key-shaped literal");
ok(fire("PSC-002", "localStorage.setItem('piUser', JSON.stringify(user));").length === 1,
  "PSC-002 fires when the client user is stored and no accessToken verification is present");
ok(fire("PSC-002", "localStorage.setItem('piUser', JSON.stringify(user));\nawait fetch('/api/auth/verify', { body: JSON.stringify({ accessToken }) });").length === 0,
  "PSC-002 does NOT fire when the file also verifies the accessToken");
ok(fire("PSC-003", "createPayment({}, {\n  onReadyForServerApproval: fn,\n  onReadyForServerCompletion: fn,\n});\nsetIsPremium(true);").length === 1,
  "PSC-003 fires when a grant call precedes the completion handler");
ok(fire("PSC-002", "const { user, accessToken } = await Pi.authenticate(['username'], cb);").length === 0,
  "PSC-002 does not fire on a plain authenticate destructure");
ok(fire("PSC-004", "onReadyForServerApproval: (paymentId) => fetch('/api/payments/approve', {...})").length === 1,
  "PSC-004 flags a callback path for cross-checking");
ok(fire("PSC-005", "fetch('/api/ads/reward', { method: 'POST', body: JSON.stringify({ adId }) });").length === 1,
  "PSC-005 fires on a user-specific fetch without Authorization");
ok(fire("PSC-005", "fetch('/api/ads/reward', { headers: { 'Authorization': `Bearer ${accessToken}` }, body });\n").length === 0,
  "PSC-005 does NOT fire when the statement carries Authorization");
ok(fire("PSC-006", "if (result.result === 'AD_REWARDED') { addExtraLife(); }").length === 1,
  "PSC-006 fires when a reward is granted on the client ad result alone");
ok(fire("PSC-006", "if (result.result === 'AD_REWARDED') { await verifyAd(adId); addExtraLife(); }\n// mediator_ack_status checked").length === 0,
  "PSC-006 does NOT fire when the file verifies the ad server-side");
ok(fire("PSC-007", "const accessToken = window.PiSdkBase?.accessToken ?? '';").length === 1,
  "PSC-007 fires on the undocumented internal property");
ok(fire("PSC-008", "body: JSON.stringify({ paymentId: '', txid: '' })").length === 1,
  "PSC-008 fires on an empty paymentId/txid");
ok(fire("PSC-008", "body: JSON.stringify({ paymentId, txid })").length === 0,
  "PSC-008 does NOT fire when the real arguments are used");
ok(fire("PSC-009", "await window.Pi.authenticate(['username'], onIncompletePaymentFound);").length === 1,
  "PSC-009 fires when Pi.authenticate has no visible Pi.init in the file");
ok(fire("PSC-009", "Pi.init({ version: '2.0', sandbox: false });\nawait window.Pi.authenticate(['username'], cb);").length === 0,
  "PSC-009 does NOT fire when Pi.init is present in the file");

// --- CORRECT forms from the docs must produce NO findings --------------------
// These lines are taken from the 'Correct' examples in the official pages and
// must be silent. If a rule fires on documented-correct code, the rule is wrong.
const correctLines = [
  "window.Pi.init({ version: '2.0', sandbox: false });",
  "const { user, accessToken } = await window.Pi.authenticate(['username', 'payments'], onIncompletePayment);",
  "const res = await fetch('/api/auth/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ accessToken }) });",
  "await fetch('/api/payment/complete', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` }, body: JSON.stringify({ paymentId, txid }) });",
  "if (res.ok) { setIsPremium(true); }",
];
for (const line of correctLines) {
  const found = scanText("src/client/correct.ts", "Pi.init({ version: '2.0' });\n" + line);
  // Allow PSC-004 (a documented cross-check prompt) and PSC-009 (init may be
  // in the first line we prepended), but no HIGH findings on documented code.
  const high = found.filter((f) => f.severity === "high");
  eq(high.length, 0, `no high-severity finding on documented-correct code: ${line.slice(0, 50)}`);
}

// --- a single match with the ignore pragma is SUPPRESSED, not dropped --------
const suppressed = scanText("src/client/pay.ts", "const serverApiKey = 'abcdef123456'; // pi-scan-ignore");
eq(suppressed.length, 1, "the suppressed match is still produced");
eq(suppressed[0].suppressed, true, "the match is marked suppressed");
ok(/pi-scan-ignore/.test(suppressed[0].suppressionNote), "the suppression note names the pragma");

// --- the report separates active from suppressed, and counts honestly --------
const rep = buildScanReport([
  { file: "a.ts", findings: scanText("src/client/a.ts", "const serverApiKey = 'abcdef123456';") },
  { file: "b.ts", findings: scanText("src/client/b.ts", "const serverApiKey = 'abcdef123456'; // pi-scan-ignore") },
]);
eq(rep.totalActive, 1, "one active finding");
eq(rep.totalSuppressed, 1, "one suppressed finding");
eq(rep.filesWithFindings, 1, "one file has active findings");
eq(rep.exitCode, 1, "an active finding yields exit code 1");
eq(rep.bySeverity.high, 1, "the active finding is counted as high");

const clean = buildScanReport([{ file: "a.ts", findings: [] }]);
eq(clean.exitCode, 0, "no active finding yields exit code 0");
ok(/does NOT mean the application is secure/i.test(clean.cleanRunMeaning),
  "a clean run states that it is not a pass");

// --- rendered output keeps the 'does not mean' next to every finding ---------
const text = renderReport(rep);
ok(/DOES NOT MEAN/.test(text), "rendered report includes a 'DOES NOT MEAN' line");
ok(/does not mean the application is insecure/i.test(text), "the non-claim is present verbatim");
ok(/NO ACTIVE FINDINGS/.test(renderReport(clean)), "a clean report says so explicitly");
ok(/does NOT mean the application is secure/i.test(renderReport(clean)), "a clean report is not a pass");
const j = JSON.parse(toJSON(rep));
eq(j.mode, "static", "JSON marks the mode as static");
eq(j.findings.length, 1, "JSON carries the active findings");
eq(j.suppressed.length, 1, "JSON carries the suppressed findings, visibly");
ok(/static/i.test(j.disclaimer.join(" ")), "the JSON disclaimer names the static limit");

// --- boundaries are explicit and truthful ------------------------------------
ok(BOUNDARIES.some((b) => /never runs|static only/i.test(b)), "boundary: never executes scanned code");
ok(BOUNDARIES.some((b) => /data-flow/i.test(b)), "boundary: no data-flow analysis");
ok(BOUNDARIES.some((b) => /CVE|vulnerability database/i.test(b)), "boundary: no dependency/CVE analysis");
ok(BOUNDARIES.some((b) => /no network|network request/i.test(b)), "boundary: no network");
ok(BOUNDARIES.some((b) => /absence of findings is not evidence/i.test(b)), "boundary: silence is not a pass");
ok(/does NOT mean the application is secure/i.test(CLEAN_RUN_MEANING), "the clean-run non-claim is recorded");
ok(/substitute for a review/i.test(CLEAN_RUN_MEANING), "the clean-run meaning rejects substitution for review");

// --- the scanner does not contain forbidden operations as real code ----------
// The words appear in FORBIDDEN_OPERATIONS and in documentation strings; the
// check is that no module INVOKES them. lib.mjs legitimately mentions `fetch(`
// as a forbidden token and in detector regexes, so it is checked directly for
// execution primitives only.
ok(FORBIDDEN_OPERATIONS.length > 0, "forbidden operations are enumerated");
for (const f of ["scan.mjs", "render.mjs"]) {
  const src = readFileSync(join(root, f), "utf8");
  ok(!/\bfetch\s*\(/.test(src), `${f} performs no network call`);
  ok(!/child_process|execSync|new Function\s*\(/.test(src), `${f} executes nothing`);
}
{
  const src = readFileSync(join(root, "lib.mjs"), "utf8");
  // lib.mjs is pure data + detector regexes. The strings "fetch(", "eval(",
  // "new Function(" and "require('child_process')" appear ONLY as documented
  // forbidden tokens. What matters is the actual IMPORT surface: no module is
  // imported at all, so nothing can be executed or contacted.
  const imports = [...src.matchAll(/^\s*import\s+.+$/gm)].map((m) => m[0].trim());
  eq(imports, [], "lib.mjs imports nothing — it is pure data and regexes");
  ok(/export const FORBIDDEN_OPERATIONS/.test(src), "lib.mjs declares FORBIDDEN_OPERATIONS");
  ok(FORBIDDEN_OPERATIONS.some((f) => /child_process/.test(f)), "child_process is a declared forbidden token");
}
{
  const src = readFileSync(join(root, "scan-cli.mjs"), "utf8");
  ok(!/\bfetch\s*\(/.test(src), "scan-cli.mjs performs no network call");
  ok(!/child_process|execSync|new Function\s*\(/.test(src), "scan-cli.mjs executes nothing");
}

// --- the sources are official and recorded -----------------------------------
ok(SOURCES.length >= 4, "at least four sources recorded");
for (const s of SOURCES) {
  ok(/^https:\/\/docs\.minepi\.com\//.test(s.url), `source ${s.id} is an official docs URL`);
  eq(s.kind, "documented", `source ${s.id} is documented`);
}

// --- the ignore model is explicit --------------------------------------------
eq(IGNORE_MODEL.pragma, IGNORE_PRAGMA, "the ignore pragma matches the model");
ok(/SUPPRESSED, not silently dropped/i.test(IGNORE_MODEL.meaning), "suppression is visible, not silent");
ok(/no file-wide|per-line/i.test(IGNORE_MODEL.rule), "suppression is per-line only");

// --- fixtures are synthetic and labelled -------------------------------------
ok(Object.keys(FIXTURES).length >= 6, "at least six synthetic fixtures");
ok(/no real keys, no real users, and no personal data/i.test(FIXTURE_NOTE),
  "the fixture note declares them synthetic and free of personal data");

// --- the shipped examples behave: vulnerable flagged, corrected clean --------
// These are files in the repository, scanned in-process. The vulnerable example
// must trigger every rule family it demonstrates; the corrected one must be
// clean. This is the end-to-end proof the rules work on realistic code.

{
  const vulnPath = join(root, "examples", "vulnerable", "client", "payment.ts");
  const corrPath = join(root, "examples", "corrected", "client", "payment.ts");
  const vuln = scanText(vulnPath, readFileSync(vulnPath, "utf8"));
  const corr = scanText(corrPath, readFileSync(corrPath, "utf8"));

  const vulnIds = new Set(vuln.map((f) => f.ruleId));
  for (const id of ["PSC-001", "PSC-002", "PSC-003", "PSC-005", "PSC-006", "PSC-007", "PSC-008", "PSC-009"]) {
    ok(vulnIds.has(id), `the vulnerable example triggers ${id}`);
  }
  // The corrected example must produce NO active findings at all.
  eq(corr.filter((f) => !f.suppressed).length, 0, "the corrected example produces zero findings");
  // And no finding at any severity in the corrected file.
  eq(corr.length, 0, "the corrected example produces no findings of any severity");
  // Both files are classified as client code.
  ok(vuln.every((f) => f.fileKind === "client"), "vulnerable example is classified client");
}

// --- docs and links ----------------------------------------------------------
const docs = [
  "README.md", "llms.txt", "docs/INDEX.md", "docs/RULES.md", "docs/HTTP-AND-LIMITS.md",
  "docs/SOURCES.md", "docs/DECISIONS.md", "docs/VERIFICATION.md", "docs/BOUNDARIES.md",
];
for (const d of docs) {
  try { readFileSync(join(root, d), "utf8"); pass++; } catch { fail++; failures.push(`missing doc: ${d}`); }
}

// collect every prose file once — used by the forbidden-claim check and the
// link check below
const mdFiles = [];
(function walk(dir) {
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    if (ent.name === ".git" || ent.name === "node_modules") continue;
    const full = join(dir, ent.name);
    if (ent.isDirectory()) walk(full);
    else if (/\.(md|txt)$/.test(ent.name)) mdFiles.push(full);
  }
})(root);

// --- the repository's own prose contains no forbidden claim ------------------
// The phrases above must not be ASSERTED anywhere in this repo's text. A phrase
// appearing inside a quoted denial or a documentation of what is forbidden is
// fine; a phrase asserted as fact is not. We check the prose files.
{
  for (const f of mdFiles) {
    const text = readFileSync(f, "utf8");
    for (const claim of FORBIDDEN_CLAIMS) {
      const re = new RegExp(claim.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
      for (const line of text.split(/\r?\n/)) {
        if (!re.test(line)) continue;
        // allow: documentation of the forbidden list, explicit negation, quotes
        const isNegated = /\b(not|never|does not|doesn't|isn't|is not|no|nor|forbidden|cannot|can't|must not)\b/i.test(line);
        const isQuotedRule = /forbidden|FORBIDDEN|must not|quoted|quote|avoid/i.test(line);
        if (isNegated || isQuotedRule) continue;
        fail++;
        failures.push(`forbidden claim asserted in ${f}: "${claim}"\n    line: ${line.trim().slice(0, 120)}`);
      }
    }
  }
  pass++; // the block ran
}

// relative markdown links resolve
let broken = 0;
for (const f of mdFiles) {
  const t = readFileSync(f, "utf8");
  for (const m of t.matchAll(/\]\((?!https?:|#)([^)]+)\)/g)) {
    const rel = m[1].split("#")[0];
    if (!rel) continue;
    try { readFileSync(join(dirname(f), rel), "utf8"); } catch { broken++; failures.push(`broken link in ${f}: ${rel}`); }
  }
}
ok(broken === 0, `no broken relative links (found ${broken})`);

// --- verdict -----------------------------------------------------------------
if (fail) {
  console.error(`\n${fail} FAILURE(S):`);
  for (const f of failures) console.error("  - " + f);
  process.exitCode = 1;
}
console.log(`\npi-app-security-scanner — invariant tests\n  pass: ${pass}\n  fail: ${fail}`);
