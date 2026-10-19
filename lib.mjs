// lib.mjs — the rule set and the honesty contract for a STATIC Pi-SDK scanner.
//
// Everything here is either:
//   - DOCUMENTED: grounded in a quotable passage of Pi's official documentation
//     (each rule carries the exact quote and the URL), or
//   - DERIVED:   a mechanical consequence of a documented rule (recorded as such),
//     never an opinion about "best practice".
//
// The scanner is purely static: it reads text. It never executes the code it
// scans, never makes a network request, and never claims to have found
// something it did not literally match.

// ---------------------------------------------------------------------------
// 1. Claim kinds — the honesty contract (same discipline as the other repos)
// ---------------------------------------------------------------------------
export const CLAIM_KINDS = [
  { id: "documented", meaning: "quoted from Pi's official documentation; the quote and URL are recorded with the rule" },
  { id: "derived", meaning: "a mechanical consequence of a documented rule; stated as derived, not as a separate claim" },
  { id: "external", meaning: "third-party commentary, flagged UNOFFICIAL" },
  { id: "not-claimed", meaning: "out of scope: whether the app is secure overall, whether a finding is exploitable, runtime behaviour" },
];

/**
 * Phrases that must never be asserted. A static scanner reports PATTERNS in
 * text. It does not report that an app IS insecure.
 */
export const FORBIDDEN_CLAIMS = [
  "this app is insecure",
  "this app is secure",
  "this code is vulnerable",
  "the finding is exploitable",
  "prevents all attacks",
  "guarantees security",
  "Pi endorsed",
  "Pi approved",
  "we are first",
];

/**
 * What a finding is, precisely. A finding is a MATCH OF A DOCUMENTED ANTI-PATTERN
 * in text. It is not a verdict on the application.
 */
export const FINDING_PRINCIPLE =
  "A finding means a documented anti-pattern was matched in the scanned text. It does not mean the application is insecure, and it does not mean the pattern is exploitable. It means a human should look at that line.";

// ---------------------------------------------------------------------------
// 2. Severity — honest, bounded, and never "exploitable"
// ---------------------------------------------------------------------------
//
// Severity describes how DIRECTLY the documented rule is about the matched text,
// not how bad an exploit would be. That distinction is stated so severity is not
// read as a risk score.
export const SEVERITIES = [
  { id: "high", meaning: "the matched text contradicts an explicit, unconditional MUST in Pi's documentation (e.g. a Server API Key in client code)" },
  { id: "medium", meaning: "the matched text omits a step the documentation says is required, or uses a non-public API the documentation warns against" },
  { id: "low", meaning: "the matched text is a documentation-listed mistake whose consequence depends on the rest of the app (e.g. a missing init call that may exist elsewhere)" },
  { id: "info", meaning: "the matched text is a likely unintentional leftover with no documented security consequence" },
];

/** Severity is about the rule's directness, NOT about exploitability. */
export const SEVERITY_MEANING = {
  is: "how directly the matched text contradicts the recorded official rule",
  isNot: "how severe an exploit would be, or whether one exists at all",
};

// ---------------------------------------------------------------------------
// 3. The rules — each anchored to an official quote
// ---------------------------------------------------------------------------
//
// Rule ids are stable. `detect` is a pure function over a single source line
// (and, where a rule needs it, over the whole file) returning true when the
// documented anti-pattern is present. Rules are conservative: they match what
// the documentation literally warns about, and nothing more.
//
// `officialQuote` is verbatim from Pi's documentation. `sourceUrl` is the page.
// Where a rule cannot be tied to a quote, it is not a rule.

export const RULES = [
  {
    id: "PSC-001",
    title: "Server API Key present in client-reachable code",
    severity: "high",
    claimKind: "documented",
    officialQuote:
      "Your Server API Key must be kept on your server, and must not be sent to clients (do not use it in your client JavaScript code). In the future, your server API key might enable sensitive operations on your app itself that your users should not be allowed to perform. Letting users access your server API key is a serious security breach.",
    sourceUrl: "https://docs.minepi.com/api-reference/PlatformAPI",
    why: "A Server API Key in client code is readable by every user of the app. Pi states this is a serious security breach.",
    // A Key used as an Authorization header, or a key-shaped literal, in a
    // client file. We look for the Authorization: Key form and for common
    // client-side markers rather than guessing at key formats.
    detect: (line, ctx) =>
      /authorization\s*:\s*[`"']?\s*key\s+/i.test(line) ||
      /\bpi[_-]?api[_-]?key\b\s*[:=]\s*[`"'][^`"']{8,}/i.test(line) ||
      /\bserver[_-]?api[_-]?key\b\s*[:=]\s*[`"'][^`"']{8,}/i.test(line) ||
      (ctx?.isClientFile && /api\.minepi\.com\/v2/i.test(line) && /['"`]key\s+[A-Za-z0-9._-]{8,}/i.test(line)),
    wrong: `fetch('https://api.minepi.com/v2/payments/' + id + '/approve', {
  headers: { Authorization: 'Key ' + PI_API_KEY } })`,
    correct: "Do the approve/complete calls from your backend, where the Server API Key lives.",
  },
  {
    id: "PSC-002",
    title: "Client user object trusted as identity without server verification",
    severity: "high",
    claimKind: "documented",
    officialQuote:
      "This is a security flaw: the frontend user object can be spoofed. The only trusted source of user identity is the Pi Platform API's /me endpoint, which validates the accessToken server-side.",
    sourceUrl: "https://docs.minepi.com/troubleshooting/CommonMistakes",
    why: "Authorising from the client user object means an attacker can forge it.",
    // Storing / trusting the client `user` without any reference to sending the
    // accessToken to a backend. We match the store-or-authorise pattern AND the
    // absence of an accessToken-verification call in the same file.
    detect: (line, ctx) => {
      const storesUser = /localStorage\.setItem\s*\(\s*['"`]?\s*\w*(pi)?user/i.test(line) ||
        /\b(user|piUser)\s*\.\s*(uid|username)\b\s*(===|==|\?|&&)/.test(line);
      if (!storesUser) return false;
      return !ctx?.fileMentionsAccessTokenVerification;
    },
    wrong: "localStorage.setItem('piUser', JSON.stringify(user)); // never sends accessToken to a backend",
    correct: "POST the accessToken to your backend; the backend calls GET /v2/me with Bearer <accessToken>.",
  },
  {
    id: "PSC-003",
    title: "Feature granted before server-side completion",
    severity: "high",
    claimKind: "documented",
    officialQuote:
      "Server Completion (onReadyForServerCompletion) — your server confirms completion and delivers the feature. A common mistake is granting the feature (e.g., premium mode, extra lives) at Phase 1 or when the payment modal closes, rather than waiting for Phase 3 to complete successfully on the server.",
    sourceUrl: "https://docs.minepi.com/troubleshooting/CommonMistakes",
    why: "Granting before Phase 3 means a user can obtain the feature without a confirmed payment.",
    // A grant-like call that appears in a PAYMENT flow but OUTSIDE the
    // onReadyForServerCompletion callback. The rule only applies when the file
    // actually contains a payment flow (createPayment / onReadyForServer…),
    // so an unrelated grant call (e.g. a rewarded-ad reward) is not caught here.
    detect: (line, ctx) => {
      if (ctx?.fileHasPaymentFlow !== true) return false;
      const grants = /\b(setIsPremium|setPremium|addExtraLife|addExtraLives|grantReward|grantAccess|unlockFeature|setUnlocked|onExtraLivesGranted|deliverFeature|activatePremium)\b/.test(line);
      if (!grants) return false;
      return ctx?.grantBeforeCompletion === true;
    },
    wrong: "createPayment({...}, { onReadyForServerApproval: fn, onReadyForServerCompletion: fn }); setIsPremium(true);",
    correct: "Grant the feature inside onReadyForServerCompletion, only after the backend reports success.",
  },
  {
    id: "PSC-004",
    title: "Payment callback posts to a path the app also declares elsewhere (mismatch risk)",
    severity: "low",
    claimKind: "derived",
    officialQuote:
      "Pi.createPayment() callbacks must POST paymentId / txid to your backend routes. If the frontend calls a path your server does not expose, the request returns 404 and the payment stalls.",
    sourceUrl: "https://docs.minepi.com/troubleshooting/CommonMistakes",
    why: "A static scanner cannot see the server, so it can only flag that callback paths are worth cross-checking. Severity is low for that reason.",
    // We deliberately do NOT guess a mismatch. We flag that approve/complete
    // paths exist so a human verifies them against the server. recorded as
    // 'derived' precisely because it is a consequence, not a direct match.
    detect: (line) =>
      /onReadyForServerApproval|onReadyForServerCompletion/.test(line) &&
      /(approve|complete)/i.test(line),
    wrong: "frontend calls /pi_payment/approve while the server exposes /api/payments/approve",
    correct: "Cross-check every callback path against the routes your backend actually implements.",
  },
  {
    id: "PSC-005",
    title: "Authenticated backend call without an Authorization header",
    severity: "medium",
    claimKind: "documented",
    officialQuote:
      "Backend endpoints that perform user-specific actions (granting rewards, updating scores, delivering purchased features) need to know which user is making the request. If your backend uses token-based auth ... forgetting to include the header means current_user is nil and the user-specific operation silently does nothing.",
    sourceUrl: "https://docs.minepi.com/troubleshooting/CommonMistakes",
    why: "A user-specific call without an Authorization header cannot be attributed to a user.",
    // A fetch to an app-local user-specific endpoint with no Authorization in
    // the same statement window.
    detect: (line, ctx) => {
      const userSpecific = /fetch\s*\([^)]*(reward|grant|profile|me|user|score|purchase|unlock)/i.test(line) ||
        /fetch\s*\(\s*['"`][^'"`]*(reward|grant|score|purchase|unlock)/i.test(line);
      if (!userSpecific) return false;
      return ctx?.statementHasAuthorization === false;
    },
    wrong: "fetch('/api/ads/reward', { method: 'POST', body: JSON.stringify({ adId }) });",
    correct: "headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` }",
  },
  {
    id: "PSC-006",
    title: "Rewarded ad reward granted without server-side verification",
    severity: "high",
    claimKind: "documented",
    officialQuote:
      "After Pi.Ads.showAd('rewarded') resolves with { result: 'AD_REWARDED', adId }, some apps grant the reward immediately based on the client-side result. The Pi SDK client response can be spoofed. The adId must always be verified against the Pi Platform API before granting any reward.",
    sourceUrl: "https://docs.minepi.com/troubleshooting/CommonMistakes",
    why: "The client ad result can be spoofed, so rewarding on it alone is exploitable by the user.",
    detect: (line, ctx) => {
      const checksRewarded = /AD_REWARDED/.test(line);
      if (!checksRewarded) return false;
      return ctx?.statementGrantsReward === true && ctx?.fileMentionsAdVerification !== true;
    },
    wrong: "if (result.result === 'AD_REWARDED') addExtraLife();",
    correct: "POST adId to your backend; reward only if mediator_ack_status === 'granted'.",
  },
  {
    id: "PSC-007",
    title: "accessToken read from a non-public internal property",
    severity: "medium",
    claimKind: "documented",
    officialQuote:
      "Some implementations try to read the token from undocumented properties such as window.PiSdkBase?.accessToken. Those properties are not part of the public Pi SDK API, are not guaranteed to exist, and typically return undefined or an empty string.",
    sourceUrl: "https://docs.minepi.com/troubleshooting/CommonMistakes",
    why: "Reading the token from an internal property yields an empty token, so server verification silently fails.",
    detect: (line) =>
      /PiSdkBase\s*\?\.\s*accessToken|PiSdkBase\.accessToken|window\.Pi\?\.\s*_?accessToken\b/.test(line),
    wrong: "const accessToken = window.PiSdkBase?.accessToken ?? '';",
    correct: "Use the accessToken returned by Pi.authenticate().",
  },
  {
    id: "PSC-008",
    title: "Payment completion called with empty/fabricated paymentId or txid",
    severity: "medium",
    claimKind: "documented",
    officialQuote:
      "onReadyForServerCompletion is the only client callback that provides the real paymentId and txid. Completing a payment with empty or fabricated values causes the Platform API to reject the request ... The client may look finished while the server never confirmed the payment with Pi.",
    sourceUrl: "https://docs.minepi.com/troubleshooting/CommonMistakes",
    why: "The completion call is rejected, so the payment is never confirmed with Pi.",
    detect: (line) =>
      /(paymentId|txid)\s*:\s*(['"`]{2}|null\b|undefined\b|''|"")/.test(line) ||
      /JSON\.stringify\(\s*\{\s*paymentId\s*:\s*['"`]{2}/.test(line),
    wrong: "body: JSON.stringify({ paymentId: '', txid: '' })",
    correct: "Use the (paymentId, txid) arguments passed to onReadyForServerCompletion.",
  },
  {
    id: "PSC-009",
    title: "Pi SDK used without a visible Pi.init() call",
    severity: "low",
    claimKind: "documented",
    officialQuote:
      "Pi.init() must be called before any other Pi SDK calls, ... Calling Pi SDK methods without Pi.init() first ... ERROR: Pi.init() was never called",
    sourceUrl: "https://docs.minepi.com/troubleshooting/CommonMistakes",
    why: "Without init, SDK calls throw; the call may exist in another file, so severity is low.",
    detect: (line, ctx) =>
      /window\.Pi\.(authenticate|createPayment)\b/.test(line) && ctx?.fileHasPiInit !== true,
    wrong: "window.Pi.authenticate(['username'], onIncompletePaymentFound);",
    correct: "Call Pi.init({ version: '2.0', sandbox: false }) before any Pi SDK method.",
  },
];

export const ruleById = (id) => RULES.find((r) => r.id === id) ?? null;
export const rulesBySeverity = (sev) => RULES.filter((r) => r.severity === sev);

// ---------------------------------------------------------------------------
// 4. The scan model — file classification and finding shape
// ---------------------------------------------------------------------------

/** File kinds the scanner distinguishes. Client code cannot hold server secrets. */
export const FILE_KINDS = [
  { id: "client", meaning: "code shipped to the browser/Pi Browser (HTML, and JS/TS in a client-context path)" },
  { id: "server", meaning: "code that runs on the developer's server (server paths, .env-style config)" },
  { id: "unknown", meaning: "the scanner could not classify this file from its path; it is reported as unknown, not guessed" },
];

/** A finding is a matched rule in one line. Nothing more. */
export function makeFinding({ rule, file, line, lineNumber, snippet }) {
  return {
    ruleId: rule.id,
    title: rule.title,
    severity: rule.severity,
    claimKind: rule.claimKind,
    file,
    line: lineNumber,
    snippet: String(snippet ?? line ?? "").trim().slice(0, 200),
    officialQuote: rule.officialQuote,
    sourceUrl: rule.sourceUrl,
    whatItMeans: `The text matched rule ${rule.id}: ${rule.title}.`,
    whatItDoesNotMean:
      "This does not mean the application is insecure, and it does not mean the match is exploitable. A human must read the line.",
  };
}

// ---------------------------------------------------------------------------
// 5. Boundaries — explicit, so the scanner's silence is never read as approval
// ---------------------------------------------------------------------------
export const BOUNDARIES = [
  "Static only: it reads text. It never runs the scanned code and never makes a network request.",
  "No data-flow analysis: it cannot follow a value from one function or file into another.",
  "No dependency or CVE analysis: it has no network access and no vulnerability database.",
  "No secret-validity check: it flags the SHAPE of a leaked key, never contacts any service to test it.",
  "No exploitability claim: a match is a line worth reading, not a demonstrated vulnerability.",
  "No completeness claim: absence of findings is not evidence that the app is secure.",
  "No server-side code: it cannot see whether your backend actually verifies a token.",
];

/** The single most important non-claim: silence is not a pass. */
export const CLEAN_RUN_MEANING =
  "No findings means no documented anti-pattern matched the text. It does NOT mean the application is secure, and it is NOT a substitute for a review.";

export const FORBIDDEN_OPERATIONS = [
  "fetch(",           // the scanner must not call out
  "require('child_process')",
  "eval(",
  "new Function(",
  "execSync",
];

// ---------------------------------------------------------------------------
// 6. Ignore model — how a line is excused, and why that is explicit
// ---------------------------------------------------------------------------
//
// A developer can mark a line as reviewed with a trailing comment. The scanner
// records the excuse rather than hiding the match, so suppressed findings are
// visible in the output.
export const IGNORE_PRAGMA = "pi-scan-ignore";
export const IGNORE_MODEL = {
  pragma: IGNORE_PRAGMA,
  meaning: "a line carrying this pragma is reported as SUPPRESSED, not silently dropped",
  rule: "suppression is per-line; there is no file-wide or rule-wide disable",
};

// ---------------------------------------------------------------------------
// 7. Synthetic fixtures — inputs the scanner is tested against, offline
// ---------------------------------------------------------------------------
export const FIXTURES = {
  "leaked-key": "fetch('/api/approve', { headers: { Authorization: 'Key ' + serverKey } });",
  "trusts-client-user": "localStorage.setItem('piUser', JSON.stringify(user));",
  "grants-early": "setIsPremium(true);",
  "no-init": "await window.Pi.authenticate(['username'], onIncompletePaymentFound);",
  "empty-txid": "body: JSON.stringify({ paymentId: '', txid: '' })",
  "internal-token": "const accessToken = window.PiSdkBase?.accessToken ?? '';",
};

export const FIXTURE_NOTE =
  "Fixtures are synthetic strings, written for this test suite. They contain no real keys, no real users, and no personal data.";

// ---------------------------------------------------------------------------
// 8. Source records — every rule's official anchor, gathered in one place
// ---------------------------------------------------------------------------
export const SOURCES = [
  {
    id: "S1",
    title: "Common Pi SDK Integration Mistakes",
    url: "https://docs.minepi.com/troubleshooting/CommonMistakes",
    kind: "documented",
    note: "Eight numbered mistakes (Mistake 1-8) with Wrong/Correct examples. Primary rule source.",
  },
  {
    id: "S2",
    title: "Platform API Reference",
    url: "https://docs.minepi.com/api-reference/PlatformAPI",
    kind: "documented",
    note: "Server API Key warning; /me, /payments/{id}/approve and /complete; ads_network/status.",
  },
  {
    id: "S3",
    title: "Pi Network Authentication Guide",
    url: "https://docs.minepi.com/authenticate-user/Authentication",
    kind: "documented",
    note: "Pi.init, Pi.authenticate, backend /me verification, narrowest-scopes advice.",
  },
  {
    id: "S4",
    title: "Client SDK Reference",
    url: "https://docs.minepi.com/api-reference/SdkReference",
    kind: "documented",
    note: "window.Pi methods for authentication, payments, ads and native features.",
  },
];
