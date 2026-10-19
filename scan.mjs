// scan.mjs — the scanning engine. Pure, offline, read-only.
//
// This module takes TEXT (from a file on disk, or a string in a test) and
// returns findings. It never executes scanned code, never makes a network
// request, and never reads anything outside the paths it is given.
//
// Every function here is deterministic: the same input always yields the same
// output, and no function consults the clock, the network, or the environment.

import { RULES, FILE_KINDS, IGNORE_PRAGMA, makeFinding } from "./lib.mjs";

// ---------------------------------------------------------------------------
// 1. File classification — conservative, and "unknown" is a real answer
// ---------------------------------------------------------------------------
//
// We classify from the PATH ONLY. We never guess from file contents, and we
// never treat "unknown" as "client" — an unknown file is reported as unknown.

const CLIENT_PATH = /(^|[\\/])(public|client|frontend|src[\\/]?client|assets|static|www|dist|build|app[\\/]?client)([\\/]|$)/i;
const SERVER_PATH = /(^|[\\/])(server|backend|api|functions|lambda|services[\\/]?server|routes)([\\/]|$)|[\\/]?(server|backend)\.[cm]?[jt]sx?$/i;
const CONFIG_PATH = /(^|[\\/])\.env(\.|$)|\.env\.[a-z]+$|secrets?\.[a-z]+\.(json|ya?ml|txt)$/i;

export function classifyPath(filePath) {
  const p = String(filePath ?? "");
  if (CONFIG_PATH.test(p)) return "server";
  // client before server so `src/client/...` is client even if it sits under a
  // folder that also looks server-ish.
  if (CLIENT_PATH.test(p)) return "client";
  if (SERVER_PATH.test(p)) return "server";
  // An .html file is always client: it is delivered to the browser.
  if (/\.(html?|htm)$/i.test(p)) return "client";
  return "unknown";
}

export const isClientPath = (p) => classifyPath(p) === "client";

// ---------------------------------------------------------------------------
// 2. Comment stripping — so a commented-out call is not a finding
// ---------------------------------------------------------------------------
//
// A naive scanner reports commented-out code. That produces false findings and
// erodes trust, so lines whose code portion is entirely a comment are skipped.
// We keep the raw line for the snippet, but we do not match code patterns in it.

export function stripComment(line) {
  const s = String(line ?? "");
  const t = s.trim();
  if (t.startsWith("//") || t.startsWith("*") || t.startsWith("/*") || t.startsWith("#")) return "";
  // Inline: cut at a trailing // that is not inside a string. This is a
  // heuristic and is documented as such, not presented as a parser.
  const idx = s.indexOf("//");
  if (idx > 0) {
    const before = s.slice(0, idx);
    const quotes = (before.match(/["'`]/g) ?? []).length;
    if (quotes % 2 === 0) return before;
  }
  return s;
}

// ---------------------------------------------------------------------------
// 3. File context — the small amount of whole-file state a rule may consult
// ---------------------------------------------------------------------------
//
// Rules receive a per-file context. Building it is the ONLY place a rule can
// "see" more than one line, and every field it exposes is a literal, checkable
// property of the text (a substring test or a statement grouping) — never a
// guess about intent.

export function buildFileContext(filePath, text) {
  const lines = String(text ?? "").split(/\r?\n/);
  const code = lines.map(stripComment);
  const all = code.join("\n");
  const kind = classifyPath(filePath);

  return {
    filePath,
    kind,
    isClientFile: kind === "client",
    lines,
    codeLines: code,
    fileHasPiInit: /Pi\s*\.\s*init\s*\(/.test(all) || /window\.Pi\s*\.\s*init\s*\(/.test(all),
    fileHasPaymentFlow: /createPayment|onReadyForServerApproval|onReadyForServerCompletion/.test(all),
    fileMentionsAccessTokenVerification:
      /accessToken/.test(all) &&
      /(\/me\b|auth\/verify|\/verify|Authorization\s*:\s*[`"']?\s*Bearer)/i.test(all),
    fileMentionsAdVerification:
      /(ads_network\/status|mediator_ack_status|verifyAd|verify_ad|verifyRewardedAd)/i.test(all) ||
      // The documented client pattern: POST the adId to the app's own backend
      // and grant only after the backend reports success.
      (/ads\/reward|ads\/verify|reward/i.test(all) && /data\.rewarded|\.rewarded\b|rewarded\s*===?\s*true/i.test(all)),
  };
}

// ---------------------------------------------------------------------------
// 4. Statement grouping — a light, honest window for cross-line rules
// ---------------------------------------------------------------------------
//
// Some rules need a small window, not one line: "does this fetch include an
// Authorization header?" We group lines into coarse statements by brace/paren
// depth and by blank lines. This is a heuristic, and the rules that use it are
// marked so in their comments.

/**
 * The body span of the arrow/function callback defined starting at `handlerIdx`.
 * We look for the FIRST brace that opens the callback body after the handler
 * name on the handler line (or subsequent lines), then its matching close.
 * A bare function REFERENCE (e.g. `onReadyForServerCompletion: fn`) has no body
 * here, and this returns null — the caller must treat that honestly.
 */
export function spanOfCallbackBody(codeLines, handlerIdx) {
  let depth = 0;
  let open = -1;
  for (let i = handlerIdx; i < codeLines.length; i++) {
    const line = codeLines[i];
    for (let c = 0; c < line.length; c++) {
      const ch = line[c];
      if (ch === "{") {
        if (open === -1) { open = i; depth = 0; }
        depth++;
      } else if (ch === "}") {
        depth--;
        if (open !== -1 && depth === 0) return { from: open, to: i };
      } else if ((ch === "(" || ch === "[") && open === -1) {
        // Track parens before the body brace so we don't mistake an argument
        // list for the body; they are balanced and do not open the body.
      }
    }
    // If we reached the end of the handler's own line and never saw a brace on
    // it, keep scanning subsequent lines for the body's opening brace only
    // while the callback is still being defined. Bounded to a few lines.
    if (open === -1 && i > handlerIdx + 3) return null;
  }
  return open === -1 ? null : { from: open, to: codeLines.length - 1 };
}

/**
 * The span of the `createPayment(...)` call's arguments, from the line carrying
 * `createPayment(` to the line where its parentheses return to the opening
 * depth. Returns null if there is no createPayment call in the file.
 */
export function createPaymentRegion(codeLines) {
  const start = codeLines.findIndex((l) => /createPayment\s*\(/.test(l));
  if (start < 0) return null;
  let depth = 0;
  let opened = false;
  let callEnd = start;
  for (let i = start; i < codeLines.length; i++) {
    for (const ch of codeLines[i]) {
      if (ch === "(" || ch === "{") { depth++; opened = true; }
      else if (ch === ")" || ch === "}") { depth = Math.max(0, depth - 1); }
    }
    if (opened && depth === 0 && i >= start) { callEnd = i; break; }
  }
  // Extend through the enclosing statement: any following lines that do not
  // start a new top-level construct and are part of the same block of code
  // immediately after the call (e.g. a grant call on the next line).
  let to = callEnd;
  for (let i = callEnd + 1; i < codeLines.length; i++) {
    const l = codeLines[i];
    if (l.trim() === "") break;
    // stop if a new function/statement that clearly belongs to something else
    if (/^\s*(export\s+)?(async\s+)?function\b|^\s*(export\s+)?(const|let|var)\s+\w+\s*=\s*(async\s*)?(function|\()/.test(l)) break;
    to = i;
    if (/;\s*$/.test(l)) break;
  }
  return { from: start, to };
}

export function statements(lines, codeLines) {
  const out = [];
  let start = 0;
  let depth = 0;
  let run = [];
  for (let i = 0; i < lines.length; i++) {
    const c = codeLines[i];
    run.push(i);
    for (const ch of c) {
      if (ch === "{" || ch === "(" || ch === "[") depth++;
      else if (ch === "}" || ch === ")" || ch === "]") depth = Math.max(0, depth - 1);
    }
    const blank = c.trim() === "";
    if (blank || depth === 0) {
      out.push({ from: start, to: i, lines: run.slice() });
      start = i + 1;
      run = [];
    }
  }
  if (run.length) out.push({ from: start, to: lines.length - 1, lines: run });
  return out;
}

// ---------------------------------------------------------------------------
// 5. The scan — apply every rule to every code line
// ---------------------------------------------------------------------------
//
// A finding requires a rule's `detect` to return true. A line carrying the
// ignore pragma is still evaluated, and if it matches it becomes a SUPPRESSED
// finding (recorded, not dropped).

export function scanText(filePath, text) {
  const ctx = buildFileContext(filePath, text);
  const stmts = statements(ctx.lines, ctx.codeLines);

  // Pre-index: for each line, which statement is it in, and does that statement
  // carry an Authorization header or a reward grant? These are literal tests.
  const stmtHasAuth = new Map();
  const stmtGrantsReward = new Map();
  for (const s of stmts) {
    const body = s.lines.map((i) => ctx.codeLines[i]).join("\n");
    const hasAuth = /['"`]?\s*authorization['"`]?\s*:/i.test(body);
    const grants = /\b(setIsPremium|setPremium|addExtraLife|addExtraLives|grantReward|grantAccess|unlockFeature|setUnlocked|onExtraLivesGranted|deliverFeature|activatePremium)\b/.test(body);
    for (const i of s.lines) {
      stmtHasAuth.set(i, hasAuth);
      stmtGrantsReward.set(i, grants);
    }
  }

  // For PSC-003 we need "is this grant call inside the createPayment options
  // object but OUTSIDE the completion callback?" We find the createPayment call
  // region, the completion handler and the span of its INLINE callback body.
  // If the handler is a bare reference there is no body in this file, so any
  // grant inside the payment region is treated as outside it — reported
  // honestly, not guessed.
  const paymentRegion = createPaymentRegion(ctx.codeLines);
  const completionHandlerIndex = ctx.codeLines.findIndex((l) => /onReadyForServerCompletion/.test(l));
  const completionBody = completionHandlerIndex >= 0
    ? spanOfCallbackBody(ctx.codeLines, completionHandlerIndex)
    : null;

  const grantBeforeCompletion = (i) => {
    if (completionHandlerIndex < 0) return false;
    if (paymentRegion == null) return false;
    // the grant must sit inside the payment call's arguments…
    if (i < paymentRegion.from || i > paymentRegion.to) return false;
    // …but not inside the completion callback's body.
    return completionBody == null || i < completionBody.from || i > completionBody.to;
  };

  const findings = [];
  for (let i = 0; i < ctx.codeLines.length; i++) {
    const line = ctx.codeLines[i];
    if (line.trim() === "") continue;
    const raw = ctx.lines[i];
    const suppressed = raw.includes(IGNORE_PRAGMA);

    for (const rule of RULES) {
      // The context a rule may consult, all literal.
      const ruleCtx = {
        ...ctx,
        statementHasAuthorization: stmtHasAuth.get(i) ?? false,
        statementGrantsReward: stmtGrantsReward.get(i) ?? false,
        grantBeforeCompletion: grantBeforeCompletion(i),
      };
      if (!rule.detect(line, ruleCtx)) continue;

      const finding = makeFinding({ rule, file: filePath, line: raw, lineNumber: i + 1, snippet: raw });
      finding.fileKind = ctx.kind;
      finding.suppressed = suppressed;
      if (suppressed) finding.suppressionNote = `explicitly suppressed by the ${IGNORE_PRAGMA} pragma on this line`;
      findings.push(finding);
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// 6. Report building — counts, by severity, with suppressed kept visible
// ---------------------------------------------------------------------------

export function buildScanReport(fileResults) {
  const active = [];
  const suppressed = [];
  for (const fr of fileResults) {
    for (const f of fr.findings) (f.suppressed ? suppressed : active).push(f);
  }
  const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of active) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;

  return {
    filesScanned: fileResults.length,
    filesWithFindings: fileResults.filter((fr) => fr.findings.some((f) => !f.suppressed)).length,
    totalActive: active.length,
    totalSuppressed: suppressed.length,
    bySeverity,
    active,
    suppressed,
    // A stable exit code a CI job can use: any active finding is non-zero.
    exitCode: active.length > 0 ? 1 : 0,
    cleanRunMeaning:
      active.length === 0
        ? "No findings means no documented anti-pattern matched the text. It does NOT mean the application is secure."
        : null,
  };
}

export { RULES, FILE_KINDS };
