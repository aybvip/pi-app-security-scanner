// render.mjs — render a scan report as human-readable text or JSON.
//
// Pure functions. No I/O. The text form is designed so a finding's "does not
// mean" line is never separated from the finding itself: the whole point is
// that a reader cannot mistake a match for a verdict.

import { SEVERITY_MEANING, FINDING_PRINCIPLE, CLEAN_RUN_MEANING, BOUNDARIES } from "./lib.mjs";

const ORDER = { high: 0, medium: 1, low: 2, info: 3 };

/** Always attached to a rendered report. */
export const REPORT_DISCLAIMER = [
  FINDING_PRINCIPLE,
  `Severity is ${SEVERITY_MEANING.is}. It is not ${SEVERITY_MEANING.isNot}.`,
  "This is a static text scan. It does not prove the application is secure or insecure.",
];

export function sortFindings(findings) {
  return [...findings].sort(
    (a, b) =>
      (ORDER[a.severity] ?? 9) - (ORDER[b.severity] ?? 9) ||
      String(a.file).localeCompare(String(b.file)) ||
      a.line - b.line
  );
}

export function renderReport(report) {
  const lines = [];
  lines.push("=== PI APP SECURITY SCAN (static, read-only) ===");
  lines.push(`  files scanned:      ${report.filesScanned}`);
  lines.push(`  files with findings: ${report.filesWithFindings}`);
  lines.push(`  active findings:    ${report.totalActive}`);
  lines.push(`  suppressed:         ${report.totalSuppressed}`);
  lines.push(
    `  by severity:        high=${report.bySeverity.high} medium=${report.bySeverity.medium} low=${report.bySeverity.low} info=${report.bySeverity.info}`
  );
  lines.push("");

  if (report.totalActive === 0) {
    lines.push("  NO ACTIVE FINDINGS.");
    lines.push(`  ${CLEAN_RUN_MEANING}`);
    lines.push("");
  }

  for (const f of sortFindings(report.active)) {
    lines.push(`  [${f.severity.toUpperCase()}] ${f.ruleId} ${f.title}`);
    lines.push(`      file:    ${f.file}:${f.line} (${f.fileKind})`);
    lines.push(`      match:   ${f.snippet}`);
    lines.push(`      rule:    ${f.whatItMeans}`);
    lines.push(`      source:  ${f.sourceUrl}`);
    lines.push(`      DOES NOT MEAN: ${f.whatItDoesNotMean}`);
    lines.push("");
  }

  if (report.totalSuppressed > 0) {
    lines.push(`  -- SUPPRESSED (${report.totalSuppressed}) --`);
    for (const f of report.suppressed) {
      lines.push(`  [suppressed] ${f.ruleId} ${f.file}:${f.line} — ${f.suppressionNote}`);
    }
    lines.push("");
  }

  lines.push("  -- DISCLAIMER --");
  for (const d of REPORT_DISCLAIMER) lines.push(`  - ${d}`);
  return lines.join("\n");
}

export function renderBoundaries() {
  const lines = ["=== BOUNDARIES — what this scan cannot do ==="];
  for (const b of BOUNDARIES) lines.push(`  - ${b}`);
  lines.push("");
  lines.push(`  ${CLEAN_RUN_MEANING}`);
  return lines.join("\n");
}

export function toJSON(report) {
  return JSON.stringify(
    {
      tool: "pi-app-security-scanner",
      mode: "static",
      disclaimer: REPORT_DISCLAIMER,
      summary: {
        filesScanned: report.filesScanned,
        filesWithFindings: report.filesWithFindings,
        totalActive: report.totalActive,
        totalSuppressed: report.totalSuppressed,
        bySeverity: report.bySeverity,
      },
      findings: sortFindings(report.active),
      suppressed: report.suppressed,
      cleanRunMeaning: report.cleanRunMeaning,
    },
    null,
    2
  );
}
