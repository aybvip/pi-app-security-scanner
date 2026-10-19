// scan-cli.mjs — command line for the static Pi-SDK scanner.
//
// READ-ONLY. It reads files inside the target directory, computes findings, and
// prints them. It writes nothing anywhere, executes nothing, and contacts no
// network. Where it cannot read a file it reports that as a skip, not silence.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, extname, relative } from "node:path";
import { scanText, buildScanReport } from "./scan.mjs";
import { renderReport, renderBoundaries, toJSON, REPORT_DISCLAIMER } from "./render.mjs";
import { RULES, BOUNDARIES, SOURCES, FIXTURES, FIXTURE_NOTE, IGNORE_MODEL, CLEAN_RUN_MEANING, SEVERITY_MEANING } from "./lib.mjs";

const out = (s) => process.stdout.write(s + "\n");
const rule = (s) => out(`\n=== ${s} ===`);

// Extensions we read as text. Anything else is skipped and reported.
const TEXT_EXT = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".htm", ".vue", ".svelte", ".json", ".env", ".txt", ".md", ".yaml", ".yml"]);

// Directories never descended into.
const SKIP_DIR = new Set([".git", "node_modules", ".next", "dist", "build", "coverage", ".cache", "vendor"]);

const MAX_FILE_BYTES = 2 * 1024 * 1024; // a scan is not a bulk text processor

function collect(dir, acc = [], skips = []) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    skips.push({ path: dir, reason: `cannot read directory: ${e.code ?? e.message}` });
    return acc;
  }
  for (const ent of entries) {
    const full = join(dir, ent.name);
    if (ent.isDirectory()) {
      if (SKIP_DIR.has(ent.name)) continue;
      collect(full, acc, skips);
    } else if (ent.isFile()) {
      const ext = extname(ent.name).toLowerCase();
      // .env files have no usable extension after split; treat by name too.
      const isEnv = /^\.env/i.test(ent.name);
      if (!TEXT_EXT.has(ext) && !isEnv) {
        skips.push({ path: full, reason: `not a scanned text type (${ext || "no extension"})` });
        continue;
      }
      let size = 0;
      try { size = statSync(full).size; } catch { /* fall through to read error */ }
      if (size > MAX_FILE_BYTES) {
        skips.push({ path: full, reason: `file larger than ${MAX_FILE_BYTES} bytes; skipped, not silently` });
        continue;
      }
      acc.push(full);
    }
  }
  return acc;
}

function scanDir(target) {
  const skips = [];
  const files = collect(target, [], skips);
  const fileResults = [];
  for (const file of files) {
    let text;
    try {
      text = readFileSync(file, "utf8");
    } catch (e) {
      skips.push({ path: file, reason: `cannot read file: ${e.code ?? e.message}` });
      continue;
    }
    fileResults.push({ file: relative(target, file), findings: scanText(relative(target, file), text) });
  }
  const report = buildScanReport(fileResults);
  return { report, skips, root: target };
}

function help() {
  out("pi-app-security-scanner - static scan for documented Pi SDK anti-patterns");
  out("");
  out("  node scan-cli.mjs --rules            the rule set, each with its official quote");
  out("  node scan-cli.mjs --scan DIR         scan a directory (read-only)");
  out("  node scan-cli.mjs --scan DIR --json  machine-readable output");
  out("  node scan-cli.mjs --boundaries       what this scan cannot do");
  out("  node scan-cli.mjs --severity         how severity is defined (and what it is not)");
  out("  node scan-cli.mjs --fixtures         the synthetic strings the tests use");
  out("  node scan-cli.mjs --sources          official sources, by rule");
  out("  node scan-cli.mjs --ignore           the suppression model");
  out("  node scan-cli.mjs --help             this help");
  out("");
  out("Static and read-only. Reads text. Executes nothing. No network. Writes nothing.");
  out(`A clean run is not a pass: ${CLEAN_RUN_MEANING}`);
}

function rules() {
  rule("RULE SET");
  out(`  ${RULES.length} rules, each anchored to an official quote.`);
  for (const r of RULES) {
    out("");
    out(`  ${r.id}  [${r.severity}]  ${r.title}`);
    out(`      claim kind:   ${r.claimKind}`);
    out(`      official:     "${r.officialQuote}"`);
    out(`      source:       ${r.sourceUrl}`);
    out(`      why:          ${r.why}`);
  }
}

function scan(target, asJson) {
  let st;
  try {
    st = statSync(target);
  } catch {
    out(`cannot scan "${target}": path does not exist or is not readable.`);
    process.exitCode = 2;
    return;
  }
  if (!st.isDirectory()) {
    out(`"${target}" is not a directory. This scanner scans directories, not single files (so the file-kind classification is meaningful).`);
    process.exitCode = 2;
    return;
  }
  const { report, skips } = scanDir(target);

  if (asJson) {
    out(toJSON(report));
  } else {
    out(renderReport(report));
    if (skips.length) {
      rule(`SKIPPED (${skips.length}) — reported, not hidden`);
      for (const s of skips) out(`  - ${s.path}: ${s.reason}`);
    }
  }
  process.exitCode = report.exitCode;
}

const args = process.argv.slice(2);
const has = (f) => args.includes(f);
const after = (f) => { const i = args.indexOf(f); return args[i + 1]; };

if (args.length === 0 || has("--help") || has("-h")) help();
else if (has("--rules")) rules();
else if (has("--scan")) scan(after("--scan"), has("--json"));
else if (has("--boundaries")) out(renderBoundaries());
else if (has("--severity")) {
  rule("SEVERITY — what it measures");
  out(`  severity is:     ${SEVERITY_MEANING.is}`);
  out(`  severity is NOT: ${SEVERITY_MEANING.isNot}`);
  rule("DISCLAIMER ATTACHED TO EVERY REPORT");
  for (const d of REPORT_DISCLAIMER) out(`  - ${d}`);
} else if (has("--fixtures")) {
  rule("SYNTHETIC FIXTURES");
  for (const [k, v] of Object.entries(FIXTURES)) out(`  ${k}: ${v}`);
  out(`  ${FIXTURE_NOTE}`);
} else if (has("--sources")) {
  rule("OFFICIAL SOURCES");
  for (const s of SOURCES) out(`  ${s.id} [${s.kind}] ${s.title}\n      ${s.url}\n      ${s.note}`);
} else if (has("--ignore")) {
  rule("SUPPRESSION MODEL");
  out(`  pragma:  ${IGNORE_MODEL.pragma}`);
  out(`  meaning: ${IGNORE_MODEL.meaning}`);
  out(`  rule:    ${IGNORE_MODEL.rule}`);
} else {
  out(`unknown option: ${args.join(" ")}`);
  out("try: node scan-cli.mjs --help");
  process.exitCode = 2;
}
