// @ts-check
/**
 * mcp-output-firewall — report rendering (runtime)
 */

/** @typedef {import('./rules.js').Finding} Finding */
/** @typedef {import('./rules.js').ScanResult} ScanResult */
/** @typedef {import('./rules.js').Severity} Severity */

const ORDER = { low: 0, medium: 1, high: 2, critical: 3 };
const ICON = { critical: "[CRIT]", high: "[HIGH]", medium: "[MED ]", low: "[LOW ]" };

/** @param {Severity} a @param {Severity} b */
export function severityAtLeast(a, b) {
  return ORDER[a] >= ORDER[b];
}

/**
 * @param {Array<Finding & {path?:string}>} findings
 * @returns {string}
 */
export function renderFindings(findings) {
  if (findings.length === 0) return "  no findings\n";
  /** @type {string[]} */
  const lines = [];

  for (const f of findings) {
    lines.push(`${ICON[f.severity]} [${f.ruleId}] ${f.title}${f.path ? " @ " + f.path : ""}`);
    lines.push(`     severity : ${f.severity}`);
    lines.push(`     category : ${f.category}`);
    if (f.evidence) lines.push(`     evidence : ${JSON.stringify(f.evidence)}`);
    lines.push(`     why      : ${f.why}`);
    lines.push(`     fix      : ${f.fix}`);
    lines.push("");
  }
  return lines.join("\n");
}

/**
 * @param {ScanResult} result
 * @param {string} label
 * @returns {string}
 */
export function renderScanResult(result, label) {
  const head = result.safe
    ? `[OK]   ${label} — clean (${result.stats.rulesRun} rules, ${result.stats.elapsedMs}ms)`
    : `${ICON[result.worst || "low"]} ${label} — ${result.findings.length} finding(s), worst=${result.worst} (${result.stats.elapsedMs}ms)`;
  return [head, "", ...(result.findings.length ? [renderFindings(result.findings)] : [])].join("\n");
}

/**
 * @param {Record<string, ScanResult>} results
 * @returns {string}
 */
export function toJsonReport(results) {
  const total = Object.values(results).reduce((n, r) => n + r.findings.length, 0);
  return JSON.stringify(
    {
      tool: "mcp-output-firewall",
      version: "0.1.0",
      generatedAt: new Date().toISOString(),
      summary: {
        targets: Object.keys(results).length,
        totalFindings: total,
      },
      results,
    },
    null,
    2,
  );
}

/**
 * Exit codes: 0 clean, 1 findings at/above threshold.
 * @param {Record<string, ScanResult>} results
 * @param {Severity} threshold
 */
export function exitCodeFor(results, threshold) {
  for (const r of Object.values(results)) {
    if (r.worst && severityAtLeast(r.worst, threshold)) return 1;
  }
  return 0;
}
