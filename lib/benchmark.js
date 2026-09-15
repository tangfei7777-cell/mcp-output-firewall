// @ts-check
/**
 * mcp-output-firewall — benchmark runner (runtime)
 *
 * Scores the engine against the adversarial corpus and prints an honest,
 * reproducible scorecard. Three numbers matter and they are reported separately,
 * because collapsing them into a single "detection rate" is how security tools
 * lie to their users:
 *
 *   catch rate   — of the vectors we claim to detect, how many did we detect.
 *                  A regression here fails CI.
 *   gap count    — vectors we openly cannot catch with this architecture.
 *                  Reported, never hidden, and never counted as a win.
 *   control rate — of the benign samples, how many passed untouched.
 *                  This is the number that decides whether the tool is usable.
 *
 * @typedef {import('./adversarial.js').AttackVector} AttackVector
 */

import { ATTACK_VECTORS, summarizeByClass } from "./adversarial.js";
import { scanDeep } from "./rules.js";

const ORDER = { low: 0, medium: 1, high: 2, critical: 3 };

/**
 * @typedef {object} VectorOutcome
 * @property {string} id
 * @property {string} attackClass
 * @property {string} title
 * @property {string} expected
 * @property {string} actual       "caught" | "missed" | "clean" | "false-positive"
 * @property {boolean} ok
 * @property {string} [worst]
 * @property {string[]} [rules]
 * @property {string} [coveredBy]
 */

/**
 * @typedef {object} BenchReport
 * @property {number} total
 * @property {{ catchable:number, caught:number, missed:number, rate:number }} catchRate
 * @property {{ count:number, gaps:number }} gaps
 * @property {{ controls:number, clean:number, falsePositives:number, rate:number }} controls
 * @property {VectorOutcome[]} outcomes
 * @property {ReturnType<typeof summarizeByClass>} byClass
 * @property {number} elapsedMs
 */

/**
 * Score one vector.
 * @param {AttackVector} v
 * @returns {VectorOutcome}
 */
function score(v) {
  const findings = scanDeep(v.content);
  const worst = findings.length
    ? findings.reduce((a, f) => (ORDER[f.severity] > ORDER[a] ? f.severity : a), "low")
    : null;
  const rules = [...new Set(findings.map((f) => f.ruleId))];

  if (v.expected === "clean") {
    const falsePositive = findings.length > 0;
    return {
      id: v.id,
      attackClass: v.attackClass,
      title: v.title,
      expected: v.expected,
      actual: falsePositive ? "false-positive" : "clean",
      ok: !falsePositive,
      worst: worst || undefined,
      rules,
    };
  }

  // "catch" and "gap" vectors are both attacks; the difference is whether we
  // claim to stop them. A gap that we happen to catch is a bonus, not a win.
  const caught = findings.length > 0;
  return {
    id: v.id,
    attackClass: v.attackClass,
    title: v.title,
    expected: v.expected,
    actual: caught ? "caught" : "missed",
    ok: v.expected === "gap" ? true : caught,
    worst: worst || undefined,
    rules,
    coveredBy: v.coveredBy,
  };
}

/**
 * Run the full corpus.
 * @returns {BenchReport}
 */
export function runBenchmark() {
  const started = Date.now();
  const outcomes = ATTACK_VECTORS.map(score);

  const catchable = outcomes.filter((o) => o.expected === "catch");
  const caught = catchable.filter((o) => o.actual === "caught");
  const missed = catchable.filter((o) => o.actual === "missed");

  const gaps = outcomes.filter((o) => o.expected === "gap");
  const gapsCaught = gaps.filter((o) => o.actual === "caught");

  const controls = outcomes.filter((o) => o.expected === "clean");
  const clean = controls.filter((o) => o.actual === "clean");
  const falsePositives = controls.filter((o) => o.actual === "false-positive");

  return {
    total: outcomes.length,
    catchRate: {
      catchable: catchable.length,
      caught: caught.length,
      missed: missed.length,
      rate: catchable.length ? caught.length / catchable.length : 1,
    },
    gaps: {
      count: gaps.length,
      // Vectors we did not claim but caught anyway — honest bonus reporting.
      gaps: gaps.length - gapsCaught.length,
    },
    controls: {
      controls: controls.length,
      clean: clean.length,
      falsePositives: falsePositives.length,
      rate: controls.length ? clean.length / controls.length : 1,
    },
    outcomes,
    byClass: summarizeByClass(),
    elapsedMs: Date.now() - started,
  };
}

/** @param {number} n @returns {string} */
function pct(n) {
  return `${Math.round(n * 100)}%`;
}

/** @param {string} s @param {number} w */
function pad(s, w) {
  return s.length >= w ? s : s + " ".repeat(w - s.length);
}

/**
 * Human-readable scorecard.
 * @param {BenchReport} report
 * @returns {string}
 */
export function renderBench(report) {
  /** @type {string[]} */
  const lines = [];
  lines.push("");
  lines.push("mcp-output-firewall adversarial benchmark");
  lines.push("=".repeat(66));
  lines.push("");
  lines.push("  Detection coverage (attack vectors we claim to stop)");
  lines.push(`    catchable vectors : ${report.catchRate.catchable}`);
  lines.push(`    caught            : ${report.catchRate.caught}`);
  lines.push(`    missed            : ${report.catchRate.missed}`);
  lines.push(`    catch rate        : ${pct(report.catchRate.rate)}`);
  lines.push("");
  lines.push("  Known gaps (cannot be solved by content inspection alone)");
  lines.push(`    uncaught by design: ${report.gaps.gaps} of ${report.gaps.count}`);
  lines.push("    these are covered by the egress policy and the action layer");
  lines.push("");
  lines.push("  False-positive control (benign content that must pass)");
  lines.push(`    control samples   : ${report.controls.controls}`);
  lines.push(`    passed clean      : ${report.controls.clean}`);
  lines.push(`    false positives   : ${report.controls.falsePositives}`);
  lines.push(`    control rate      : ${pct(report.controls.rate)}`);
  lines.push("");
  lines.push("-".repeat(66));
  lines.push("");
  lines.push(`  ${pad("ID", 14)}${pad("CLASS", 24)}${pad("EXPECTED", 10)}${pad("ACTUAL", 16)}RULES`);
  lines.push(`  ${"-".repeat(12)}  ${"-".repeat(22)}  ${"-".repeat(8)}  ${"-".repeat(14)}  ${"-".repeat(10)}`);
  for (const o of report.outcomes) {
    const mark = o.ok ? " " : "!";
    lines.push(
      `${mark} ${pad(o.id, 14)}${pad(o.attackClass, 24)}${pad(o.expected, 10)}${pad(o.actual, 16)}` +
        (o.rules && o.rules.length ? o.rules.join(",") : o.coveredBy ? `[${o.coveredBy}]` : "-"),
    );
  }
  lines.push("");
  lines.push(`  completed in ${report.elapsedMs}ms`);
  lines.push("");
  return lines.join("\n");
}

/**
 * Machine-readable scorecard.
 * @param {BenchReport} report
 */
export function toJsonBench(report) {
  return JSON.stringify(
    {
      tool: "mcp-output-firewall",
      version: "0.2.0",
      generatedAt: new Date().toISOString(),
      summary: {
        catchRate: report.catchRate,
        gaps: report.gaps,
        controls: report.controls,
      },
      byClass: report.byClass,
      outcomes: report.outcomes,
    },
    null,
    2,
  );
}
