/**
 * Run the full corpus.
 * @returns {BenchReport}
 */
export function runBenchmark(): BenchReport;
/**
 * Human-readable scorecard.
 * @param {BenchReport} report
 * @returns {string}
 */
export function renderBench(report: BenchReport): string;
/**
 * Machine-readable scorecard.
 * @param {BenchReport} report
 */
export function toJsonBench(report: BenchReport): string;
export type VectorOutcome = {
    id: string;
    attackClass: string;
    title: string;
    expected: string;
    /**
     * "caught" | "missed" | "clean" | "false-positive"
     */
    actual: string;
    ok: boolean;
    worst?: string | undefined;
    rules?: string[] | undefined;
    coveredBy?: string | undefined;
};
export type BenchReport = {
    total: number;
    catchRate: {
        catchable: number;
        caught: number;
        missed: number;
        rate: number;
    };
    gaps: {
        count: number;
        gaps: number;
    };
    controls: {
        controls: number;
        clean: number;
        falsePositives: number;
        rate: number;
    };
    outcomes: VectorOutcome[];
    byClass: ReturnType<typeof summarizeByClass>;
    elapsedMs: number;
};
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
 */
export type AttackVector = import("./adversarial.js").AttackVector;
import { summarizeByClass } from "./adversarial.js";
