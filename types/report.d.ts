/** @param {Severity} a @param {Severity} b */
export function severityAtLeast(a: Severity, b: Severity): boolean;
/**
 * @param {Array<Finding & {path?:string}>} findings
 * @returns {string}
 */
export function renderFindings(findings: Array<Finding & {
    path?: string;
}>): string;
/**
 * @param {ScanResult} result
 * @param {string} label
 * @returns {string}
 */
export function renderScanResult(result: ScanResult, label: string): string;
/**
 * @param {Record<string, ScanResult>} results
 * @returns {string}
 */
export function toJsonReport(results: Record<string, ScanResult>): string;
/**
 * Exit codes: 0 clean, 1 findings at/above threshold.
 * @param {Record<string, ScanResult>} results
 * @param {Severity} threshold
 */
export function exitCodeFor(results: Record<string, ScanResult>, threshold: Severity): 0 | 1;
export type Finding = import("./rules.js").Finding;
export type ScanResult = import("./rules.js").ScanResult;
export type Severity = import("./rules.js").Severity;
