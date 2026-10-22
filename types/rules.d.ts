/**
 * Replace anything that looks like a credential with a marker.
 * Used so that reports never re-leak a secret they just detected.
 * @param {string} text
 * @returns {string}
 */
export function maskSecrets(text: string): string;
/**
 * Scan a block of text for prompt-injection and exfiltration content.
 * Pure and synchronous: safe to call on every tool result.
 * @param {string} text
 * @param {ScanOptions} [options]
 * @returns {ScanResult}
 */
export function scan(text: string, options?: ScanOptions): ScanResult;
/**
 * @param {string} text
 * @param {ScanOptions} [options]
 * @returns {boolean}
 */
export function isSafe(text: string, options?: ScanOptions): boolean;
/**
 * Scan every string field of an arbitrary JSON value (i.e. a tool result).
 * Returns findings annotated with a JSON path so you can locate the offender.
 * @param {unknown} value
 * @param {ScanOptions} [options]
 * @param {string} [path]
 * @returns {Array<Finding & {path:string}>}
 */
export function scanDeep(value: unknown, options?: ScanOptions, path?: string): Array<Finding & {
    path: string;
}>;
/**
 * Rewrite text so it is safe to hand to a model.
 *
 * Deliberately conservative: it neutralises instruction-bearing constructs and
 * strips invisible characters, but does NOT delete the surrounding content.
 * The agent still sees the data; it just cannot be hijacked by it.
 * @param {string} text
 * @param {ScanOptions} [options]
 * @returns {SanitizeResult}
 */
export function sanitize(text: string, options?: ScanOptions): SanitizeResult;
/**
 * Machine-readable rule catalogue.
 * @returns {Array<Pick<Rule,'id'|'category'|'severity'|'title'|'why'|'fix'>>}
 */
export function listRules(): Array<Pick<Rule, "id" | "category" | "severity" | "title" | "why" | "fix">>;
/** @type {Rule[]} */
export const RULES: Rule[];
export type Severity = "critical" | "high" | "medium" | "low";
export type RuleCategory = "injection" | "exfiltration" | "secrets" | "tool-hijack" | "obfuscation" | "supply-chain";
export type Rule = {
    id: string;
    category: RuleCategory;
    severity: Severity;
    title: string;
    /**
     * Plain-language explanation of the attack this stops.
     */
    why: string;
    /**
     * Any single match fires the rule.
     */
    patterns: RegExp[];
    refine?: ((match: string, full: string, index: number) => boolean) | undefined;
    /**
     * Remediation hint surfaced in reports.
     */
    fix: string;
};
export type Finding = {
    ruleId: string;
    category: RuleCategory;
    severity: Severity;
    title: string;
    why: string;
    fix: string;
    evidence: string;
    index: number;
    maskedEvidence: string;
};
export type ScanOptions = {
    disable?: Partial<Record<RuleCategory, boolean>> | undefined;
    minSeverity?: Severity | undefined;
    maxHitsPerRule?: number | undefined;
    includeRawEvidence?: boolean | undefined;
};
export type ScanResult = {
    safe: boolean;
    worst: Severity | null;
    findings: Finding[];
    stats: {
        bytesScanned: number;
        rulesRun: number;
        hits: number;
        elapsedMs: number;
    };
};
export type SanitizeResult = {
    text: string;
    changed: boolean;
    applied: string[];
};
